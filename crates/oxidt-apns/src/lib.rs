//! Apple push (APNs) with a token key, the way the apps with an iPhone
//! companion use it: a silent push wakes the app to do what waits for it,
//! and a visible one says what did not reach the phone in time.
//!
//! iOS may hold a silent push back, or drop it for an app that was
//! force-quit, so nothing should rest on [`Apns::wake`] alone.
//!
//! The app keeps its own device tokens and decides what to send when. This
//! crate signs the provider token, sends, and says which device tokens Apple
//! no longer accepts ([`Answer::Gone`]). It never logs a token or the key.

use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

pub const PRODUCTION: &str = "https://api.push.apple.com";
/// For a development build of the app, as Xcode installs it.
pub const SANDBOX: &str = "https://api.sandbox.push.apple.com";

pub struct Apns {
    http: reqwest::Client,
    base: String,
    topic: String,
    key_id: String,
    team_id: String,
    key: EncodingKey,
    /// The signed provider token and when it was made. Apple refuses one
    /// renewed more often than every 20 minutes, and one older than an hour.
    jwt: Mutex<Option<(String, Instant)>>,
}

/// How Apple answered one push.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Sent,
    /// The device token is no longer valid: the app was removed or the
    /// token changed. Delete it.
    Gone,
    /// Worth trying again later.
    Failed,
}

/// The key is not a readable `.p8` file. Says no more: the cause could quote it.
#[derive(Debug)]
pub struct InvalidKey;

impl Apns {
    /// `base` is [`PRODUCTION`] or [`SANDBOX`]; `key` the `.p8` file's
    /// contents; `topic` the app's bundle id.
    pub fn new(
        base: &str,
        key: &str,
        key_id: &str,
        team_id: &str,
        topic: &str,
    ) -> Result<Self, InvalidKey> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| InvalidKey)?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').into(),
            topic: topic.into(),
            key_id: key_id.into(),
            team_id: team_id.into(),
            key: EncodingKey::from_ec_pem(key.as_bytes()).map_err(|_| InvalidKey)?,
            jwt: Mutex::default(),
        })
    }

    /// From `APNS_KEY` (the `.p8` file's contents, line breaks may be written
    /// as `\n`), `APNS_KEY_ID` and `APNS_TEAM_ID`. `APNS_TOPIC` overrides
    /// `topic`; `APNS_SANDBOX=true` is for a development build of the app.
    /// `None`, push is off, unless the first three are set and the key reads.
    pub fn from_env(topic: &str) -> Option<Self> {
        let env = |key: &str| std::env::var(key).ok().filter(|value| !value.is_empty());
        let (key, key_id, team_id) = (env("APNS_KEY")?, env("APNS_KEY_ID")?, env("APNS_TEAM_ID")?);
        let sandbox = env("APNS_SANDBOX").is_some_and(|value| value == "true" || value == "1");
        let topic = env("APNS_TOPIC").unwrap_or_else(|| topic.into());
        let base = if sandbox { SANDBOX } else { PRODUCTION };
        let made = Self::new(base, &key.replace("\\n", "\n"), &key_id, &team_id, &topic);
        if made.is_err() {
            tracing::warn!("push is off: APNS_KEY is not a readable .p8 key");
        }
        made.ok()
    }

    /// A silent push: the app is woken in the background. No content.
    pub async fn wake(&self, token: &str) -> Answer {
        let body = json!({"aps": {"content-available": 1}});
        self.send(token, &body, "background", 5, None).await
    }

    /// A visible push with the default sound. Sent again under the same
    /// `collapse` id, the phone replaces the first instead of showing two.
    pub async fn alert(&self, token: &str, text: &str, collapse: Option<&str>) -> Answer {
        let body = json!({"aps": {"alert": {"body": text}, "sound": "default"}});
        self.send(token, &body, "alert", 10, collapse).await
    }

    async fn send(
        &self,
        token: &str,
        body: &Value,
        kind: &str,
        priority: u8,
        collapse: Option<&str>,
    ) -> Answer {
        // It goes into the address: nothing but what Apple hands out.
        if !is_token(token) {
            return Answer::Gone;
        }
        let Some(jwt) = self.jwt() else {
            return Answer::Failed;
        };
        let mut request = self
            .http
            .post(format!("{}/3/device/{token}", self.base))
            .bearer_auth(jwt)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", kind)
            .header("apns-priority", priority.to_string())
            .json(body);
        if let Some(collapse) = collapse {
            request = request.header("apns-collapse-id", collapse);
        }
        let Ok(response) = request.send().await else {
            tracing::warn!("push failed: APNs unreachable");
            return Answer::Failed;
        };
        let status = response.status().as_u16();
        if status == 200 {
            return Answer::Sent;
        }
        let reason = response.json::<Value>().await.unwrap_or_default()["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if status == 410 || reason == "Unregistered" || reason == "BadDeviceToken" {
            return Answer::Gone;
        }
        if reason == "ExpiredProviderToken" {
            *self.jwt.lock().unwrap() = None;
        }
        tracing::warn!("push failed: APNs answered {status} {reason}");
        Answer::Failed
    }

    /// The provider token, renewed after 50 minutes.
    fn jwt(&self) -> Option<String> {
        let mut cached = self.jwt.lock().unwrap();
        if let Some((jwt, made)) = cached.as_ref()
            && made.elapsed() < Duration::from_secs(50 * 60)
        {
            return Some(jwt.clone());
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let claims = json!({"iss": self.team_id, "iat": now});
        let jwt = jsonwebtoken::encode(&header, &claims, &self.key).ok()?;
        *cached = Some((jwt.clone(), Instant::now()));
        Some(jwt)
    }
}

/// Whether this is a device token as iOS hands it out, in hex. Check before
/// storing one a client sent.
pub fn is_token(token: &str) -> bool {
    (64..=200).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}
