//! JWKS fetching, caching, and JWT validation for FerrisKey-issued access tokens,
//! or for any standard OpenID Connect issuer ([`JwksCache::oidc`]).
//!
//! Used to validate id_tokens received from the OIDC token endpoint after a
//! successful authorization-code exchange, and Bearer tokens from mobile
//! clients (currently stubbed on this branch).

use serde::Deserialize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const CLOCK_LEEWAY_SECONDS: u64 = 60;
const OIDC_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// `localhost` and `*.localhost`: names [`LoopbackPinned`] always resolves to
/// this machine.
fn is_localhost_name(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

/// The generic issuer client's resolver: `localhost` and `*.localhost` go to
/// 127.0.0.1 and ::1 whatever DNS or a hosts file says, so the plain-http
/// exception below really is a loopback connection, redirects included.
/// Every other name goes to the system resolver.
struct LoopbackPinned;

impl reqwest::dns::Resolve for LoopbackPinned {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = if is_localhost_name(&host) {
                vec![
                    (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                    (std::net::Ipv6Addr::LOCALHOST, 0).into(),
                ]
            } else {
                tokio::task::spawn_blocking(move || {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0))
                        .map(Iterator::collect::<Vec<_>>)
                })
                .await??
            };
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether a generic issuer's URL may be trusted for discovery, keys or the
/// login endpoints: https, or plain http to loopback for development: a
/// loopback address (`127.0.0.0/8`, `::1`), or `localhost` / `*.localhost`,
/// which the issuer client pins to loopback ([`LoopbackPinned`]). Signing keys
/// fetched over plain http elsewhere are only as good as the network path.
pub(crate) fn is_secure_issuer_url(url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Domain(host)) => is_localhost_name(host),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Claims extracted from a validated FerrisKey JWT.
#[derive(Debug, Deserialize)]
pub struct OidcJwtClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    /// OIDC `email_verified` claim. Consulted before an id_token's email is
    /// allowed to match an existing account by address; absent counts as
    /// unverified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    pub iss: String,
    pub exp: u64,
    pub iat: u64,
    /// OIDC `nonce` claim. Echoed by the IdP from the auth request — the
    /// caller compares it against the per-flow nonce to bind the id_token
    /// to the original request. Optional here because not every issuer
    /// includes it and validation happens at the call site.
    #[serde(default)]
    pub nonce: Option<String>,
}

struct CachedJwks {
    jwks: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
}

/// The parts of an issuer's discovery document
/// (`{issuer}/.well-known/openid-configuration`) the redirect login uses.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcEndpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// RP-initiated logout. Without it, logout ends only the app's session.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Thread-safe JWKS cache with automatic refresh on unknown key IDs.
pub struct JwksCache {
    jwks_url: String,
    expected_issuers: Vec<String>,
    expected_audience: String,
    cache: RwLock<Option<CachedJwks>>,
    http: reqwest::Client,
    /// Set by [`JwksCache::oidc`]: the issuer whose discovery document supplies
    /// the JWKS URL, the one accepted `iss` and the SSO endpoints.
    oidc_issuer: Option<String>,
    /// Fetched on first use and kept once it succeeds, so an IdP that is down
    /// at boot does not stop the app from starting.
    discovery: tokio::sync::OnceCell<OidcEndpoints>,
}

impl JwksCache {
    /// Create a new JWKS cache for the given FerrisKey realm.
    ///
    /// `ferriskey_url` is the FerrisKey API base URL used for JWKS fetches.
    /// `issuer_url` is the configured public OIDC issuer base URL. FerrisKey
    /// deployments can differ on whether the `/api` mount appears in `iss`, so
    /// accept the same realm on both the configured issuer base and API base,
    /// with a stripped-`/api` variant for backwards compatibility.
    pub fn new(ferriskey_url: &str, issuer_url: &str, realm: &str, client_id: &str) -> Self {
        let base = ferriskey_url.trim_end_matches('/');
        let issuer = issuer_url.trim_end_matches('/');
        let mut expected_issuers = Vec::new();
        for candidate in [
            issuer,
            issuer.strip_suffix("/api").unwrap_or(issuer),
            base,
            base.strip_suffix("/api").unwrap_or(base),
        ] {
            let expected = format!("{candidate}/realms/{realm}");
            if !expected_issuers.contains(&expected) {
                expected_issuers.push(expected);
            }
        }

        Self {
            jwks_url: format!("{base}/realms/{realm}/protocol/openid-connect/certs"),
            expected_issuers,
            expected_audience: client_id.to_string(),
            cache: RwLock::new(None),
            http: reqwest::Client::new(),
            oidc_issuer: None,
            discovery: tokio::sync::OnceCell::new(),
        }
    }

    /// A cache for any standard OpenID Connect issuer, instead of FerrisKey's
    /// realm URL shapes. Endpoints and keys come from
    /// `{issuer_url}/.well-known/openid-configuration`, fetched lazily; the
    /// document's `issuer` must equal `issuer_url` (a trailing `/` aside) and
    /// becomes the only `iss` accepted. `client_id` is the expected `aud`, and
    /// an id_token must name no other audience or authorized party (`azp`).
    ///
    /// The issuer and every endpoint it lists must be https, except on a
    /// loopback host (`localhost`, `*.localhost`, 127.0.0.1, ::1); otherwise
    /// discovery fails and so does every login.
    ///
    /// Building [`crate::AuthState`] with this cache switches `auth_router` to
    /// the browser-redirect login against that issuer (see the README).
    pub fn oidc(issuer_url: &str, client_id: &str) -> Self {
        Self {
            jwks_url: String::new(),
            expected_issuers: Vec::new(),
            expected_audience: client_id.to_string(),
            cache: RwLock::new(None),
            // Bounded: discovery runs one fetch at a time, so a hung issuer
            // would otherwise stall every login, logout and token check.
            http: reqwest::Client::builder()
                .timeout(OIDC_HTTP_TIMEOUT)
                .dns_resolver(LoopbackPinned)
                // A redirect must not move discovery or the keys off https.
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    if attempt.previous().len() >= 10 {
                        attempt.error("too many redirects")
                    } else if is_secure_issuer_url(attempt.url().as_str()) {
                        attempt.follow()
                    } else {
                        attempt.error("redirect to a non-https URL")
                    }
                }))
                .build()
                .expect("reqwest::Client builder should not fail with a timeout"),
            oidc_issuer: Some(issuer_url.to_string()),
            discovery: tokio::sync::OnceCell::new(),
        }
    }

    /// Whether this cache was built by [`JwksCache::oidc`].
    pub fn is_oidc(&self) -> bool {
        self.oidc_issuer.is_some()
    }

    /// The expected audience: the OIDC client id.
    pub(crate) fn client_id(&self) -> &str {
        &self.expected_audience
    }

    /// The issuer's discovered endpoints, or `None` for a FerrisKey cache.
    pub async fn oidc_endpoints(&self) -> Result<Option<&OidcEndpoints>, JwtError> {
        let Some(issuer_url) = self.oidc_issuer.as_deref() else {
            return Ok(None);
        };
        self.discovery
            .get_or_try_init(|| self.discover(issuer_url))
            .await
            .map(Some)
    }

    async fn discover(&self, issuer_url: &str) -> Result<OidcEndpoints, JwtError> {
        let issuer_url = issuer_url.trim_end_matches('/');
        if !is_secure_issuer_url(issuer_url) {
            tracing::error!("OIDC issuer {issuer_url:?} is not https (or a loopback host)");
            return Err(JwtError::JwksFetchFailed);
        }
        let url = format!("{issuer_url}/.well-known/openid-configuration");
        let endpoints: OidcEndpoints = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| {
                tracing::error!("Failed to fetch OIDC discovery from {url}: {e:?}");
                JwtError::JwksFetchFailed
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse OIDC discovery from {url}: {e:?}");
                JwtError::JwksFetchFailed
            })?;
        if endpoints.issuer.trim_end_matches('/') != issuer_url {
            tracing::error!(
                "OIDC discovery at {url} names issuer {:?}, expected {issuer_url:?}",
                endpoints.issuer
            );
            return Err(JwtError::JwksFetchFailed);
        }
        for (name, url) in [
            ("jwks_uri", Some(&endpoints.jwks_uri)),
            (
                "authorization_endpoint",
                Some(&endpoints.authorization_endpoint),
            ),
            ("token_endpoint", Some(&endpoints.token_endpoint)),
            (
                "end_session_endpoint",
                endpoints.end_session_endpoint.as_ref(),
            ),
        ] {
            if let Some(url) = url
                && !is_secure_issuer_url(url)
            {
                tracing::error!(
                    "OIDC discovery at {url:?} lists {name} {url:?}, which is not https"
                );
                return Err(JwtError::JwksFetchFailed);
            }
        }
        Ok(endpoints)
    }

    /// Validate a JWT token and return the extracted claims.
    ///
    /// On unknown `kid`, attempts a single JWKS refresh to handle key rotation.
    pub async fn validate_token(&self, token: &str) -> Result<OidcJwtClaims, JwtError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidToken)?;
        let kid = header.kid.as_deref().ok_or(JwtError::MissingKid)?;

        let (jwks_url, issuers) = match self.oidc_endpoints().await? {
            Some(endpoints) => (endpoints.jwks_uri.as_str(), vec![endpoints.issuer.as_str()]),
            None => (
                self.jwks_url.as_str(),
                self.expected_issuers.iter().map(String::as_str).collect(),
            ),
        };

        // Try cached key first
        if let Some(key) = self.find_key(kid) {
            return self.decode_with_key(token, &key, &issuers);
        }

        // Key not found or cache expired — refresh JWKS (handles key rotation)
        self.refresh_jwks(jwks_url).await?;

        let key = self.find_key(kid).ok_or(JwtError::UnknownKid)?;
        self.decode_with_key(token, &key, &issuers)
    }

    fn find_key(&self, kid: &str) -> Option<jsonwebtoken::DecodingKey> {
        let cache = self.cache.read().ok()?;
        let cached = cache.as_ref()?;

        if cached.fetched_at.elapsed() > JWKS_CACHE_TTL {
            return None;
        }

        cached
            .jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .and_then(|jwk| jsonwebtoken::DecodingKey::from_jwk(jwk).ok())
    }

    async fn refresh_jwks(&self, jwks_url: &str) -> Result<(), JwtError> {
        let jwks: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch JWKS from {}: {:?}", jwks_url, e);
                JwtError::JwksFetchFailed
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse JWKS response: {:?}", e);
                JwtError::JwksFetchFailed
            })?;

        tracing::info!(
            "Refreshed JWKS cache ({} keys) from {}",
            jwks.keys.len(),
            jwks_url
        );

        let mut cache = self.cache.write().map_err(|_| JwtError::CacheLockError)?;
        *cache = Some(CachedJwks {
            jwks,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    fn decode_with_key(
        &self,
        token: &str,
        key: &jsonwebtoken::DecodingKey,
        issuers: &[&str],
    ) -> Result<OidcJwtClaims, JwtError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(issuers);
        validation.set_audience(&[&self.expected_audience]);
        // `set_required_spec_claims` enforces that these fields are present
        // in the payload (deserialization would fail anyway for the
        // non-Option fields, but this rejects tokens missing `exp`/`iat`
        // before they can be considered valid). Nonce isn't on the OIDC
        // spec list but is checked separately at the call site.
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECONDS;

        let token_data = jsonwebtoken::decode::<serde_json::Value>(token, key, &validation)
            .map_err(|e| {
                tracing::warn!(
                    expected_issuers = ?issuers,
                    expected_audience = %self.expected_audience,
                    "JWT validation failed: {:?}",
                    e
                );
                JwtError::ValidationFailed
            })?;

        // `set_audience` accepts an `aud` array if any entry matches. A
        // generic issuer serves other clients too, so a token that also
        // names one of them, or was issued to one (`azp`), is not ours.
        if self.is_oidc() {
            let audiences = match &token_data.claims["aud"] {
                serde_json::Value::Array(list) => list.len(),
                _ => 1,
            };
            let azp = token_data.claims.get("azp");
            let azp_ok = azp.is_none_or(|azp| azp.as_str() == Some(&self.expected_audience));
            if audiences != 1 || !azp_ok {
                tracing::warn!(
                    expected_audience = %self.expected_audience,
                    ?azp,
                    audiences,
                    "id_token names another audience or authorized party"
                );
                return Err(JwtError::ValidationFailed);
            }
        }

        serde_json::from_value(token_data.claims).map_err(|e| {
            tracing::warn!("JWT claims malformed: {e}");
            JwtError::ValidationFailed
        })
    }
}

#[derive(Debug)]
pub enum JwtError {
    InvalidToken,
    MissingKid,
    UnknownKid,
    JwksFetchFailed,
    ValidationFailed,
    CacheLockError,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::InvalidToken => write!(f, "Invalid JWT token"),
            JwtError::MissingKid => write!(f, "JWT missing kid header"),
            JwtError::UnknownKid => write!(f, "Unknown key ID in JWT"),
            JwtError::JwksFetchFailed => write!(f, "Failed to fetch JWKS"),
            JwtError::ValidationFailed => write!(f, "JWT validation failed"),
            JwtError::CacheLockError => write!(f, "JWKS cache lock error"),
        }
    }
}

impl std::error::Error for JwtError {}
