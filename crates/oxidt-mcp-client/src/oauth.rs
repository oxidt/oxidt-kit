//! Sign-in to a remote MCP server that wants OAuth instead of a pasted token.
//!
//! rmcp does the protocol; this module adds the network policy and the rules
//! a hosted app needs, and leaves storage to the app:
//!
//! 1. [`begin`] discovers the server's sign-in, registers this app as a
//!    client (or presents its client metadata document), and returns the URL
//!    to send the browser to plus a [`Pending`] flow.
//! 2. The app stores the `Pending` **encrypted**, keyed by
//!    [`Pending::state`], bound to the signed-in user *and* the browser that
//!    started it, for a few minutes, and deletes it when it is claimed. A
//!    callback from another browser, twice, or late must find nothing.
//! 3. [`finish`] exchanges the callback's code and returns the access token
//!    and a [`Grant`]. The app stores the grant encrypted.
//! 4. [`access_token`] returns a usable token before each connection,
//!    refreshing when needed. Rotating refresh tokens must not be used by two
//!    workers at once: hold a lock on the connection's row around the call
//!    and save the grant it updated before releasing it.
//!
//! What is refused: a server that does not publish OAuth metadata (nothing is
//! probed at guessed paths), one that does not advertise PKCE `S256`, an
//! answer from an issuer other than the one discovered, and every endpoint
//! that is not public https. Provider response bodies never reach an error
//! message: [`Error`] is a fixed set of categories.

use std::{sync::Arc, time::Duration};

use oxidt_egress::{Timeouts, UrlPolicy};
use rmcp::transport::auth::{
    AuthError, AuthorizationManager, AuthorizationMetadata, CredentialStore,
    InMemoryCredentialStore, InMemoryStateStore, OAuthClientConfig, OAuthHttpClient,
    OAuthHttpClientError, OAuthHttpClientFuture, OAuthHttpRequest, StateStore,
    StoredAuthorizationState, StoredCredentials,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::CONNECT_TIMEOUT;

/// Longest wait for discovery and registration, and for the code exchange.
const FLOW_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for a refresh.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
/// An OAuth response larger than this is refused.
const MAX_RESPONSE: usize = 1024 * 1024;

/// Why sign-in did not work. The text is safe to show: it never contains
/// what the provider sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("enter a public https server URL")]
    Url,
    #[error("this server does not offer sign-in; use an access token instead")]
    NotOffered,
    #[error("could not discover the service's sign-in configuration")]
    Discovery,
    #[error("could not reach the service's sign-in endpoint")]
    Unreachable,
    #[error("the service does not support the required PKCE S256 sign-in method")]
    Pkce,
    #[error("the service's sign-in issuer could not be verified")]
    Issuer,
    #[error("the service rejected this app's callback URL")]
    RedirectRejected,
    #[error("the service could not register this app as a client")]
    Registration,
    #[error("the service could not exchange the authorization code")]
    Exchange,
    /// The saved sign-in is gone or was rejected: the user signs in again.
    #[error("sign-in expired; connect again")]
    Expired,
    /// A refresh could not be attempted or got no clear answer. The saved
    /// sign-in may still be good: keep it and try again later.
    #[error("the service's sign-in endpoint did not answer; try again shortly")]
    Unavailable,
    #[error("the service did not allow the requested permissions")]
    Scope,
    #[error("the service returned an unusable access token")]
    Token,
    #[error("sign-in timed out")]
    Timeout,
    #[error("sign-in could not be completed")]
    Other,
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        match &error {
            AuthError::RegistrationFailed(detail) => registration(detail),
            AuthError::MetadataError(_) | AuthError::NoAuthorizationSupport => Error::Discovery,
            AuthError::HttpError(_) => Error::Unreachable,
            AuthError::PkceUnsupported => Error::Pkce,
            AuthError::AuthorizationServerMismatch { .. }
            | AuthError::AuthorizationServerMissingIssuer { .. } => Error::Issuer,
            AuthError::TokenExchangeFailed(_) => Error::Exchange,
            AuthError::TokenRefreshFailed(_) => Error::Unavailable,
            AuthError::TokenRefreshRejected(_)
            | AuthError::TokenExpired
            | AuthError::AuthorizationRequired => Error::Expired,
            AuthError::InvalidScope(_) | AuthError::InsufficientScope { .. } => Error::Scope,
            _ => Error::Other,
        }
    }
}

/// rmcp wraps a registration error as `HTTP <status>: <body>`. Only the
/// protocol's own error code is read; the description and the rest are
/// dropped.
fn registration(detail: &str) -> Error {
    let body = detail
        .find('{')
        .and_then(|start| serde_json::from_str::<Value>(&detail[start..]).ok());
    match body.as_ref().and_then(|v| v["error"].as_str()) {
        Some("invalid_redirect_uri") => Error::RedirectRejected,
        _ => Error::Registration,
    }
}

/// This app as an OAuth client.
pub struct Client<'a> {
    /// Shown on the provider's consent page.
    pub name: &'a str,
    /// Where the provider sends the browser back to. Must be registered
    /// exactly, so it is the app's one fixed callback address.
    pub redirect_uri: &'a str,
    /// Where the app serves [`client_metadata`], when it is on public https.
    /// Used instead of registering when the provider supports client id
    /// metadata documents.
    pub metadata_url: Option<&'a str>,
    /// Credentials the provider handed out in advance, for one that offers
    /// no registration. With these nothing is registered.
    pub registered: Option<Registered<'a>>,
}

/// A client id, and its secret if the provider issued one.
#[derive(Clone, Copy)]
pub struct Registered<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
}

/// The document to serve at [`Client::metadata_url`].
pub fn client_metadata(client: &Client<'_>, client_uri: &str) -> Value {
    json!({
        "client_id": client.metadata_url,
        "client_name": client.name,
        "client_uri": client_uri,
        "redirect_uris": [client.redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
    })
}

/// A signed-in connection: what is needed to use and refresh its token.
/// Holds secrets. Store it encrypted and never send it to a browser.
#[derive(Clone, Serialize, Deserialize)]
pub struct Grant {
    resource: String,
    metadata: AuthorizationMetadata,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    credentials: Option<StoredCredentials>,
}

impl Grant {
    /// The issuer that granted it, for display.
    pub fn issuer(&self) -> Option<&str> {
        self.metadata.issuer.as_deref()
    }

    async fn manager(
        &self,
        http: Arc<dyn OAuthHttpClient>,
    ) -> Result<(AuthorizationManager, InMemoryCredentialStore), Error> {
        let mut manager =
            AuthorizationManager::new_with_oauth_http_client(&self.resource, http).await?;
        manager.set_metadata(self.metadata.clone());
        let mut config = OAuthClientConfig::new(&self.client_id, &self.redirect_uri)
            .with_application_type("web");
        if let Some(secret) = &self.client_secret {
            config = config.with_client_secret(secret);
        }
        manager.configure_client(config)?;
        let store = InMemoryCredentialStore::new();
        if let Some(credentials) = &self.credentials {
            store.save(credentials.clone()).await?;
        }
        manager.set_credential_store(store.clone());
        Ok((manager, store))
    }
}

/// A sign-in the browser has been sent away for. Holds the PKCE verifier.
/// Store it encrypted; see the module docs for how it must be bound.
#[derive(Serialize, Deserialize)]
pub struct Pending {
    grant: Grant,
    state: StoredAuthorizationState,
}

impl Pending {
    /// The `state` the callback will carry: the key to store this under.
    pub fn state(&self) -> &str {
        &self.state.csrf_token
    }
}

/// Start a sign-in to the MCP server at `resource`. Returns the address to
/// send the browser to.
pub async fn begin(resource: &str, client: &Client<'_>) -> Result<(String, Pending), Error> {
    let resource = oxidt_egress::check_url(resource, &UrlPolicy::default())
        .map_err(|_| Error::Url)?
        .to_string();
    tokio::time::timeout(
        FLOW_TIMEOUT,
        prepare(resource, client, Arc::new(PublicHttp)),
    )
    .await
    .map_err(|_| Error::Timeout)?
}

async fn prepare(
    resource: String,
    client: &Client<'_>,
    http: Arc<dyn OAuthHttpClient>,
) -> Result<(String, Pending), Error> {
    let mut manager = AuthorizationManager::new_with_oauth_http_client(&resource, http).await?;
    let resolution = manager.resolve_metadata().await?;
    if !resolution.source.is_discovered() {
        return Err(Error::NotOffered);
    }
    let metadata = resolution.metadata;
    let s256 = metadata
        .code_challenge_methods_supported
        .as_ref()
        .is_some_and(|methods| methods.iter().any(|method| method == "S256"));
    if !s256 {
        return Err(Error::Pkce);
    }
    // The browser goes to the first and the server to the second; both must
    // be public even though only one is fetched from here.
    let browser_goes_to =
        endpoint(&metadata.authorization_endpoint).map_err(|_| Error::Discovery)?;
    pinned(&browser_goes_to)
        .await
        .map_err(|_| Error::Discovery)?;
    endpoint(&metadata.token_endpoint).map_err(|_| Error::Discovery)?;
    manager.set_metadata(metadata.clone());
    // Before registering: rmcp otherwise registers as a native app.
    manager.configure_client(
        OAuthClientConfig::new("pending", client.redirect_uri).with_application_type("web"),
    )?;
    let scopes = manager.select_scopes(None, &[]);
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let documents = metadata
        .additional_fields
        .get("client_id_metadata_document_supported")
        .and_then(Value::as_bool)
        == Some(true);
    let config = match (client.registered, client.metadata_url) {
        (Some(registered), _) => {
            let config = OAuthClientConfig::new(registered.client_id, client.redirect_uri)
                .with_scopes(scopes.clone())
                .with_application_type("web");
            match registered.client_secret {
                Some(secret) => config.with_client_secret(secret),
                None => config,
            }
        }
        (None, Some(document)) if documents => {
            OAuthClientConfig::new(document, client.redirect_uri)
                .with_scopes(scopes.clone())
                .with_application_type("web")
        }
        _ => {
            manager
                .register_client(client.name, client.redirect_uri, &scope_refs)
                .await?
        }
    };
    manager.configure_client(config.clone())?;
    let states = InMemoryStateStore::new();
    manager.set_state_store(states.clone());
    let auth_url = manager.get_authorization_url(&scope_refs).await?;
    let parsed = Url::parse(&auth_url).map_err(|_| Error::Other)?;
    let param = |name: &str| {
        parsed
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let state = param("state").ok_or(Error::Other)?;
    // rmcp's own spelling of the resource, kept so a later process sends the
    // same one.
    let resource = param("resource").unwrap_or(resource);
    let state = states.load(&state).await?.ok_or(Error::Other)?;
    let grant = Grant {
        resource,
        metadata,
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: client.redirect_uri.to_owned(),
        credentials: None,
    };
    Ok((auth_url, Pending { grant, state }))
}

/// Complete a sign-in with what the callback carried. `state` must be the
/// one the flow was stored under; `iss` is the callback's `iss` parameter.
pub async fn finish(
    pending: Pending,
    code: &str,
    state: &str,
    iss: Option<&str>,
) -> Result<(SecretString, Grant), Error> {
    tokio::time::timeout(
        FLOW_TIMEOUT,
        exchange(pending, code, state, iss, Arc::new(PublicHttp)),
    )
    .await
    .map_err(|_| Error::Timeout)?
}

async fn exchange(
    pending: Pending,
    code: &str,
    state: &str,
    iss: Option<&str>,
    http: Arc<dyn OAuthHttpClient>,
) -> Result<(SecretString, Grant), Error> {
    if code.is_empty() || code.len() > 8192 || state != pending.state() {
        return Err(Error::Exchange);
    }
    let Pending {
        mut grant,
        state: stored,
    } = pending;
    let (mut manager, store) = grant.manager(http).await?;
    let states = InMemoryStateStore::new();
    states.save(state, stored).await?;
    manager.set_state_store(states);
    manager
        .exchange_code_for_token_with_issuer(code, state, iss)
        .await?;
    let token = manager.get_access_token().await?;
    grant.credentials = store.load().await?;
    Ok((usable(token)?, grant))
}

/// A token for the next connection, refreshed when it has expired. `grant`
/// is updated in place: save it **whatever this returns**, because a refresh
/// that rotated the refresh token has used up the old one even when the call
/// then fails. See the module docs on locking.
///
/// [`Error::Expired`] means the user must sign in again;
/// [`Error::Unavailable`] and [`Error::Timeout`] mean try again later.
pub async fn access_token(grant: &mut Grant) -> Result<SecretString, Error> {
    refresh(grant, Arc::new(PublicHttp)).await
}

async fn refresh(grant: &mut Grant, http: Arc<dyn OAuthHttpClient>) -> Result<SecretString, Error> {
    let (manager, store) = grant.manager(http).await?;
    let token = tokio::time::timeout(REFRESH_TIMEOUT, manager.get_access_token()).await;
    // Before anything can fail: what the provider rotated is kept.
    if let Some(credentials) = store.load().await? {
        grant.credentials = Some(credentials);
    }
    usable(token.map_err(|_| Error::Timeout)??)
}

/// Refresh now, even though the token has not expired. For a server that
/// rejected a token that should still be good, which is what a revoked
/// grant looks like: refresh once and try once more; a second rejection
/// means the user signs in again. Save `grant` whatever this returns.
pub async fn refresh_now(grant: &mut Grant) -> Result<SecretString, Error> {
    force(grant, Arc::new(PublicHttp)).await
}

async fn force(grant: &mut Grant, http: Arc<dyn OAuthHttpClient>) -> Result<SecretString, Error> {
    let (manager, store) = grant.manager(http).await?;
    let refreshed = tokio::time::timeout(REFRESH_TIMEOUT, manager.refresh_token()).await;
    if let Some(credentials) = store.load().await? {
        grant.credentials = Some(credentials);
    }
    let response = refreshed.map_err(|_| Error::Timeout)??;
    // Taken from this response, not asked for again: asking could refresh a
    // second time when the new token is short-lived, and that rotation would
    // not be in `grant`.
    let token = serde_json::to_value(&response)
        .ok()
        .and_then(|tokens| tokens["access_token"].as_str().map(str::to_owned))
        .ok_or(Error::Token)?;
    usable(token)
}

/// Tell the provider this grant is finished (RFC 7009), so the tokens stop
/// working there too. `Ok(false)`: the provider offers no way to.
///
/// A courtesy after the app deleted its own copy, never a condition for it:
/// a provider that is down or refuses must not keep a user from
/// disconnecting.
pub async fn revoke(grant: &Grant) -> Result<bool, Error> {
    let Some((address, form)) = revocation(grant) else {
        return Ok(false);
    };
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&form)
        .finish();
    let basic = basic_secret(grant);
    let send = async {
        let url = endpoint(&address).map_err(|_| Error::Discovery)?;
        let client = pinned(&url).await.map_err(|_| Error::Unreachable)?;
        let mut request = client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some((id, secret)) = basic {
            request = request.basic_auth(id, Some(secret));
        }
        let response = request.send().await.map_err(|_| Error::Unreachable)?;
        // RFC 7009: 200 also for a token the provider no longer knows.
        if response.status().is_success() {
            Ok(true)
        } else {
            Err(Error::Other)
        }
    };
    tokio::time::timeout(REFRESH_TIMEOUT, send)
        .await
        .map_err(|_| Error::Timeout)?
}

/// Where to send the revocation and what to send: the refresh token when
/// there is one (revoking it ends the access tokens too), else the access
/// token.
fn revocation(grant: &Grant) -> Option<(String, Vec<(&'static str, String)>)> {
    let address = grant
        .metadata
        .additional_fields
        .get("revocation_endpoint")?
        .as_str()?
        .to_owned();
    // Read through its JSON form: the token type is rmcp's own.
    let tokens = serde_json::to_value(grant.credentials.as_ref()?.token_response.as_ref()?).ok()?;
    let held = |name: &str| tokens[name].as_str().filter(|token| !token.is_empty());
    let (token, hint) = match held("refresh_token") {
        Some(refresh) => (refresh, "refresh_token"),
        None => (held("access_token")?, "access_token"),
    };
    let mut form = vec![
        ("token", token.to_owned()),
        ("token_type_hint", hint.to_owned()),
    ];
    match (&grant.client_secret, basic_secret(grant)) {
        // In the Authorization header instead.
        (Some(_), Some(_)) => {}
        (Some(secret), None) => {
            form.push(("client_id", grant.client_id.clone()));
            form.push(("client_secret", secret.clone()));
        }
        (None, _) => form.push(("client_id", grant.client_id.clone())),
    }
    Some((address, form))
}

/// The client id and secret for HTTP Basic, form-encoded as RFC 6749 §2.3.1
/// asks, when that is how this provider wants a confidential client to
/// authenticate at the revocation endpoint. Basic is the default; the form
/// is used only where the provider lists `client_secret_post` and not Basic.
fn basic_secret(grant: &Grant) -> Option<(String, String)> {
    let secret = grant.client_secret.as_ref()?;
    let listed = |field: &str| {
        let methods = grant.metadata.additional_fields.get(field)?.as_array()?;
        Some(methods.iter().filter_map(Value::as_str).collect::<Vec<_>>())
    };
    let methods = listed("revocation_endpoint_auth_methods_supported")
        .or_else(|| listed("token_endpoint_auth_methods_supported"))
        .unwrap_or_default();
    let post_only =
        methods.contains(&"client_secret_post") && !methods.contains(&"client_secret_basic");
    let encoded = |text: &str| url::form_urlencoded::byte_serialize(text.as_bytes()).collect();
    (!post_only).then(|| (encoded(&grant.client_id), encoded(secret)))
}

fn usable(token: String) -> Result<SecretString, Error> {
    if token.is_empty() || token.len() > 16_384 || token.contains(['\r', '\n']) {
        return Err(Error::Token);
    }
    Ok(token.into())
}

/// OAuth endpoints may carry a query; the MCP resource URL may not.
fn endpoint(input: &str) -> Result<Url, OAuthHttpClientError> {
    if input.len() > 8192 {
        return Err("OAuth URL is too long".into());
    }
    let url = Url::parse(input)?;
    let mut base = url.clone();
    base.set_query(None);
    oxidt_egress::check_url(base.as_str(), &UrlPolicy::default()).map_err(|e| e.to_string())?;
    Ok(url)
}

async fn pinned(url: &Url) -> Result<reqwest::Client, OAuthHttpClientError> {
    let pinned = tokio::time::timeout(CONNECT_TIMEOUT, oxidt_egress::guard_host_async(url))
        .await
        .map_err(|_| "address lookup timed out")?
        .map_err(|e| e.to_string())?;
    let timeouts = Timeouts {
        connect: CONNECT_TIMEOUT,
        total: REFRESH_TIMEOUT,
    };
    Ok(oxidt_egress::pinned_client(&pinned, timeouts).map_err(|e| e.to_string())?)
}

/// Every endpoint the provider names is resolved, checked and pinned on its
/// own. No redirects (the client follows none, and one handed back here is
/// refused before rmcp can follow it itself), no proxy, no retried POST, and
/// a bounded body.
struct PublicHttp;

impl OAuthHttpClient for PublicHttp {
    fn execute(&self, operation: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
        Box::pin(async move {
            let url = endpoint(&operation.request.uri().to_string())?;
            let client = pinned(&url).await?;
            let request = reqwest::Request::try_from(operation.request)?;
            let mut response = client.execute(request).await?;
            if response.status().is_redirection() {
                return Err("OAuth endpoint answered with a redirect".into());
            }
            let mut builder = http::Response::builder().status(response.status());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len() + chunk.len() > MAX_RESPONSE {
                    return Err("OAuth response is too large".into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(builder.body(body)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use secrecy::ExposeSecret;

    use super::*;

    const APP: Client<'static> = Client {
        name: "Test app",
        redirect_uri: "https://app.example.com/oauth/callback",
        metadata_url: Some("https://app.example.com/oauth/client.json"),
        registered: None,
    };

    #[test]
    fn oauth_endpoints_may_carry_a_query_but_must_be_public_https() {
        assert!(endpoint("https://auth.example.com/token?tenant=one").is_ok());
        for url in [
            "http://auth.example.com/token",
            "https://user:secret@auth.example.com/token",
            "https://auth.example.com/token#fragment",
            "javascript:alert(1)",
        ] {
            assert!(endpoint(url).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn a_private_endpoint_is_refused_before_anything_is_sent() {
        for inside in [
            "https://127.0.0.1/token",
            "https://169.254.169.254/token",
            "https://[::1]/token",
        ] {
            assert!(pinned(&endpoint(inside).unwrap()).await.is_err());
        }
        assert_eq!(
            begin("http://service.example.com/mcp", &APP).await.err(),
            Some(Error::Url)
        );
    }

    #[test]
    fn a_registration_error_names_the_callback_and_leaks_nothing() {
        let rejected = registration(
            r#"HTTP 400 Bad Request: {"error":"invalid_redirect_uri","error_description":"secret-token"}"#,
        );
        assert_eq!(rejected, Error::RedirectRejected);
        for detail in ["secret-token", r#"HTTP 400: {"error":"secret-token"}"#] {
            assert_eq!(registration(detail), Error::Registration);
            assert!(!registration(detail).to_string().contains("secret-token"));
        }
    }

    #[test]
    fn the_client_document_names_the_callback_and_holds_no_secret() {
        let document = client_metadata(&APP, "https://app.example.com");
        assert_eq!(
            document["client_id"],
            "https://app.example.com/oauth/client.json"
        );
        assert_eq!(document["redirect_uris"][0], APP.redirect_uri);
        assert_eq!(document["token_endpoint_auth_method"], "none");
    }

    /// A token endpoint that answers a code exchange, then one refresh.
    struct MockOAuth {
        /// How long the first access token lasts, in seconds.
        first_expires: u64,
        /// The refresh answers with an access token too long to use.
        oversized: bool,
        /// The refresh gets no answer at all.
        down: bool,
        requests: Mutex<Vec<HashMap<String, String>>>,
    }

    impl MockOAuth {
        /// The first token lasts a second, so it is refreshed at once.
        fn new() -> Arc<Self> {
            Self::with(1, false, false)
        }

        fn with(first_expires: u64, oversized: bool, down: bool) -> Arc<Self> {
            Arc::new(Self {
                first_expires,
                oversized,
                down,
                requests: Mutex::default(),
            })
        }
    }

    impl OAuthHttpClient for MockOAuth {
        fn execute(&self, operation: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
            Box::pin(async move {
                assert_eq!(operation.request.uri(), "https://auth.example.com/token");
                assert_eq!(operation.request.method(), "POST");
                let params: HashMap<String, String> =
                    url::form_urlencoded::parse(operation.request.body())
                        .into_owned()
                        .collect();
                assert_eq!(params["resource"], "https://service.example.com/mcp");
                let refresh = params["grant_type"] == "refresh_token";
                if refresh {
                    assert_eq!(params["refresh_token"], "first-refresh-secret");
                }
                self.requests.lock().unwrap().push(params);
                if refresh && self.down {
                    return Err("connection refused".into());
                }
                let second = if self.oversized {
                    "a".repeat(20_000)
                } else {
                    "second-access-secret".into()
                };
                let body = json!({
                    "access_token": if refresh { second } else { "first-access-secret".into() },
                    "refresh_token": if refresh { "rotated-refresh-secret" } else { "first-refresh-secret" },
                    "token_type": "Bearer",
                    "expires_in": if refresh { 3600 } else { self.first_expires },
                    "scope": "tools:read"
                });
                Ok(http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body)?)?)
            })
        }
    }

    fn grant() -> Grant {
        Grant {
            resource: "https://service.example.com/mcp".into(),
            metadata: serde_json::from_value(json!({
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": true
            }))
            .unwrap(),
            client_id: "test-client".into(),
            client_secret: None,
            redirect_uri: APP.redirect_uri.into(),
            credentials: None,
        }
    }

    /// A flow as `begin` leaves it, without the discovery it would need.
    async fn pending(mock: Arc<MockOAuth>) -> (Pending, HashMap<String, String>) {
        let grant = grant();
        let (mut manager, _) = grant.manager(mock).await.unwrap();
        let states = InMemoryStateStore::new();
        manager.set_state_store(states.clone());
        let url = Url::parse(
            &manager
                .get_authorization_url(&["tools:read"])
                .await
                .unwrap(),
        )
        .unwrap();
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let state = states.load(&params["state"]).await.unwrap().unwrap();
        (Pending { grant, state }, params)
    }

    #[tokio::test]
    async fn a_stored_flow_finishes_and_a_refresh_rotates_the_grant() {
        let mock = MockOAuth::new();
        let (flow, params) = pending(mock.clone()).await;
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["resource"], "https://service.example.com/mcp");
        assert_eq!(params["redirect_uri"], APP.redirect_uri);
        assert_eq!(flow.state(), params["state"]);
        let verifier = flow.state.pkce_verifier.clone();

        // As a callback on another instance finds it: out of storage.
        let stored = serde_json::to_string(&flow).unwrap();
        let flow: Pending = serde_json::from_str(&stored).unwrap();
        let issuer = Some("https://auth.example.com");
        let (token, mut grant) =
            exchange(flow, "test-code", &params["state"], issuer, mock.clone())
                .await
                .unwrap();
        // The mock's first token lasts one second, so it is refreshed before
        // it is handed out, and the grant holds the rotated refresh token.
        assert_eq!(token.expose_secret(), "second-access-secret");
        assert_eq!(grant.issuer(), issuer);
        let saved = serde_json::to_string(&grant).unwrap();
        assert!(saved.contains("rotated-refresh-secret"));
        assert!(!saved.contains("first-refresh-secret"));

        // A token that is still good is returned as it is: nothing is sent.
        let again = refresh(&mut grant, mock.clone()).await.unwrap();
        assert_eq!(again.expose_secret(), "second-access-secret");

        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "one code exchange and one refresh");
        assert_eq!(requests[0]["code_verifier"], verifier);
        assert_eq!(requests[0]["code"], "test-code");
    }

    #[tokio::test]
    async fn a_wrong_issuer_or_state_never_sends_the_code() {
        for (state, issuer) in [
            (None, Some("https://attacker.example.com")),
            (None, None),
            (Some("unknown-state"), Some("https://auth.example.com")),
        ] {
            let mock = MockOAuth::new();
            let (flow, params) = pending(mock.clone()).await;
            let state = state.unwrap_or(&params["state"]);
            let outcome = exchange(flow, "code", state, issuer, mock.clone()).await;
            assert!(outcome.is_err());
            assert!(mock.requests.lock().unwrap().is_empty());
        }
    }

    /// A signed-in grant whose access token has run out.
    async fn stale(mock: Arc<MockOAuth>) -> Grant {
        let (flow, params) = pending(mock.clone()).await;
        let issuer = Some("https://auth.example.com");
        let (_, mut grant) = exchange(flow, "test-code", &params["state"], issuer, mock)
            .await
            .unwrap();
        grant.credentials.as_mut().unwrap().token_received_at = Some(0);
        grant
    }

    #[tokio::test]
    async fn a_rotated_refresh_token_is_kept_even_when_the_new_access_token_is_unusable() {
        let mock = MockOAuth::with(3600, true, false);
        let mut grant = stale(mock.clone()).await;

        assert_eq!(refresh(&mut grant, mock).await.err(), Some(Error::Token));
        let saved = serde_json::to_string(&grant).unwrap();
        assert!(saved.contains("rotated-refresh-secret"));
        assert!(!saved.contains("first-refresh-secret"));
    }

    #[tokio::test]
    async fn an_outage_during_refresh_keeps_the_sign_in_and_does_not_ask_for_a_new_one() {
        let mock = MockOAuth::with(3600, false, true);
        let mut grant = stale(mock.clone()).await;

        assert_eq!(
            refresh(&mut grant, mock).await.err(),
            Some(Error::Unavailable)
        );
        assert!(
            serde_json::to_string(&grant)
                .unwrap()
                .contains("first-refresh-secret")
        );
        assert_eq!(
            Error::from(AuthError::TokenRefreshRejected("x".into())),
            Error::Expired
        );
    }

    #[tokio::test]
    async fn a_forced_refresh_asks_again_although_the_token_is_still_good() {
        let mock = MockOAuth::with(3600, false, false);
        let (flow, params) = pending(mock.clone()).await;
        let issuer = Some("https://auth.example.com");
        let (token, mut grant) =
            exchange(flow, "test-code", &params["state"], issuer, mock.clone())
                .await
                .unwrap();
        assert_eq!(token.expose_secret(), "first-access-secret");

        let token = force(&mut grant, mock.clone()).await.unwrap();
        assert_eq!(token.expose_secret(), "second-access-secret");
        assert!(
            serde_json::to_string(&grant)
                .unwrap()
                .contains("rotated-refresh-secret")
        );
        assert_eq!(mock.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn revoking_sends_the_refresh_token_only_where_the_provider_offers_it() {
        let mock = MockOAuth::with(3600, false, false);
        let (flow, params) = pending(mock.clone()).await;
        let issuer = Some("https://auth.example.com");
        let (_, mut grant) = exchange(flow, "test-code", &params["state"], issuer, mock)
            .await
            .unwrap();

        // This provider names no revocation endpoint: nothing to send.
        assert!(revocation(&grant).is_none());
        assert_eq!(revoke(&grant).await, Ok(false));

        let offered = json!("https://auth.example.com/revoke");
        grant
            .metadata
            .additional_fields
            .insert("revocation_endpoint".into(), offered);
        grant.client_secret = Some("client-secret".into());
        // A confidential client authenticates with Basic unless the provider
        // lists the form and not Basic.
        let (address, form) = revocation(&grant).unwrap();
        assert_eq!(address, "https://auth.example.com/revoke");
        let token = [
            ("token", "first-refresh-secret".to_owned()),
            ("token_type_hint", "refresh_token".to_owned()),
        ];
        assert_eq!(form, token);
        let basic = basic_secret(&grant).unwrap();
        assert_eq!(
            basic,
            ("test-client".to_owned(), "client-secret".to_owned())
        );

        let methods = json!(["client_secret_post"]);
        grant
            .metadata
            .additional_fields
            .insert("token_endpoint_auth_methods_supported".into(), methods);
        assert!(basic_secret(&grant).is_none());
        let (_, form) = revocation(&grant).unwrap();
        assert_eq!(
            form[2..],
            [
                ("client_id", "test-client".to_owned()),
                ("client_secret", "client-secret".to_owned()),
            ]
        );

        // A public client only names itself.
        grant.client_secret = None;
        let (_, form) = revocation(&grant).unwrap();
        assert_eq!(form[2..], [("client_id", "test-client".to_owned())]);
    }
}
