//! The authorization endpoint's request validation (RFC 6749 §4.1.1, PKCE per
//! RFC 7636, resource indicators per RFC 8707).
//!
//! The app looks the client up in its own store, calls [`validate`], and on
//! success stashes the [`Validated`] request wherever it keeps pending
//! consents — so the consent form never carries security-critical values.
//! After the user decides, it mints and stores a code and sends the browser to
//! [`redirect_url`] with `code` (or `error=access_denied`) and `state`.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Allowlist, OAuthError, Scopes};

/// `state` is echoed back verbatim; bound it so a pending request stays small.
const MAX_STATE: usize = 2048;

/// The authorize query parameters. Missing values deserialize as empty, which
/// [`validate`] then rejects with the right error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

/// A request that passed [`validate`]: what the app keeps until consent, and
/// then alongside the code it mints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validated {
    pub client_id: String,
    pub redirect_uri: String,
    /// The S256 challenge, to check the verifier against at the token endpoint.
    pub code_challenge: String,
    /// Space-separated, validated; the required scopes when none was asked for.
    pub scope: String,
    pub state: Option<String>,
    /// The resource the code is bound to, when the server binds one.
    pub resource: Option<String>,
}

/// Why an authorize request was refused (RFC 6749 §4.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeError {
    /// The `redirect_uri` is not one of this client's, or not on the
    /// allowlist. It cannot be trusted as a redirect target: render an error
    /// page — redirecting would make the server an open redirector.
    #[error("redirect_uri is not registered for this client or not allowed")]
    InvalidRedirectUri,
    /// The redirect target is trusted: send the browser back to it with
    /// `error=…` and `state` via [`redirect_url`].
    #[error("{0}")]
    Redirect(OAuthError),
}

impl AuthorizeError {
    /// The error code, for an app that answers with JSON rather than a
    /// redirect.
    pub fn error(&self) -> &'static str {
        match self {
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::Redirect(e) => e.error,
        }
    }
}

/// Validate an authorize request for a client the app has already looked up
/// (an unknown `client_id` is the app's `invalid_client` / error page).
///
/// In order: `redirect_uri` must be one of `client_redirect_uris` **and** on
/// the allowlist; `response_type=code`; `code_challenge_method=S256` (`plain`
/// is rejected) with a well-formed 43-character challenge; `state` at most
/// 2048 bytes; `resource`, when the server binds one (`resource =
/// Some(expected)`), absent or equal to it; `scope` valid for `scopes`.
pub fn validate(
    req: &Request,
    client_redirect_uris: &[String],
    allowlist: &Allowlist,
    scopes: &Scopes,
    resource: Option<&str>,
) -> Result<Validated, AuthorizeError> {
    if !client_redirect_uris.contains(&req.redirect_uri)
        || !allowlist.redirect_uri_allowed(&req.redirect_uri)
    {
        return Err(AuthorizeError::InvalidRedirectUri);
    }
    let fail = |e| Err(AuthorizeError::Redirect(e));
    if req.response_type != "code" {
        return fail(OAuthError::unsupported_response_type(
            "only response_type=code is supported",
        ));
    }
    if req.code_challenge_method != "S256" {
        return fail(OAuthError::invalid_request(
            "code_challenge_method must be S256",
        ));
    }
    if !valid_s256_challenge(&req.code_challenge) {
        return fail(OAuthError::invalid_request("invalid code_challenge"));
    }
    if req.state.as_ref().is_some_and(|s| s.len() > MAX_STATE) {
        return fail(OAuthError::invalid_request("state is too long"));
    }
    if let (Some(expected), Some(requested)) = (resource, &req.resource)
        && requested != expected
    {
        return fail(OAuthError::invalid_target("unknown resource"));
    }
    let scope = match &req.scope {
        None => scopes.default_scope(),
        Some(s) => match scopes.validate_scope(s) {
            Ok(granted) => granted.join(" "),
            Err(e) => return fail(OAuthError::invalid_scope(e.to_string())),
        },
    };
    Ok(Validated {
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        code_challenge: req.code_challenge.clone(),
        scope,
        state: req.state.clone(),
        resource: resource.map(str::to_string),
    })
}

/// `redirect_uri` with `params` appended to its query — the authorization
/// response (`code`, `state`, `iss`) or an error (`error`, `state`).
pub fn redirect_url(redirect_uri: &str, params: &[(&str, &str)]) -> Result<Url, url::ParseError> {
    let mut url = Url::parse(redirect_uri)?;
    url.query_pairs_mut().extend_pairs(params.iter().copied());
    Ok(url)
}

/// An S256 challenge is base64url (no padding) of a 32-byte SHA-256 digest:
/// exactly 43 characters, the last carrying 4 data bits and 2 zero bits.
fn valid_s256_challenge(challenge: &str) -> bool {
    let b = challenge.as_bytes();
    b.len() == 43
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoopbackHttp;

    const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RESOURCE: &str = "https://dowat.test/mcp";

    fn allowlist() -> Allowlist {
        Allowlist::claude()
            .with_chatgpt()
            .with_loopback_http(LoopbackHttp::Path("/callback".into()))
    }

    fn scopes() -> Scopes {
        Scopes {
            required: vec!["tasks:write".into()],
            optional: vec!["offline_access".into()],
        }
    }

    fn valid() -> Request {
        Request {
            client_id: "client".into(),
            redirect_uri: CALLBACK.into(),
            response_type: "code".into(),
            code_challenge: oxidt_crypto::pkce_s256_challenge(VERIFIER),
            code_challenge_method: "S256".into(),
            state: Some("state & encoded=✓".into()),
            ..Default::default()
        }
    }

    fn check(req: &Request) -> Result<Validated, AuthorizeError> {
        validate(
            req,
            &[CALLBACK.to_string()],
            &allowlist(),
            &scopes(),
            Some(RESOURCE),
        )
    }

    #[test]
    fn valid_request_binds_resource_and_defaults_scope() {
        let v = check(&valid()).unwrap();
        assert_eq!(v.scope, "tasks:write");
        assert_eq!(v.resource.as_deref(), Some(RESOURCE));
        assert_eq!(v.state.as_deref(), Some("state & encoded=✓"));

        let mut req = valid();
        req.resource = Some(RESOURCE.into());
        req.scope = Some("tasks:write offline_access".into());
        assert_eq!(check(&req).unwrap().scope, "tasks:write offline_access");
    }

    #[test]
    fn authorize_binds_registered_redirect_pkce_resource_and_scope() {
        // Allowlisted but not registered for this client: never redirect.
        let mut p = valid();
        p.redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect".into();
        assert_eq!(check(&p).unwrap_err(), AuthorizeError::InvalidRedirectUri);

        // Registered but no longer allowlisted: never redirect either.
        let mut p = valid();
        p.redirect_uri = "https://evil.test/callback".into();
        let err = validate(
            &p,
            &["https://evil.test/callback".to_string()],
            &allowlist(),
            &scopes(),
            None,
        );
        assert_eq!(err.unwrap_err(), AuthorizeError::InvalidRedirectUri);

        let mut p = valid();
        p.response_type = "token".into();
        assert_eq!(check(&p).unwrap_err().error(), "unsupported_response_type");

        let mut p = valid();
        p.code_challenge_method = "plain".into();
        assert_eq!(check(&p).unwrap_err().error(), "invalid_request");

        let mut p = valid();
        p.code_challenge_method = String::new();
        assert_eq!(check(&p).unwrap_err().error(), "invalid_request");

        let mut p = valid();
        p.code_challenge = "not-a-sha256-challenge".into();
        assert_eq!(check(&p).unwrap_err().error(), "invalid_request");

        let mut p = valid();
        p.resource = Some("https://other.test/mcp".into());
        assert_eq!(check(&p).unwrap_err().error(), "invalid_target");

        let mut p = valid();
        p.scope = Some("tasks:write calendar:read".into());
        assert_eq!(check(&p).unwrap_err().error(), "invalid_scope");
    }

    #[test]
    fn s256_only_rejects_plain_even_with_a_verifier_shaped_challenge() {
        let mut p = valid();
        p.code_challenge_method = "plain".into();
        p.code_challenge = VERIFIER.into();
        assert_eq!(
            check(&p).unwrap_err(),
            AuthorizeError::Redirect(OAuthError::invalid_request(
                "code_challenge_method must be S256"
            ))
        );
    }

    #[test]
    fn challenge_shape() {
        assert!(valid_s256_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        // Right length, but the last character carries non-zero padding bits.
        assert!(!valid_s256_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"
        ));
        assert!(!valid_s256_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"
        ));
        assert!(!valid_s256_challenge(""));
        assert!(!valid_s256_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM="
        ));
    }

    #[test]
    fn state_is_optional_but_bounded() {
        let mut p = valid();
        p.state = None;
        assert_eq!(check(&p).unwrap().state, None);
        p.state = Some("x".repeat(2049));
        assert_eq!(check(&p).unwrap_err().error(), "invalid_request");
    }

    #[test]
    fn unbound_server_ignores_resource() {
        // smiet: no resource binding, scope `mcp`, loopback on any path.
        let smiet = Scopes {
            required: vec!["mcp".into()],
            optional: vec![],
        };
        let mut p = valid();
        p.redirect_uri = "http://127.0.0.1:3000/cb".into();
        p.resource = Some("https://anything.test/mcp".into());
        let v = validate(
            &p,
            &[p.redirect_uri.clone()],
            &Allowlist::claude(),
            &smiet,
            None,
        )
        .unwrap();
        assert_eq!(v.resource, None);
        assert_eq!(v.scope, "mcp");
    }

    #[test]
    fn query_deserializes_with_missing_fields() {
        let req: Request = serde_json::from_str(r#"{"client_id":"c","redirect_uri":"x"}"#).unwrap();
        assert_eq!(req.response_type, "");
        assert_eq!(req.state, None);
    }

    #[test]
    fn redirect_url_appends_encoded_params() {
        let url = redirect_url(
            "https://claude.ai/api/mcp/auth_callback",
            &[("code", "abc"), ("state", "a b&c")],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://claude.ai/api/mcp/auth_callback?code=abc&state=a+b%26c"
        );
        let url = redirect_url(
            "com.oxidt.smiet://oauth/callback",
            &[("error", "access_denied")],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "com.oxidt.smiet://oauth/callback?error=access_denied"
        );
        assert!(redirect_url("not a url", &[]).is_err());
    }
}
