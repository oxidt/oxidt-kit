//! The token endpoint's request parsing and authorization-code checks
//! (RFC 6749 §4.1.3, PKCE per RFC 7636 §4.6, RFC 8707 resource binding).
//!
//! The app still owns the code store: it must *take* the code (delete on
//! read, so a code is single-use), fill a [`StoredCode`] from it, and call
//! [`verify_code_exchange`]. What it then issues — an opaque token pair it
//! stores hashed, or a minted API key — is its own business. Refresh-token
//! rotation lives in the app too; [`parse`] only hands it the fields.

use serde::Deserialize;

use crate::OAuthError;

/// The token request form. Missing values deserialize as empty.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub code_verifier: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenGrant {
    pub refresh_token: String,
    pub client_id: String,
    /// When present, must equal the grant's scope (no narrowing or widening).
    pub scope: Option<String>,
    pub resource: Option<String>,
}

/// A parsed token request. A server without refresh tokens answers
/// [`Grant::RefreshToken`] with `unsupported_grant_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    AuthorizationCode(AuthorizationCodeGrant),
    RefreshToken(RefreshTokenGrant),
}

/// Parse a token request. `authorization_code` needs `code`, `code_verifier`,
/// `client_id` and `redirect_uri`; `refresh_token` needs `refresh_token` and
/// `client_id` — else `invalid_request`. Any other grant type is
/// `unsupported_grant_type`.
pub fn parse(req: Request) -> Result<Grant, OAuthError> {
    let missing = |field: &str| OAuthError::invalid_request(format!("{field} is required"));
    match req.grant_type.as_str() {
        "authorization_code" => {
            for (name, value) in [
                ("code", &req.code),
                ("code_verifier", &req.code_verifier),
                ("client_id", &req.client_id),
                ("redirect_uri", &req.redirect_uri),
            ] {
                if value.is_empty() {
                    return Err(missing(name));
                }
            }
            Ok(Grant::AuthorizationCode(AuthorizationCodeGrant {
                code: req.code,
                redirect_uri: req.redirect_uri,
                client_id: req.client_id,
                code_verifier: req.code_verifier,
                resource: req.resource,
            }))
        }
        "refresh_token" => {
            if req.refresh_token.is_empty() {
                return Err(missing("refresh_token"));
            }
            if req.client_id.is_empty() {
                return Err(missing("client_id"));
            }
            Ok(Grant::RefreshToken(RefreshTokenGrant {
                refresh_token: req.refresh_token,
                client_id: req.client_id,
                scope: req.scope,
                resource: req.resource,
            }))
        }
        _ => Err(OAuthError::unsupported_grant_type(
            "grant_type is not supported",
        )),
    }
}

/// The authorization code as the app stored it at consent time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    /// The resource the code was bound to at authorize time, if any.
    pub resource: Option<String>,
    /// Unix seconds; the code is dead at `expires_at`.
    pub expires_at: i64,
}

/// Check a code exchange against the stored code: same client, same
/// `redirect_uri`, not expired at `now`, a well-formed verifier that hashes to
/// the stored S256 challenge (`invalid_grant` for all of these), and — when
/// the code is bound to a resource — a `resource` parameter that is absent or
/// equal to it (`invalid_target`).
pub fn verify_code_exchange(
    grant: &AuthorizationCodeGrant,
    stored: &StoredCode,
    now: i64,
) -> Result<(), OAuthError> {
    if grant.client_id != stored.client_id {
        return Err(OAuthError::invalid_grant(
            "code was issued to another client",
        ));
    }
    if grant.redirect_uri != stored.redirect_uri {
        return Err(OAuthError::invalid_grant("redirect_uri does not match"));
    }
    if stored.expires_at <= now {
        return Err(OAuthError::invalid_grant("code expired"));
    }
    if !valid_verifier(&grant.code_verifier)
        || !oxidt_crypto::verify_pkce_s256(&grant.code_verifier, &stored.code_challenge)
    {
        return Err(OAuthError::invalid_grant("PKCE verification failed"));
    }
    if let (Some(bound), Some(requested)) = (&stored.resource, &grant.resource)
        && bound != requested
    {
        return Err(OAuthError::invalid_target("resource does not match"));
    }
    Ok(())
}

/// RFC 7636 §4.1: 43 to 128 unreserved characters.
fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const RESOURCE: &str = "https://dowat.test/mcp";
    const NOW: i64 = 1_000_000;

    fn stored() -> StoredCode {
        StoredCode {
            client_id: "client".into(),
            redirect_uri: CALLBACK.into(),
            code_challenge: CHALLENGE.into(),
            resource: Some(RESOURCE.into()),
            expires_at: NOW + 60,
        }
    }

    fn code_request() -> Request {
        Request {
            grant_type: "authorization_code".into(),
            client_id: "client".into(),
            code: "code".into(),
            redirect_uri: CALLBACK.into(),
            code_verifier: VERIFIER.into(),
            resource: Some(RESOURCE.into()),
            ..Default::default()
        }
    }

    fn grant(req: Request) -> AuthorizationCodeGrant {
        match parse(req).unwrap() {
            Grant::AuthorizationCode(g) => g,
            other => panic!("{other:?}"),
        }
    }

    fn err(g: &AuthorizationCodeGrant, s: &StoredCode) -> &'static str {
        verify_code_exchange(g, s, NOW).unwrap_err().error
    }

    #[test]
    fn valid_exchange_passes() {
        assert_eq!(
            verify_code_exchange(&grant(code_request()), &stored(), NOW),
            Ok(())
        );
        // The resource parameter may be omitted at the token endpoint.
        let mut req = code_request();
        req.resource = None;
        assert_eq!(verify_code_exchange(&grant(req), &stored(), NOW), Ok(()));
    }

    #[test]
    fn wrong_verifier_is_rejected() {
        let mut g = grant(code_request());
        g.code_verifier = "x".repeat(43);
        assert_eq!(err(&g, &stored()), "invalid_grant");
        // Malformed verifiers never reach the hash.
        g.code_verifier = "short".into();
        assert_eq!(err(&g, &stored()), "invalid_grant");
        g.code_verifier = format!("{VERIFIER}!");
        assert_eq!(err(&g, &stored()), "invalid_grant");
    }

    #[test]
    fn expired_code_is_rejected() {
        let g = grant(code_request());
        let mut s = stored();
        s.expires_at = NOW;
        assert_eq!(err(&g, &s), "invalid_grant");
        s.expires_at = NOW - 1;
        assert_eq!(err(&g, &s), "invalid_grant");
    }

    #[test]
    fn wrong_client_or_redirect_is_rejected() {
        let mut g = grant(code_request());
        g.client_id = "other".into();
        assert_eq!(err(&g, &stored()), "invalid_grant");
        let mut g = grant(code_request());
        g.redirect_uri = "http://localhost/callback".into();
        assert_eq!(err(&g, &stored()), "invalid_grant");
    }

    #[test]
    fn resource_mismatch_is_rejected_only_when_bound() {
        let mut g = grant(code_request());
        g.resource = Some("https://other.test/mcp".into());
        assert_eq!(err(&g, &stored()), "invalid_target");
        let mut s = stored();
        s.resource = None;
        assert_eq!(verify_code_exchange(&g, &s, NOW), Ok(()));
    }

    #[test]
    fn parse_requires_fields_per_grant() {
        for field in ["code", "code_verifier", "client_id", "redirect_uri"] {
            let mut req = code_request();
            match field {
                "code" => req.code.clear(),
                "code_verifier" => req.code_verifier.clear(),
                "client_id" => req.client_id.clear(),
                _ => req.redirect_uri.clear(),
            }
            assert_eq!(parse(req).unwrap_err().error, "invalid_request", "{field}");
        }
        let refresh = Request {
            grant_type: "refresh_token".into(),
            client_id: "client".into(),
            refresh_token: "r".into(),
            scope: Some("tasks:write".into()),
            ..Default::default()
        };
        assert_eq!(
            parse(refresh.clone()).unwrap(),
            Grant::RefreshToken(RefreshTokenGrant {
                refresh_token: "r".into(),
                client_id: "client".into(),
                scope: Some("tasks:write".into()),
                resource: None,
            })
        );
        let mut no_token = refresh;
        no_token.refresh_token.clear();
        assert_eq!(parse(no_token).unwrap_err().error, "invalid_request");
        for grant_type in ["", "client_credentials", "password"] {
            let req = Request {
                grant_type: grant_type.into(),
                ..code_request()
            };
            assert_eq!(parse(req).unwrap_err().error, "unsupported_grant_type");
        }
    }
}
