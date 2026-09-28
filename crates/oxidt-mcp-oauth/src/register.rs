//! Dynamic Client Registration (RFC 7591).
//!
//! Unauthenticated on purpose: the `client_id` handed back is not a secret.
//! The real boundary is the [`Allowlist`], which restricts callbacks to known
//! MCP hosts and loopback. Only public clients are registered — no secret, and
//! `token_endpoint_auth_method` is always `none`.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Allowlist, OAuthError, Scopes};

/// At most this many redirect URIs per client.
const MAX_REDIRECT_URIS: usize = 8;
/// `client_name` is registrant-supplied and shown on the consent screen.
const MAX_CLIENT_NAME: usize = 100;

/// The registration request body (JSON). Fields the server does not act on
/// are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
}

/// A validated registration, ready for the app to store under a fresh
/// `client_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// Trimmed; `None` when the client sent none. The app picks the fallback
    /// it shows on the consent screen.
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
}

/// Validate a registration request:
///
/// - 1 to 8 `redirect_uris`, every one on the allowlist → else
///   `invalid_redirect_uri`;
/// - `token_endpoint_auth_method` absent or `none`; `grant_types`, when given,
///   include `authorization_code` and nothing beyond `refresh_token`;
///   `response_types`, when given, exactly `["code"]`;
/// - `client_name` non-blank, at most 100 bytes, no control characters
///   → else `invalid_client_metadata`.
pub fn validate(req: Request, allowlist: &Allowlist) -> Result<Registration, OAuthError> {
    if req.redirect_uris.is_empty() {
        return Err(OAuthError::invalid_redirect_uri(
            "at least one redirect_uri is required",
        ));
    }
    if req.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(OAuthError::invalid_redirect_uri("too many redirect_uris"));
    }
    if req
        .redirect_uris
        .iter()
        .any(|u| !allowlist.redirect_uri_allowed(u))
    {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri is not on the allowlist",
        ));
    }
    if req
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|m| m != "none")
    {
        return Err(OAuthError::invalid_client_metadata(
            "only public clients (token_endpoint_auth_method=none) are supported",
        ));
    }
    if req.grant_types.as_ref().is_some_and(|g| {
        !g.iter().any(|v| v == "authorization_code")
            || g.iter()
                .any(|v| v != "authorization_code" && v != "refresh_token")
    }) {
        return Err(OAuthError::invalid_client_metadata(
            "unsupported grant_types",
        ));
    }
    if req
        .response_types
        .as_ref()
        .is_some_and(|r| r.as_slice() != ["code"])
    {
        return Err(OAuthError::invalid_client_metadata(
            "only response_type code is supported",
        ));
    }
    let client_name = match req.client_name {
        None => None,
        Some(name) => {
            let name = name.trim();
            if name.is_empty() || name.len() > MAX_CLIENT_NAME || name.chars().any(char::is_control)
            {
                return Err(OAuthError::invalid_client_metadata("invalid client_name"));
            }
            Some(name.to_string())
        }
    };
    Ok(Registration {
        client_name,
        redirect_uris: req.redirect_uris,
    })
}

/// The `201 Created` response body for a stored registration. `scope` is the
/// required scopes; `grant_types` includes `refresh_token` when the server
/// issues refresh tokens.
pub fn response(
    client_id: &str,
    reg: &Registration,
    scopes: &Scopes,
    refresh_tokens: bool,
) -> Value {
    let grants: &[&str] = if refresh_tokens {
        &["authorization_code", "refresh_token"]
    } else {
        &["authorization_code"]
    };
    let mut body = json!({
        "client_id": client_id,
        "redirect_uris": reg.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": grants,
        "response_types": ["code"],
        "scope": scopes.default_scope(),
    });
    if let Some(name) = &reg.client_name {
        body["client_name"] = json!(name);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

    fn req(uris: &[&str]) -> Request {
        Request {
            redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn err(r: Request) -> &'static str {
        validate(r, &Allowlist::claude()).unwrap_err().error
    }

    #[test]
    fn redirect_uris_must_be_one_to_eight_and_all_allowed() {
        assert_eq!(err(req(&[])), "invalid_redirect_uri");
        assert_eq!(err(req(&[CALLBACK; 9])), "invalid_redirect_uri");
        assert!(validate(req(&[CALLBACK; 8]), &Allowlist::claude()).is_ok());
        assert_eq!(
            err(req(&[CALLBACK, "https://attacker.test/callback"])),
            "invalid_redirect_uri"
        );
    }

    #[test]
    fn only_public_code_clients() {
        let mut r = req(&[CALLBACK]);
        r.token_endpoint_auth_method = Some("client_secret_basic".into());
        assert_eq!(err(r), "invalid_client_metadata");

        let mut r = req(&[CALLBACK]);
        r.token_endpoint_auth_method = Some("none".into());
        r.grant_types = Some(vec!["authorization_code".into(), "refresh_token".into()]);
        r.response_types = Some(vec!["code".into()]);
        assert!(validate(r, &Allowlist::claude()).is_ok());

        for grants in [
            vec!["refresh_token"],
            vec!["authorization_code", "client_credentials"],
            vec!["implicit"],
        ] {
            let mut r = req(&[CALLBACK]);
            r.grant_types = Some(grants.into_iter().map(String::from).collect());
            assert_eq!(err(r), "invalid_client_metadata");
        }
        let mut r = req(&[CALLBACK]);
        r.response_types = Some(vec!["token".into()]);
        assert_eq!(err(r), "invalid_client_metadata");
    }

    #[test]
    fn client_name_is_trimmed_and_bounded() {
        let mut r = req(&[CALLBACK]);
        r.client_name = Some("  Claude  ".into());
        let reg = validate(r, &Allowlist::claude()).unwrap();
        assert_eq!(reg.client_name.as_deref(), Some("Claude"));

        for bad in ["   ", "evil\u{7}name", &"x".repeat(101)] {
            let mut r = req(&[CALLBACK]);
            r.client_name = Some(bad.into());
            assert_eq!(err(r), "invalid_client_metadata", "{bad:?}");
        }
        assert_eq!(
            validate(req(&[CALLBACK]), &Allowlist::claude())
                .unwrap()
                .client_name,
            None
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let r: Request = serde_json::from_str(
            r#"{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"logo_uri":"x"}"#,
        )
        .unwrap();
        assert!(validate(r, &Allowlist::claude()).is_ok());
    }

    #[test]
    fn response_matches_each_app() {
        let reg = Registration {
            client_name: Some("Claude".into()),
            redirect_uris: vec![CALLBACK.into()],
        };
        let dowat = Scopes {
            required: vec!["tasks:write".into()],
            optional: vec!["offline_access".into()],
        };
        assert_eq!(
            response("mcp_abc", &reg, &dowat, true),
            json!({
                "client_id": "mcp_abc", "client_name": "Claude", "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"], "scope": "tasks:write"
            })
        );
        let smiet = Scopes {
            required: vec!["mcp".into()],
            optional: vec![],
        };
        let reg = Registration {
            client_name: None,
            ..reg
        };
        let body = response("mcp_abc", &reg, &smiet, false);
        assert_eq!(body["grant_types"], json!(["authorization_code"]));
        assert_eq!(body["scope"], "mcp");
        assert!(body.get("client_name").is_none());
    }
}
