//! OAuth discovery metadata.
//!
//! - Protected Resource Metadata (RFC 9728) tells the MCP client which
//!   authorization server protects the MCP endpoint.
//! - Authorization Server Metadata (RFC 8414) describes the endpoints. Tokens
//!   are opaque, not JWTs, so there is no `jwks_uri`.
//!
//! Serve [`authorization_server`] at `/.well-known/oauth-authorization-server`
//! (smiet also serves it at `/.well-known/openid-configuration` for clients
//! that only probe OIDC discovery), and [`protected_resource`] at
//! `/.well-known/oauth-protected-resource` and
//! `/.well-known/oauth-protected-resource/mcp`.

use serde_json::{Value, json};

/// What the authorization server supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMetadata {
    /// `scopes_supported`: every scope a client may request.
    pub scopes: Vec<String>,
    /// Advertise the `refresh_token` grant.
    pub refresh_tokens: bool,
    /// Advertise an RFC 7009 `revocation_endpoint` at [`Paths::revoke`].
    pub revocation: bool,
    /// The authorization response carries `iss` (RFC 9207). Set it only when
    /// the app actually appends `iss` to its redirects.
    pub iss_parameter: bool,
    pub paths: Paths,
}

/// Endpoint paths, relative to the issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub authorize: String,
    pub token: String,
    pub register: String,
    pub revoke: String,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            authorize: "/oauth/authorize".into(),
            token: "/oauth/token".into(),
            register: "/oauth/register".into(),
            revoke: "/oauth/revoke".into(),
        }
    }
}

/// The RFC 8414 authorization server metadata document. `base` is the issuer,
/// e.g. `https://dowat.app`; a trailing slash is dropped.
pub fn authorization_server(base: &str, opts: &ServerMetadata) -> Value {
    let base = base.trim_end_matches('/');
    let grants: &[&str] = if opts.refresh_tokens {
        &["authorization_code", "refresh_token"]
    } else {
        &["authorization_code"]
    };
    let mut doc = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}{}", opts.paths.authorize),
        "token_endpoint": format!("{base}{}", opts.paths.token),
        "registration_endpoint": format!("{base}{}", opts.paths.register),
        "response_types_supported": ["code"],
        "grant_types_supported": grants,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": opts.scopes,
    });
    if opts.revocation {
        doc["revocation_endpoint"] = json!(format!("{base}{}", opts.paths.revoke));
        doc["revocation_endpoint_auth_methods_supported"] = json!(["none"]);
    }
    if opts.iss_parameter {
        doc["authorization_response_iss_parameter_supported"] = json!(true);
    }
    doc
}

/// The RFC 9728 protected resource metadata for the resource at
/// `{base}{resource_path}`, protected by the issuer `base`.
pub fn protected_resource(
    base: &str,
    resource_path: &str,
    scopes: &[String],
    resource_name: Option<&str>,
) -> Value {
    let base = base.trim_end_matches('/');
    let mut doc = json!({
        "resource": format!("{base}{resource_path}"),
        "authorization_servers": [base],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    });
    if let Some(name) = resource_name {
        doc["resource_name"] = json!(name);
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dowat_documents_are_unchanged() {
        let base = "https://dowat.test";
        let opts = ServerMetadata {
            scopes: strings(&["tasks:write", "offline_access"]),
            refresh_tokens: true,
            revocation: true,
            iss_parameter: true,
            paths: Paths::default(),
        };
        assert_eq!(
            authorization_server(base, &opts),
            json!({"issuer": base,
                "authorization_endpoint": format!("{base}/oauth/authorize"),
                "token_endpoint": format!("{base}/oauth/token"),
                "registration_endpoint": format!("{base}/oauth/register"),
                "revocation_endpoint": format!("{base}/oauth/revoke"),
                "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
                "revocation_endpoint_auth_methods_supported": ["none"],
                "authorization_response_iss_parameter_supported": true,
                "scopes_supported": ["tasks:write", "offline_access"]})
        );
        assert_eq!(
            protected_resource(base, "/mcp", &strings(&["tasks:write"]), Some("DoWat")),
            json!({"resource": format!("{base}/mcp"), "authorization_servers": [base],
                "scopes_supported": ["tasks:write"], "bearer_methods_supported": ["header"], "resource_name": "DoWat"})
        );
    }

    #[test]
    fn smiet_documents_are_unchanged() {
        // smiet trims a trailing slash off its configured base URL.
        let configured = "https://smiet.test/";
        let base = "https://smiet.test";
        let opts = ServerMetadata {
            scopes: strings(&["mcp"]),
            refresh_tokens: false,
            revocation: false,
            iss_parameter: false,
            paths: Paths::default(),
        };
        assert_eq!(
            authorization_server(configured, &opts),
            json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/oauth/authorize"),
                "token_endpoint": format!("{base}/oauth/token"),
                "registration_endpoint": format!("{base}/oauth/register"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["mcp"],
            })
        );
        assert_eq!(
            protected_resource(configured, "/mcp", &strings(&["mcp"]), None),
            json!({
                "resource": format!("{base}/mcp"),
                "authorization_servers": [base],
                "scopes_supported": ["mcp"],
                "bearer_methods_supported": ["header"],
            })
        );
    }

    #[test]
    fn custom_paths_are_used() {
        let opts = ServerMetadata {
            scopes: strings(&["mcp"]),
            refresh_tokens: false,
            revocation: true,
            iss_parameter: false,
            paths: Paths {
                token: "/api/oauth/token".into(),
                revoke: "/api/oauth/revoke".into(),
                ..Paths::default()
            },
        };
        let doc = authorization_server("https://a.test", &opts);
        assert_eq!(doc["token_endpoint"], "https://a.test/api/oauth/token");
        assert_eq!(
            doc["revocation_endpoint"],
            "https://a.test/api/oauth/revoke"
        );
    }
}
