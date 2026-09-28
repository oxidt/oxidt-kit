//! The `WWW-Authenticate` header a protected resource sends with its 401, so
//! an MCP client can discover the authorization server (RFC 9728 §5.1).

/// `Bearer resource_metadata="…"`, plus `scope="…"` when given.
///
/// ```
/// use oxidt_mcp_oauth::challenge::www_authenticate;
///
/// assert_eq!(
///     www_authenticate(
///         "https://dowat.app/.well-known/oauth-protected-resource/mcp",
///         Some("tasks:write"),
///     ),
///     r#"Bearer resource_metadata="https://dowat.app/.well-known/oauth-protected-resource/mcp", scope="tasks:write""#,
/// );
/// ```
pub fn www_authenticate(resource_metadata_url: &str, scope: Option<&str>) -> String {
    match scope {
        Some(scope) => {
            format!("Bearer resource_metadata=\"{resource_metadata_url}\", scope=\"{scope}\"")
        }
        None => format!("Bearer resource_metadata=\"{resource_metadata_url}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smiet_challenge_has_no_scope() {
        assert_eq!(
            www_authenticate(
                "https://smiet.test/.well-known/oauth-protected-resource",
                None
            ),
            "Bearer resource_metadata=\"https://smiet.test/.well-known/oauth-protected-resource\""
        );
    }
}
