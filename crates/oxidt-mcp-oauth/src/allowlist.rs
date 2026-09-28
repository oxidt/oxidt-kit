//! Which `redirect_uri`s a client may register and be redirected to.
//!
//! Registration is unauthenticated and a `client_id` is not a secret, so this
//! allowlist is the real security boundary: an authorization code is only
//! ever delivered to a callback on it.

use url::Url;

const CLAUDE_AI: &str = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_COM: &str = "https://claude.com/api/mcp/auth_callback";
const CHATGPT: &str = "https://chatgpt.com/connector_platform_oauth_redirect";

/// Plain-`http` callbacks on `localhost`, `127.0.0.1` or `[::1]`, any port
/// (RFC 8252 §7.3) — for local development and the MCP inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopbackHttp {
    /// No loopback callbacks.
    Never,
    /// Any path on a loopback host.
    AnyPath,
    /// Only this exact path, e.g. `/callback`.
    Path(String),
}

/// The redirect-URI allowlist.
///
/// A URI is allowed when it matches an [`exact`](Self::exact) entry verbatim.
/// Otherwise it must parse, carry no userinfo, query or fragment, and then be
/// either a ChatGPT connector callback (when [`chatgpt`](Self::chatgpt) is set)
/// or a loopback callback permitted by [`loopback_http`](Self::loopback_http).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    /// Callbacks allowed verbatim — including custom schemes such as
    /// `com.example.app://oauth/callback` (RFC 8252 §7.1; PKCE guards against
    /// scheme squatting).
    pub exact: Vec<String>,
    /// Allow ChatGPT's fixed connector callback and its per-connector
    /// `https://chatgpt.com/connector/oauth/{id}` form.
    pub chatgpt: bool,
    pub loopback_http: LoopbackHttp,
}

impl Allowlist {
    /// claude.ai and claude.com's MCP callbacks, plus loopback on any path.
    pub fn claude() -> Self {
        Self {
            exact: vec![CLAUDE_AI.into(), CLAUDE_COM.into()],
            chatgpt: false,
            loopback_http: LoopbackHttp::AnyPath,
        }
    }

    /// Also allow ChatGPT's connector callbacks.
    pub fn with_chatgpt(mut self) -> Self {
        self.chatgpt = true;
        self
    }

    /// Also allow `uri` verbatim, e.g. a native app's custom-scheme callback.
    pub fn with_exact(mut self, uri: impl Into<String>) -> Self {
        self.exact.push(uri.into());
        self
    }

    /// Replace the loopback policy.
    pub fn with_loopback_http(mut self, policy: LoopbackHttp) -> Self {
        self.loopback_http = policy;
        self
    }

    /// Is `uri` allowed as a redirect target?
    pub fn redirect_uri_allowed(&self, uri: &str) -> bool {
        if self.exact.iter().any(|e| e == uri) || (self.chatgpt && uri == CHATGPT) {
            return true;
        }
        let Ok(url) = Url::parse(uri) else {
            return false;
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        if url.scheme() == "http" && is_loopback(&url) {
            return match &self.loopback_http {
                LoopbackHttp::Never => false,
                LoopbackHttp::AnyPath => true,
                LoopbackHttp::Path(path) => url.path() == path,
            };
        }
        // ChatGPT connections can have a callback-specific identifier.
        self.chatgpt
            && url.scheme() == "https"
            && url.host_str() == Some("chatgpt.com")
            && url.port().is_none()
            && url
                .path()
                .strip_prefix("/connector/oauth/")
                .is_some_and(|id| {
                    !id.is_empty()
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dowat: Claude + ChatGPT, loopback only on `/callback`.
    fn dowat() -> Allowlist {
        Allowlist::claude()
            .with_chatgpt()
            .with_loopback_http(LoopbackHttp::Path("/callback".into()))
    }

    /// smiet: Claude, the iOS app's custom scheme, loopback on any path.
    fn smiet() -> Allowlist {
        Allowlist::claude().with_exact("com.oxidt.smiet://oauth/callback")
    }

    #[test]
    fn callback_allowlist_rejects_lookalikes_userinfo_queries_and_fragments() {
        let list = dowat();
        for uri in [
            CLAUDE_AI,
            CLAUDE_COM,
            CHATGPT,
            "https://chatgpt.com/connector/oauth/abc-123",
            "http://localhost:4151/callback",
            "http://127.0.0.1:4151/callback",
            "http://[::1]:4151/callback",
        ] {
            assert!(list.redirect_uri_allowed(uri), "{uri}");
        }
        for uri in [
            "https://claude.ai.evil.test/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback#x",
            "https://chatgpt.com/connector/oauth/",
            "https://chatgpt.com/connector/oauth/a/b",
            "https://chatgpt.com:444/connector/oauth/a",
            "https://chatgpt.com/connector/oauth/a?next=evil",
            "http://localhost:80@evil.test/callback",
            "http://localhost.evil.test/callback",
            "http://localhost/other",
            "http://user@localhost/callback",
            "https://evil.test/callback",
        ] {
            assert!(!list.redirect_uri_allowed(uri), "{uri}");
        }
    }

    #[test]
    fn allows_claude_callbacks_custom_scheme_and_loopback() {
        let list = smiet();
        for uri in [
            CLAUDE_AI,
            CLAUDE_COM,
            "http://localhost:8765/callback",
            "http://127.0.0.1/cb",
            "http://[::1]/anything",
            "com.oxidt.smiet://oauth/callback",
        ] {
            assert!(list.redirect_uri_allowed(uri), "{uri}");
        }
    }

    #[test]
    fn rejects_arbitrary_and_https_non_claude() {
        let list = smiet();
        for uri in [
            "https://evil.example.com/callback",
            "https://claude.ai.evil.com/api/mcp/auth_callback",
            "http://example.com/callback",
            "com.oxidt.smiet://other/path",
            "not-a-url",
            // ChatGPT is opt-in.
            CHATGPT,
            "https://chatgpt.com/connector/oauth/abc",
            // Loopback must be plain http.
            "https://localhost/callback",
        ] {
            assert!(!list.redirect_uri_allowed(uri), "{uri}");
        }
    }

    #[test]
    fn any_path_loopback_still_rejects_userinfo_queries_and_fragments() {
        let list = smiet();
        for uri in [
            "http://user@localhost/cb",
            "http://user:pw@127.0.0.1/cb",
            "http://localhost:80@evil.test/cb",
            "http://localhost/cb?next=evil",
            "http://localhost/cb#x",
            "http://localhost.evil.test/cb",
        ] {
            assert!(!list.redirect_uri_allowed(uri), "{uri}");
        }
    }

    #[test]
    fn loopback_can_be_switched_off() {
        let list = Allowlist::claude().with_loopback_http(LoopbackHttp::Never);
        assert!(!list.redirect_uri_allowed("http://localhost/callback"));
        assert!(list.redirect_uri_allowed(CLAUDE_AI));
    }
}
