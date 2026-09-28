use serde_json::{Value, json};

/// An OAuth error response: an RFC error code plus a human-readable
/// description.
///
/// [`OAuthError::json`] is the response body and [`OAuthError::status`] its
/// status code; the app wraps both in whatever HTTP framework it uses. Token
/// responses, errors included, should also carry `Cache-Control: no-store`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{error}: {description}")]
pub struct OAuthError {
    /// The RFC error code, e.g. `invalid_grant`.
    pub error: &'static str,
    /// Sent as `error_description` when non-empty.
    pub description: String,
}

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        impl OAuthError {
            $(
                $(#[$doc])*
                pub fn $name(description: impl Into<String>) -> Self {
                    Self { error: stringify!($name), description: description.into() }
                }
            )*
        }
    };
}

codes! {
    /// RFC 6749 §4.1.2.1 / §5.2: a parameter is missing, repeated or malformed.
    invalid_request,
    /// RFC 6749 §5.2: the client is unknown.
    invalid_client,
    /// RFC 6749 §5.2: the code or refresh token is invalid, expired, replayed,
    /// or was issued to another client or redirect URI.
    invalid_grant,
    /// RFC 6749 §5.2: the grant type is not supported by this server.
    unsupported_grant_type,
    /// RFC 6749 §4.1.2.1: only `response_type=code` is supported.
    unsupported_response_type,
    /// RFC 6749 §4.1.2.1 / §5.2: the requested scope is unknown or incomplete.
    invalid_scope,
    /// RFC 8707 §2: the `resource` parameter names another resource server.
    invalid_target,
    /// RFC 7591 §3.2.2: a registered redirect URI is not allowed.
    invalid_redirect_uri,
    /// RFC 7591 §3.2.2: some other registration field is invalid.
    invalid_client_metadata,
    /// RFC 6749 §4.1.2.1: an unexpected condition on the server.
    server_error,
    /// RFC 6749 §4.1.2.1: the server is overloaded or its store unavailable.
    temporarily_unavailable,
}

impl OAuthError {
    /// The HTTP status: 500 for `server_error`, 503 for
    /// `temporarily_unavailable`, 400 for everything else.
    ///
    /// `invalid_client` stays 400: these are public clients, which never
    /// authenticate through the `Authorization` header that would make
    /// RFC 6749 §5.2 require a 401.
    pub fn status(&self) -> u16 {
        match self.error {
            "server_error" => 500,
            "temporarily_unavailable" => 503,
            _ => 400,
        }
    }

    /// The response body: `{"error": …}`, plus `error_description` when set.
    pub fn json(&self) -> Value {
        if self.description.is_empty() {
            json!({ "error": self.error })
        } else {
            json!({ "error": self.error, "error_description": self.description })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_omits_an_empty_description() {
        assert_eq!(
            OAuthError::invalid_grant("").json(),
            json!({ "error": "invalid_grant" })
        );
        assert_eq!(
            OAuthError::invalid_redirect_uri("not allowed").json(),
            json!({ "error": "invalid_redirect_uri", "error_description": "not allowed" })
        );
    }

    #[test]
    fn status_codes() {
        assert_eq!(OAuthError::invalid_client("").status(), 400);
        assert_eq!(OAuthError::server_error("").status(), 500);
        assert_eq!(OAuthError::temporarily_unavailable("").status(), 503);
    }
}
