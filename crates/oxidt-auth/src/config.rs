/// Configuration for auth routes, redirects, and FerrisKey integration.
///
/// Replaces all reads from `AppState.config.*` and `AppState.secrets.*`
/// that the auth crate previously needed.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// URL for the login page (e.g. "/login")
    pub login_page_url: String,
    /// Default redirect after login (e.g. "/org/redirect" or "/dashboard")
    pub default_post_login_url: String,
    /// Dev login page URL (e.g. "/dev/login")
    pub dev_login_url: String,

    // ── FerrisKey configuration ─────────────────────────────────────
    /// FerrisKey base API URL (e.g. "http://localhost:3333")
    pub ferriskey_url: String,
    /// FerrisKey public issuer base URL. If unset, derived from
    /// `ferriskey_url` by stripping a trailing `/api`.
    pub ferriskey_issuer_url: Option<String>,
    /// FerrisKey realm name (e.g. "myapp")
    pub ferriskey_realm: String,
    /// FerrisKey OIDC client ID (e.g. "myapp-dashboard")
    pub ferriskey_client_id: String,
    /// FerrisKey OIDC client secret. Required for authorization-code
    /// exchange and the client-credentials grant used for service-account
    /// calls (user lookup/create).
    pub ferriskey_client_secret: Option<String>,

    // ── Application URLs ───────────────────────────────────────────
    /// Base URL where the dashboard is deployed (e.g. "https://example.com")
    pub base_url: String,
    /// Whether auth rate limiting may trust X-Forwarded-For, X-Real-IP, and
    /// Forwarded headers from an upstream reverse proxy.
    pub trust_proxy_headers: bool,

    // ── SSO (browser-redirect login) ──────────────────────────────
    /// Mount the browser-redirect login routes (`GET /auth/sso/start`,
    /// `GET /auth/callback`, `POST /auth/sso/complete`) and end the FerrisKey
    /// session on logout. The browser is sent to FerrisKey's hosted login page
    /// and completes the code exchange itself, which is what puts FerrisKey's
    /// `FERRISKEY_IDENTITY` cookie in the browser: the next app in the same
    /// realm then logs in without a prompt.
    ///
    /// Requires `ferriskey_client_id` to be a **public** FerrisKey client (no
    /// secret is used), `ferriskey_url` to be reachable from the browser, and
    /// on the client: `{base_url}/auth/callback` as a redirect URI, web origin
    /// `+`, and `{base_url}{login_page_url}` as a post-logout redirect URI.
    pub sso_enabled: bool,

    // ── Registration allowlist ─────────────────────────────────────
    /// Exact, lowercased email addresses permitted to self-register.
    /// Empty means no address allowlist (see [`crate::AuthConfig`] docs on the
    /// bootstrap behaviour when both allowlists are empty).
    pub allowed_registration_emails: Vec<String>,
    /// Lowercased email domains (the part after `@`) permitted to self-register.
    /// Empty means no domain allowlist.
    pub allowed_registration_domains: Vec<String>,
    /// Open self-registration to every address, for a public product where
    /// anyone may sign up. Overrides both allowlists and the first-run
    /// bootstrap rule. Pair it with a captcha (`CAPTCHA_URL` and friends):
    /// with that unset, nothing stands in front of account creation.
    pub open_registration: bool,

    // ── Password login (local mode) ───────────────────────────────
    /// Offer a password step on the self-owned login flow
    /// (`local_auth_router`): `POST /auth/session/password/verify`, and
    /// `password: true` in the start-session response so the page shows the
    /// field. Set it when the app has any password to verify — i.e. when it
    /// overrides [`crate::AuthUserStore::verify_password`]; leaving it off
    /// with an implementation that answers `true` means the page never asks
    /// for one.
    ///
    /// The flag is global, never per-address: the start-session response
    /// mirrors it as-is, so it cannot be used to enumerate which addresses
    /// have a password. It is what makes an instance with only an admin
    /// email + password — no identity provider and no SMTP — able to log
    /// anyone in at all (see [`crate::AuthState::local_without_email`]).
    pub password_login: bool,

    // ── Terms of service ──────────────────────────────────────────
    /// The terms version a user must have accepted to log in, or `None` for
    /// no acceptance step at all. Compared to what the store returns in
    /// `AuthUser::tos_acceptance`; a mismatch (or nothing stored) sends them
    /// through the acceptance step on both login flows, so bumping this
    /// re-prompts everyone. Any string works: a date, a semver, a hash. The
    /// step links to `/legal/terms` and `/legal/privacy`, which the app serves.
    pub tos_version: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            login_page_url: "/login".to_string(),
            default_post_login_url: "/dashboard".to_string(),
            dev_login_url: "/dev/login".to_string(),
            ferriskey_url: String::new(),
            ferriskey_issuer_url: None,
            ferriskey_realm: String::new(),
            ferriskey_client_id: String::new(),
            ferriskey_client_secret: None,
            base_url: "http://localhost:8080".to_string(),
            trust_proxy_headers: false,
            sso_enabled: false,
            allowed_registration_emails: Vec::new(),
            allowed_registration_domains: Vec::new(),
            open_registration: false,
            password_login: false,
            tos_version: None,
        }
    }
}

/// `SSO_ISSUER_URL` and `SSO_CLIENT_ID`: the generic OIDC issuer an app logs
/// in against when its operator selects SSO (each app owns that switch, e.g.
/// `AUTH_MODE=sso`). Shared names, so every app is configured the same way.
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct SsoSettings {
    /// The issuer URL, exactly as it appears in the id_token's `iss`.
    pub issuer_url: String,
    /// The public client registered for this app at the issuer.
    pub client_id: String,
}

#[cfg(feature = "axum")]
impl SsoSettings {
    pub const ISSUER_URL_VAR: &'static str = "SSO_ISSUER_URL";
    pub const CLIENT_ID_VAR: &'static str = "SSO_CLIENT_ID";

    /// Read both variables; an `Err` names the one that is missing or not an
    /// absolute URL, for the app to fail at boot with.
    pub fn from_env() -> crate::AuthResult<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> crate::AuthResult<Self> {
        let required = |key: &str| {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    crate::AuthError::ServerStateError(format!("SSO login needs {key} to be set"))
                })
        };
        let issuer_url = required(Self::ISSUER_URL_VAR)?;
        url::Url::parse(&issuer_url).map_err(|e| {
            crate::AuthError::ServerStateError(format!(
                "{} is not an absolute URL ({issuer_url:?}): {e}",
                Self::ISSUER_URL_VAR
            ))
        })?;
        Ok(Self {
            issuer_url,
            client_id: required(Self::CLIENT_ID_VAR)?,
        })
    }

    /// The JWKS cache for [`crate::AuthState::jwks_cache`]; it is what switches
    /// `auth_router` to this issuer.
    pub fn jwks_cache(&self) -> crate::JwksCache {
        crate::JwksCache::oidc(&self.issuer_url, &self.client_id)
    }
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use super::SsoSettings;

    fn settings(vars: &[(&str, &str)]) -> crate::AuthResult<SsoSettings> {
        SsoSettings::from_lookup(|key| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn sso_settings_name_the_missing_variable() {
        let err = settings(&[("SSO_CLIENT_ID", "app")]).unwrap_err();
        assert!(err.to_string().contains("SSO_ISSUER_URL"));
        let err = settings(&[("SSO_ISSUER_URL", "https://sso.example")]).unwrap_err();
        assert!(err.to_string().contains("SSO_CLIENT_ID"));
        let err =
            settings(&[("SSO_ISSUER_URL", "sso.example"), ("SSO_CLIENT_ID", "app")]).unwrap_err();
        assert!(err.to_string().contains("not an absolute URL"));
    }

    #[test]
    fn sso_settings_read_both_variables() {
        let s = settings(&[
            ("SSO_ISSUER_URL", " https://sso.example "),
            ("SSO_CLIENT_ID", "app"),
        ])
        .unwrap();
        assert_eq!(s.issuer_url, "https://sso.example");
        assert_eq!(s.client_id, "app");
        assert!(s.jwks_cache().is_oidc());
    }
}
