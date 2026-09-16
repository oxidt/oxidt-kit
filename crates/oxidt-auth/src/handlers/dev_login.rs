//! Development-only login bypass.
//!
//! Signs in as a fixed local user without going through FerrisKey, so you can
//! iterate on authenticated pages without a running IdP. The session it creates
//! carries `id_token = "dev_mode_token"`, which [`crate::session::logout`] uses
//! to route logout back to the dev login page.
//!
//! # Redirect
//!
//! The form-encoded body may carry a `redirect_url`, so the control on the
//! login page can send the developer back where they were headed — the app's
//! OAuth flow lands on `/login?redirect_url=/oauth/authorize/resume` and has to
//! resume there. It is validated with the same `is_safe_redirect_url` check the
//! real login uses (relative paths only), and anything else falls back to
//! `AuthConfig::default_post_login_url`.
//!
//! The button is a plain HTML form POST, which browsers send with an `Origin`
//! (and `Referer`) header, so it satisfies [`crate::csrf::csrf_origin_check`]
//! like every other POST on these routes — no separate token, no exemption.
//!
//! # Production safety
//!
//! This is guarded by two independent gates, either of which is sufficient:
//! 1. **Compile-time:** the whole module — handler and route — is behind
//!    `#[cfg(debug_assertions)]`, so `dx build --release` (which turns debug
//!    assertions off) omits it from the production binary entirely.
//! 2. **Runtime:** even in a debug build the handler stays inert unless
//!    `DEV_LOGIN=true` is set in the environment.

use axum::Extension;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::response::{IntoResponse, Redirect, Response};

use super::{AuthUserInfo, lookup_or_create_user};
use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::session::{LoggedInData, login};
use crate::state::AuthState;

/// Fixed identity the dev login signs in as.
const DEV_SUB: &str = "dev-mode-user";
const DEV_EMAIL: &str = "dev@localhost";
const DEV_USERNAME: &str = "dev";

/// Body of the login page's dev-login form.
#[derive(serde::Deserialize)]
pub struct DevLoginForm {
    /// Where to continue after signing in. Honoured only if relative.
    #[serde(default)]
    redirect_url: Option<String>,
}

/// `POST /auth/dev-login` — sign in as the local dev user, bypassing FerrisKey.
///
/// Only present in debug builds, and only active when `DEV_LOGIN=true`.
pub async fn dev_login_handler(
    Extension(auth_config): Extension<AuthConfig>,
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
    // A rejection (no body at all, as a bare `curl -X POST` sends) is not an
    // error here — it just means no redirect was asked for.
    form: Result<Form<DevLoginForm>, FormRejection>,
) -> AuthResult<Response> {
    if std::env::var("DEV_LOGIN").as_deref() != Ok("true") {
        return Err(AuthError::Unauthorized("Dev login is disabled".to_string()));
    }

    let info = AuthUserInfo {
        sub: DEV_SUB.to_string(),
        nickname: None,
        name: Some("Dev User".to_string()),
        email: DEV_EMAIL.to_string(),
        email_verified: true,
        picture: None,
        preferred_username: Some(DEV_USERNAME.to_string()),
    };

    let user = lookup_or_create_user(&auth_state, &info).await?;

    // Rotate the session id to avoid fixation, matching the real login flow.
    session.cycle_id().await?;

    let data = LoggedInData {
        id: user.id,
        sub: user.sub,
        email: user.email,
        username: DEV_USERNAME.to_string(),
        avatar_url: None,
        id_token: "dev_mode_token".to_string(),
    };
    login(&session, &data).await?;

    let redirect = form
        .ok()
        .and_then(|Form(body)| body.redirect_url)
        .filter(|url| super::shared::is_safe_redirect_url(url))
        .unwrap_or_else(|| auth_config.default_post_login_url.clone());

    tracing::warn!("Dev login used — signed in as {DEV_EMAIL}");

    Ok(Redirect::to(&redirect).into_response())
}
