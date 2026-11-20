//! Logout handler.

use axum::Extension;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::AuthConfig;
use crate::error::AuthResult;
use crate::ferriskey;
use crate::session::LoggedInData;
use crate::session::login::LOGGED_IN_USER_SESSION_KEY;
use crate::state::AuthState;

/// Handler to run when the user wants to logout.
///
/// Behaviour depends on how the user logged in (encoded in `id_token`):
/// - `"dev_mode_token"` → redirect to `AuthConfig.dev_login_url`
/// - otherwise, with a generic OIDC issuer ([`crate::JwksCache::oidc`]) →
///   redirect through its `end_session_endpoint`, back to `login_page_url`
/// - otherwise, with `sso_enabled` → redirect through FerrisKey's end-session
///   endpoint, which clears its cookies and returns to `login_page_url`
/// - otherwise → redirect to `AuthConfig.login_page_url`
pub async fn logout(
    Extension(auth_config): Extension<AuthConfig>,
    auth_state: Option<Extension<AuthState>>,
    session: tower_sessions::Session,
) -> AuthResult<Response> {
    // Read login data before flushing the entire session
    let login_data = session
        .get::<LoggedInData>(LOGGED_IN_USER_SESSION_KEY)
        .await?;

    // Flush the session: removes all data AND deletes it from the session store.
    // This is stronger than remove() which only deletes one key but leaves
    // the session ID valid in the store.
    session.flush().await?;

    let oidc = auth_state.filter(|Extension(state)| state.jwks_cache.is_oidc());

    if let Some(login_data) = login_data {
        if login_data.id_token == "dev_mode_token" {
            Ok(Redirect::to(&auth_config.dev_login_url).into_response())
        } else if let Some(Extension(state)) = oidc {
            let back = format!(
                "{}{}",
                auth_config.base_url.trim_end_matches('/'),
                auth_config.login_page_url
            );
            // The local session is already gone; if the issuer cannot be
            // reached or has no end-session endpoint, its session outlives it.
            let end_session = match state.jwks_cache.oidc_endpoints().await {
                Ok(endpoints) => endpoints.and_then(|e| e.end_session_endpoint.as_deref()),
                Err(e) => {
                    tracing::warn!("OIDC discovery failed at logout: {e}");
                    None
                }
            };
            let url = match end_session {
                Some(endpoint) => {
                    ferriskey::logout_url_at(endpoint, state.jwks_cache.client_id(), &back)?
                }
                None => auth_config.login_page_url.clone(),
            };
            Ok(Redirect::to(&url).into_response())
        } else if auth_config.sso_enabled {
            // End the FerrisKey session as well, or the next `/auth/sso/start`
            // — here or in any other app of the realm — logs straight back in.
            // Only a top-level POST (a form submit) gets FerrisKey's cookies
            // cleared: a `fetch` follows the redirect without credentials.
            let back = format!(
                "{}{}",
                auth_config.base_url.trim_end_matches('/'),
                auth_config.login_page_url
            );
            let url = ferriskey::logout_url(
                &auth_config.ferriskey_url,
                &auth_config.ferriskey_realm,
                &auth_config.ferriskey_client_id,
                &back,
            )?;
            Ok(Redirect::to(&url).into_response())
        } else {
            Ok(Redirect::to(&auth_config.login_page_url).into_response())
        }
    } else {
        Ok(Redirect::to("/").into_response())
    }
}
