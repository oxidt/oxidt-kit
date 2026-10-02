//! Topcoat integration: read the login state from a Topcoat page or route.
//!
//! Topcoat serves the auth router as a tower service. Wrap the whole Topcoat
//! router in your `SessionManagerLayer`, so pages and the auth handlers share
//! one session:
//!
//! ```rust,ignore
//! use topcoat::router::{Router, tower::{TowerLayer, TowerRoute}};
//!
//! let router = Router::builder()
//!     .route(TowerRoute::any("/auth/{*rest}", auth_router(config, state)))
//!     .layer(TowerLayer::new(session_manager_layer))
//!     .build();
//! ```
//!
//! Then, in a page:
//!
//! ```rust,ignore
//! let user = oxidt_auth::topcoat::user_session(cx).await?.data()?;
//! ```

use ::topcoat::{context::Cx, router::request::extensions};

use crate::error::AuthError;
use crate::session::UserSession;

/// The [`UserSession`] of the current request.
///
/// Fails with [`AuthError::AuthSessionLayerNotFound`] when no
/// `SessionManagerLayer` wraps the router.
pub async fn user_session(cx: &Cx) -> Result<UserSession, AuthError> {
    let session = extensions(cx).get::<tower_sessions::Session>().ok_or(
        AuthError::AuthSessionLayerNotFound("Auth Session Layer not found".to_string()),
    )?;

    UserSession::from_session(session).await
}

#[cfg(feature = "local-login")]
mod login_page;

#[cfg(feature = "local-login")]
pub use login_page::local_login_page;
