//! The OAuth 2.1 authorization-server core an app needs to let claude.ai /
//! ChatGPT connect to its MCP endpoint: discovery metadata, dynamic client
//! registration, PKCE authorization code, and the validation rules — without
//! owning your storage, sessions or consent page.
//!
//! Extracted from two apps with the same flow and different plumbing:
//!
//! - **dowat** — OAuth authorization-code + S256 PKCE. Account tokens only
//!   authorize consent; opaque, separately scoped MCP tokens never
//!   authenticate app API requests. Refresh tokens rotate, and reuse revokes
//!   the family.
//! - **smiet** — a minimal self-hosted authorization server for the MCP
//!   connector. It owns the consent flow (reusing the app's login session) and
//!   issues opaque `oat_` tokens that the existing API-key path validates — so
//!   MCP clients ride the same auth as the CLI.
//!
//! Endpoints an app wires, and the function each calls:
//!
//! - `GET  /.well-known/oauth-protected-resource[/mcp]` — [`metadata::protected_resource`] (RFC 9728)
//! - `GET  /.well-known/oauth-authorization-server`     — [`metadata::authorization_server`] (RFC 8414)
//! - `POST /oauth/register`                             — [`register::validate`], [`register::response`] (RFC 7591)
//! - `GET  /oauth/authorize`                            — [`authorize::validate`], [`authorize::redirect_url`]
//! - `POST /oauth/token`                                — [`token::parse`], [`token::verify_code_exchange`]
//! - the MCP endpoint's 401                             — [`challenge::www_authenticate`]
//!
//! No clock is read inside the crate: expiry checks take `now` (Unix seconds).

mod allowlist;
pub mod authorize;
pub mod challenge;
mod error;
pub mod metadata;
pub mod register;
mod scope;
pub mod token;

pub use allowlist::{Allowlist, LoopbackHttp};
pub use error::OAuthError;
pub use scope::{ScopeError, Scopes};
pub use url::Url;
