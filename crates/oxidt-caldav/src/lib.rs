//! CalDAV/WebDAV for apps that write a user's own calendar.
//!
//! The provider that needs no paperwork. Microsoft Graph and Google Calendar
//! both want an OAuth app registered — an Azure tenant, or a Google Cloud
//! project plus verification for a sensitive scope. CalDAV wants an app
//! password and a URL, and works against iCloud, Fastmail, Nextcloud and
//! Radicale alike.
//!
//! - [`discover`] walks the RFC 4791 `PROPFIND` chain —
//!   `current-user-principal`, then `calendar-home-set`, then the collections
//!   in it — and reports which components (VEVENT, VTODO) each one takes.
//! - [`put_ics`] writes one calendar object to `{collection}/{uid}.ics`. We
//!   choose the resource name, so a write is a single `PUT` with no
//!   server-assigned id to read back. [`PutMode::CreateOnly`] sends
//!   `If-None-Match: *`, so a retried export finds the entry already there
//!   (412, reported as [`PutOutcome::AlreadyExists`]) instead of writing a
//!   duplicate. [`PutMode::Overwrite`] replaces in place: when the uid is
//!   derived from what the entry *stands for* (a time slot, say), rewriting it
//!   updates the entry rather than stacking a copy beside it.
//! - [`validate_folder`] checks that a URL is a WebDAV collection, for apps
//!   that also drop plain files next to the calendar.
//! - [`ics`] builds VTODO and VEVENT bodies.
//!
//! ## Every request goes through oxidt-egress
//!
//! The account URL is user input, and discovery follows hrefs the server
//! sends back — which may point at another host. Each request is therefore
//! checked on its own: public https only ([`oxidt_egress::check_url`]), every
//! resolved address checked, the connection pinned to those addresses, no
//! proxy, and no redirects. A `PUT` that followed a redirect would be a write
//! to a URL the user never saw.

mod dav;
mod error;
pub mod ics;

pub use dav::{discover, put_ics, resource_url, validate_folder};
pub use error::Error;

use secrecy::SecretString;
use url::Url;

/// A user's CalDAV account.
#[derive(Debug, Clone)]
pub struct Account {
    /// Where discovery starts: the server root, the DAV root or the principal.
    /// A bare Nextcloud host is tried again under `/remote.php/dav/`.
    pub base: Url,
    pub username: String,
    /// An app-specific password. iCloud and Fastmail both require one; the real
    /// account password won't authenticate against their DAV endpoints.
    pub password: SecretString,
}

/// A calendar collection found by [`discover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calendar {
    pub href: Url,
    /// The display name, or the last path segment when the server has none.
    pub name: String,
    /// What the collection accepts. A server that doesn't report
    /// `supported-calendar-component-set` is taken to accept both.
    pub components: Vec<Component>,
}

/// A calendar component type a collection accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// `VEVENT`
    Event,
    /// `VTODO`
    Todo,
}

/// How [`put_ics`] treats an existing resource of the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutMode {
    /// Replace it in place.
    Overwrite,
    /// Leave it alone (`If-None-Match: *`).
    CreateOnly,
}

/// What [`put_ics`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// `201`: the resource is new.
    Created,
    /// `200` / `204`: an existing resource was replaced.
    Updated,
    /// `412` under [`PutMode::CreateOnly`]: it was already there, untouched.
    AlreadyExists,
}
