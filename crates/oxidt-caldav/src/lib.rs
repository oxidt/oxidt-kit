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
//! - [`query`] reads a collection back: a `REPORT` for its VTODOs, or its
//!   VEVENTs in a time range, each with its href and ETag.
//! - [`put_object`] writes to a resource the server already named — one found
//!   by [`query`] — and returns the new ETag. [`PutMode::IfMatch`] makes the
//!   write fail with [`Error::PreconditionFailed`] when someone else changed
//!   the entry since it was read, instead of silently overwriting their edit.
//! - [`delete`] removes a resource, optionally under the same `If-Match`.
//! - [`validate_folder`] checks that a URL is a WebDAV collection, for apps
//!   that also drop plain files next to the calendar.
//! - [`ics`] builds VTODO and VEVENT bodies and reads them back.
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

pub use dav::{delete, discover, put_ics, put_object, query, resource_url, validate_folder};
pub use error::Error;

/// The egress crate this one is built on, so an app that also calls it
/// directly names one crate and one tag. Cargo treats each distinct git `tag`
/// as its own source: pinning `oxidt-egress` separately builds a second copy,
/// and [`Error::Egress`] then wraps a type the app's own `oxidt_egress` does
/// not recognise.
pub use oxidt_egress;

use chrono::{DateTime, Utc};
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
    /// The calendar's colour as `#RRGGBB`, when the server reports one
    /// (Apple's `calendar-color`, which Nextcloud and iCloud both set).
    pub color: Option<String>,
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

/// How a `PUT` treats an existing resource of the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutMode<'a> {
    /// Replace it in place.
    Overwrite,
    /// Leave it alone (`If-None-Match: *`).
    CreateOnly,
    /// Replace it only if it still carries this ETag (`If-Match`), exactly as
    /// the server sent it. A `412` is [`Error::PreconditionFailed`]: it changed
    /// since it was read.
    IfMatch(&'a str),
}

/// What a `PUT` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// `201`: the resource is new.
    Created,
    /// `200` / `204`: an existing resource was replaced.
    Updated,
    /// `412` under [`PutMode::CreateOnly`]: it was already there, untouched.
    AlreadyExists,
}

/// What [`put_object`] did, and the ETag the server gave the new version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub outcome: PutOutcome,
    /// Verbatim, quotes included. Servers may omit it (when they rewrite the
    /// body on store); [`query`] then reads it back.
    pub etag: Option<String>,
}

/// What [`query`] asks a collection for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// Every VTODO, done or not.
    Todos,
    /// VEVENTs overlapping `[start, end)`. Recurring events whose series
    /// overlaps are included once, as stored.
    Events {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
}

/// One calendar object found by [`query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Where it lives. Not always `{uid}.ics`: other clients name their own
    /// resources, so update and delete by this, never by a rebuilt name.
    pub href: Url,
    /// Verbatim, quotes included — hand it back to [`PutMode::IfMatch`] or
    /// [`delete`] as is.
    pub etag: Option<String>,
    /// The iCalendar text; read it with [`ics::todos`] or [`ics::events`].
    pub ics: String,
}
