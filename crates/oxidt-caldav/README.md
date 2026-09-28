# oxidt-caldav

CalDAV/WebDAV for apps that write a user's own calendar: discovery, a
create-only or overwrite `PUT`, a WebDAV folder check, and VTODO/VEVENT bodies.
Every request goes through [`oxidt-egress`](../oxidt-egress).

```toml
[dependencies]
oxidt-caldav = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-caldav-v0.1.0" }
```

## Why

**Writing to the user's own calendar needs no paperwork.** Microsoft Graph and
Google Calendar both want a registered OAuth app: an Azure tenant, or a Google
Cloud project plus verification for a sensitive scope. CalDAV only needs an
app password and a URL. That covers iCloud, Fastmail, Nextcloud and Radicale.

**Discovery is a chain.** RFC 4791 finds calendars through `PROPFIND`s:
`current-user-principal`, then `calendar-home-set`, then the collections in the
home. Each step returns an href that can point at another host (iCloud does
this). So every URL in the chain is checked and pinned on its own. A bare
Nextcloud host is tried again under `/remote.php/dav/`.

The alternative is to skip discovery and have the user paste one collection
URL. That takes one paste, avoids three round trips, and removes the guess
about which calendar they meant. `put_ics` works either way.

**Why `If-None-Match: *`.** We choose the resource name
(`{collection}/{uid}.ics`), so a write is a single `PUT` with no
server-assigned id to read back. With `PutMode::CreateOnly`, a retried export
finds the entry already there. The server answers 412, which comes back as
`PutOutcome::AlreadyExists`, not as an error and not as a duplicate.

**Why overwrite in place is also a mode.** Sometimes the uid is derived from
what the entry *stands for*, such as a time slot, rather than from a row id.
Then re-planning should replace the entry, not leave it alone.
`PutMode::Overwrite` sends no precondition, so writing again updates the entry
instead of adding a copy.

**No redirects, public https only.** The account URL is user input. A `PUT`
that followed a redirect would write to a URL the user never saw.

## API

```rust
pub struct Account { pub base: Url, pub username: String, pub password: SecretString }
pub struct Calendar { pub href: Url, pub name: String, pub components: Vec<Component> }
pub enum Component { Event, Todo }
pub enum PutMode { Overwrite, CreateOnly }
pub enum PutOutcome { Created, Updated, AlreadyExists }

pub async fn discover(account: &Account) -> Result<Vec<Calendar>, Error>;
pub async fn put_ics(account: &Account, collection: &Url, uid: &str, body: &str, mode: PutMode)
    -> Result<PutOutcome, Error>;
pub fn resource_url(collection: &Url, uid: &str) -> Result<Url, Error>;
pub async fn validate_folder(account: &Account, url: &str) -> Result<Url, Error>;

pub mod ics {
    pub enum When { Date(NaiveDate), Time(DateTime<Utc>) }
    pub fn todo(uid, summary, description, due: Option<When>, priority: Option<u32>,
                stamped: DateTime<Utc>) -> String;
    pub fn event(uid, summary, description, start: When, end: Option<When>,
                 location: Option<&str>, stamped: DateTime<Utc>) -> String;
}
```

`Error` keeps the status: `Unauthorized` (401), `NotFound` (404, or no calendar
home), `PreconditionFailed` (412 under `Overwrite`), `NotACollection`,
`Status { code, title }` for everything else, plus `Transport`,
`Egress(oxidt_egress::Error)`, `Xml` and `Url`. It has no user-facing copy.
The app writes its own; a 403 or 409 on `PUT` usually means the URL is a
calendar home, not a single calendar.

`resource_url` accepts the collection with or without a trailing slash. People
paste both, and a doubled slash names a different resource.

`ics::event` without an `end` makes an all-day event last one day and a timed
event last one hour. `stamped` becomes `DTSTAMP`. It is a parameter, not read
from the clock, so the body depends only on its inputs. A zone-less local time
has no `When` variant: convert it to UTC in the zone you know it was written in.

## Two shapes

**Export once, never duplicate.** The user picks a calendar from discovery.
Each note is exported under its own id.

```rust
use oxidt_caldav::{Account, Component, PutMode, PutOutcome, discover, ics, put_ics};

let calendars = discover(&account).await?;
let tasks = calendars.iter().find(|c| c.components.contains(&Component::Todo)).unwrap();
let body = ics::todo(&note.id, &title, &note.text, due, Some(1), Utc::now());
match put_ics(&account, &tasks.href, &note.id, &body, PutMode::CreateOnly).await? {
    PutOutcome::Created | PutOutcome::Updated => {}
    PutOutcome::AlreadyExists => {} // an earlier attempt landed
}
```

**Holds that follow the plan.** The user pastes one collection URL, and the uid
comes from the slot. Re-planning a day overwrites its own holds. A partial
failure should still report what landed.

```rust
for hold in holds {
    let uid = hold.slot_uid();
    let body = my_vevent(hold, stamped, &uid); // the app's own builder is fine
    match put_ics(&account, &collection, &uid, &body, PutMode::Overwrite).await {
        Ok(_) => written.push(uid),
        Err(e) => failures.push(explain(&e)),
    }
}
```

## Tests

No network. The `PUT` tests run against a one-shot HTTP server on a raw
`TcpListener`. They reach it through an internal function that takes a
prebuilt client, because the public API always goes through the egress guard,
and the guard refuses loopback by design.

## License

MIT — see [LICENSE](../../LICENSE).
