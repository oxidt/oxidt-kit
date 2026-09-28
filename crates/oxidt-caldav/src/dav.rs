use std::time::Duration;

use oxidt_egress::{Timeouts, UrlPolicy, check_url, guard_host_async, pinned_client};
use reqwest::{Method, StatusCode};
use secrecy::ExposeSecret;
use url::Url;

use crate::{Account, Calendar, Component, Error, PutMode, PutOutcome};

const TIMEOUTS: Timeouts = Timeouts {
    connect: Duration::from_secs(10),
    total: Duration::from_secs(20),
};
const DAV: &str = "DAV:";
const CALDAV: &str = "urn:ietf:params:xml:ns:caldav";

const PRINCIPAL: &str =
    r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"#;
const HOME: &str = r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>"#;
const RESOURCETYPE: &str =
    r#"<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;
const LIST: &str = r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:displayname/><d:resourcetype/><c:supported-calendar-component-set/></d:prop></d:propfind>"#;

/// Find the account's calendars: principal → calendar home → its collections.
pub async fn discover(account: &Account) -> Result<Vec<Calendar>, Error> {
    let mut base = check_url(account.base.as_str(), &UrlPolicy::default())?;
    let (mut status, mut body) = propfind(account, &base, "0", PRINCIPAL).await?;
    // A bare Nextcloud host serves DAV under /remote.php/dav/.
    if matches!(status.as_u16(), 404 | 405) && base.path() == "/" {
        base = base.join("/remote.php/dav/").map_err(|_| Error::Url)?;
        (status, body) = propfind(account, &base, "0", PRINCIPAL).await?;
    }
    let principal = match multistatus(status, &body)?
        .into_iter()
        .find_map(|r| r.principal)
    {
        Some(href) => resolve(&base, &href)?,
        None => base,
    };
    let (status, body) = propfind(account, &principal, "0", HOME).await?;
    let home = multistatus(status, &body)?
        .into_iter()
        .find_map(|r| r.home)
        .ok_or(Error::NotFound)?;
    let home = resolve(&principal, &home)?;
    let (status, body) = propfind(account, &home, "1", LIST).await?;
    multistatus(status, &body)?
        .into_iter()
        .filter(|r| r.calendar)
        .map(|r| {
            let href = resolve(&home, &r.href)?;
            let name = r.name.filter(|n| !n.is_empty()).unwrap_or_else(|| {
                href.as_str()
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            });
            let components = match r.components {
                None => vec![Component::Event, Component::Todo],
                Some(names) => names
                    .iter()
                    .filter_map(|name| match name.as_str() {
                        "VEVENT" => Some(Component::Event),
                        "VTODO" => Some(Component::Todo),
                        _ => None,
                    })
                    .collect(),
            };
            Ok(Calendar {
                href,
                name,
                components,
            })
        })
        .collect()
}

/// Write `body` to `{collection}/{uid}.ics`.
///
/// Under [`PutMode::CreateOnly`] a `412` means the resource already exists and
/// is reported as [`PutOutcome::AlreadyExists`]; under
/// [`PutMode::Overwrite`] it is [`Error::PreconditionFailed`].
pub async fn put_ics(
    account: &Account,
    collection: &Url,
    uid: &str,
    body: &str,
    mode: PutMode,
) -> Result<PutOutcome, Error> {
    let url = check_url(
        resource_url(collection, uid)?.as_str(),
        &UrlPolicy::default(),
    )?;
    let client = client_for(&url).await?;
    put_with(&client, account, url, body, mode).await
}

/// `{collection}/{uid}.ics`, tolerating a collection URL with or without its
/// trailing slash — people paste both, and a doubled slash names a different
/// resource.
pub fn resource_url(collection: &Url, uid: &str) -> Result<Url, Error> {
    let trimmed = collection.as_str().trim_end_matches('/');
    Url::parse(&format!("{trimmed}/{uid}.ics")).map_err(|_| Error::Url)
}

/// Check that `url` is a WebDAV collection the account can reach — a folder to
/// write files into. Returns it with a trailing slash.
pub async fn validate_folder(account: &Account, url: &str) -> Result<Url, Error> {
    let url = if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    };
    let url = check_url(&url, &UrlPolicy::default())?;
    let (status, body) = propfind(account, &url, "0", RESOURCETYPE).await?;
    let folder = multistatus(status, &body)?.into_iter().next();
    if !folder.is_some_and(|r| r.collection) {
        return Err(Error::NotACollection);
    }
    Ok(url)
}

/// A client for `url`'s host alone, pinned to its checked addresses. Built per
/// request, since discovery can hop hosts.
async fn client_for(url: &Url) -> Result<reqwest::Client, Error> {
    let pinned = tokio::time::timeout(TIMEOUTS.connect, guard_host_async(url))
        .await
        .map_err(|_| oxidt_egress::Error::Resolve(url.host_str().unwrap_or_default().into()))??;
    Ok(pinned_client(&pinned, TIMEOUTS)?)
}

async fn put_with(
    client: &reqwest::Client,
    account: &Account,
    url: Url,
    body: &str,
    mode: PutMode,
) -> Result<PutOutcome, Error> {
    let mut headers = vec![("Content-Type", "text/calendar; charset=utf-8")];
    if mode == PutMode::CreateOnly {
        headers.push(("If-None-Match", "*"));
    }
    let (status, _) = send(client, account, Method::PUT, url, &headers, body.into()).await?;
    match status.as_u16() {
        201 => Ok(PutOutcome::Created),
        200 | 204 => Ok(PutOutcome::Updated),
        412 if mode == PutMode::CreateOnly => Ok(PutOutcome::AlreadyExists),
        _ => Err(failure(status)),
    }
}

async fn propfind(
    account: &Account,
    url: &Url,
    depth: &str,
    body: &str,
) -> Result<(StatusCode, String), Error> {
    let client = client_for(url).await?;
    let method = Method::from_bytes(b"PROPFIND").expect("valid method");
    let headers = [("Depth", depth), ("Content-Type", "application/xml")];
    send(&client, account, method, url.clone(), &headers, body.into()).await
}

/// One request with basic auth; returns the status and body.
async fn send(
    client: &reqwest::Client,
    account: &Account,
    method: Method,
    url: Url,
    headers: &[(&str, &str)],
    body: String,
) -> Result<(StatusCode, String), Error> {
    let mut request = client
        .request(method.clone(), url.clone())
        .basic_auth(&account.username, Some(account.password.expose_secret()))
        .body(body);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.map_err(Error::Transport)?;
    let status = response.status();
    tracing::debug!(%method, host = url.host_str(), status = status.as_u16(), "caldav");
    let text = response.text().await.map_err(Error::Transport)?;
    Ok((status, text))
}

fn failure(status: StatusCode) -> Error {
    match status.as_u16() {
        401 => Error::Unauthorized,
        404 => Error::NotFound,
        412 => Error::PreconditionFailed,
        code => Error::Status {
            code,
            title: status.canonical_reason().unwrap_or_default().to_string(),
        },
    }
}

fn multistatus(status: StatusCode, body: &str) -> Result<Vec<Resource>, Error> {
    match status.as_u16() {
        207 => parse_multistatus(body).ok_or(Error::Xml),
        _ => Err(failure(status)),
    }
}

/// Resolve a server-sent href against the URL it came from, under the same
/// public-https policy as the user's own URL.
fn resolve(base: &Url, href: &str) -> Result<Url, Error> {
    let url = base.join(href).map_err(|_| Error::Url)?;
    Ok(check_url(url.as_str(), &UrlPolicy::default())?)
}

/// The properties of one `<d:response>` this crate cares about.
#[derive(Debug, Default, PartialEq)]
struct Resource {
    href: String,
    name: Option<String>,
    principal: Option<String>,
    home: Option<String>,
    calendar: bool,
    collection: bool,
    /// `None` when the server didn't report the component set (→ both).
    components: Option<Vec<String>>,
}

fn is(node: &roxmltree::Node, ns: &str, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == name
}

fn href_below(node: roxmltree::Node) -> Option<String> {
    node.descendants()
        .find(|n| is(n, DAV, "href"))
        .and_then(|n| n.text())
        .map(|t| t.trim().to_string())
}

/// Parse a WebDAV multistatus, reading only properties from 200 propstats.
fn parse_multistatus(xml: &str) -> Option<Vec<Resource>> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let responses = doc.descendants().filter(|n| is(n, DAV, "response"));
    Some(
        responses
            .map(|response| {
                let mut r = Resource {
                    href: response
                        .children()
                        .find(|n| is(n, DAV, "href"))
                        .and_then(|n| n.text())
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                    ..Resource::default()
                };
                let found = response
                    .children()
                    .filter(|n| is(n, DAV, "propstat"))
                    .filter(|p| {
                        p.children()
                            .find(|n| is(n, DAV, "status"))
                            .and_then(|n| n.text())
                            .is_some_and(|s| s.contains(" 200 "))
                    })
                    .flat_map(|p| p.children().filter(|n| is(n, DAV, "prop")))
                    .flat_map(|p| p.children());
                for prop in found {
                    if is(&prop, DAV, "displayname") {
                        r.name = prop.text().map(|t| t.trim().to_string());
                    } else if is(&prop, DAV, "current-user-principal") {
                        r.principal = href_below(prop);
                    } else if is(&prop, CALDAV, "calendar-home-set") {
                        r.home = href_below(prop);
                    } else if is(&prop, DAV, "resourcetype") {
                        r.calendar = prop.children().any(|n| is(&n, CALDAV, "calendar"));
                        r.collection = prop.children().any(|n| is(&n, DAV, "collection"));
                    } else if is(&prop, CALDAV, "supported-calendar-component-set") {
                        r.components = Some(
                            prop.children()
                                .filter(|n| is(n, CALDAV, "comp"))
                                .filter_map(|n| n.attribute("name"))
                                .map(str::to_uppercase)
                                .collect(),
                        );
                    }
                }
                r
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn parses_a_nextcloud_calendar_home() {
        let xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:oc="http://owncloud.org/ns">
 <d:response>
  <d:href>/remote.php/dav/calendars/anna/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  <d:propstat><d:prop><d:displayname/><cal:supported-calendar-component-set/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
 </d:response>
 <d:response>
  <d:href>/remote.php/dav/calendars/anna/personal/</d:href>
  <d:propstat><d:prop>
   <d:displayname>Personal</d:displayname>
   <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
   <cal:supported-calendar-component-set><cal:comp name="VEVENT"/><cal:comp name="VTODO"/></cal:supported-calendar-component-set>
  </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
 </d:response>
 <d:response>
  <d:href>/remote.php/dav/calendars/anna/tasks/</d:href>
  <d:propstat><d:prop>
   <d:displayname>Tasks</d:displayname>
   <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
   <cal:supported-calendar-component-set><cal:comp name="VTODO"/></cal:supported-calendar-component-set>
  </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
 </d:response>
 <d:response>
  <d:href>/remote.php/dav/calendars/anna/inbox/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/><cal:schedule-inbox/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
 </d:response>
</d:multistatus>"#;
        let found = parse_multistatus(xml).unwrap();
        let calendars: Vec<_> = found.iter().filter(|r| r.calendar).collect();
        assert_eq!(found.len(), 4);
        assert_eq!(calendars.len(), 2);
        assert_eq!(calendars[0].name.as_deref(), Some("Personal"));
        assert_eq!(calendars[1].href, "/remote.php/dav/calendars/anna/tasks/");
        assert_eq!(calendars[1].components, Some(vec!["VTODO".to_string()]));
        // A 404 propstat reports nothing, so the home's component set is unknown.
        assert_eq!(found[0].components, None);
        assert!(found[0].collection && !found[0].calendar);

        let principal = parse_multistatus(
            r#"<multistatus xmlns="DAV:"><response><href>/remote.php/dav/</href><propstat><prop><current-user-principal><href>/remote.php/dav/principals/users/anna/</href></current-user-principal></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"#,
        )
        .unwrap();
        assert_eq!(
            principal[0].principal.as_deref(),
            Some("/remote.php/dav/principals/users/anna/")
        );
    }

    #[test]
    fn an_unreadable_multistatus_is_an_xml_error_and_a_401_is_unauthorized() {
        assert!(matches!(
            multistatus(StatusCode::MULTI_STATUS, "<not xml"),
            Err(Error::Xml)
        ));
        assert!(matches!(
            multistatus(StatusCode::UNAUTHORIZED, ""),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            multistatus(StatusCode::FORBIDDEN, ""),
            Err(Error::Status { code: 403, .. })
        ));
    }

    #[test]
    fn server_hrefs_resolve_against_their_origin_under_the_egress_policy() {
        let home = Url::parse("https://dav.example.com/calendars/anna/").unwrap();
        assert_eq!(
            resolve(&home, "/calendars/anna/work/").unwrap().as_str(),
            "https://dav.example.com/calendars/anna/work/"
        );
        assert_eq!(
            resolve(&home, "https://p01-caldav.icloud.com/1/calendars/")
                .unwrap()
                .host_str(),
            Some("p01-caldav.icloud.com")
        );
        // A server may not bounce discovery onto plain http.
        assert!(matches!(
            resolve(&home, "http://dav.example.com/calendars/"),
            Err(Error::Egress(oxidt_egress::Error::Scheme))
        ));
    }

    #[test]
    fn a_collection_url_yields_the_same_resource_with_or_without_a_slash() {
        let with = Url::parse("https://caldav.fastmail.com/dav/calendars/u/1/work/").unwrap();
        let without = Url::parse("https://caldav.fastmail.com/dav/calendars/u/1/work").unwrap();
        assert_eq!(
            resource_url(&with, "dowat-2026-07-30-0900").unwrap(),
            resource_url(&without, "dowat-2026-07-30-0900").unwrap(),
            "people paste both, and a doubled slash is a different resource"
        );
        assert_eq!(
            resource_url(&with, "dowat-2026-07-30-0900")
                .unwrap()
                .as_str(),
            "https://caldav.fastmail.com/dav/calendars/u/1/work/dowat-2026-07-30-0900.ics",
            "the resource name is the uid, which is how the PUT stays idempotent"
        );
    }

    #[tokio::test]
    async fn a_collection_on_the_private_network_is_refused_before_any_request() {
        let collection = Url::parse("https://169.254.169.254/dav/").unwrap();
        let outcome = put_ics(&account(), &collection, "x", "", PutMode::Overwrite).await;
        assert!(matches!(
            outcome,
            Err(Error::Egress(oxidt_egress::Error::Forbidden(_)))
        ));
    }

    #[tokio::test]
    async fn plain_http_is_refused() {
        let collection = Url::parse("http://caldav.fastmail.com/dav/calendars/u/1/work/").unwrap();
        let outcome = put_ics(&account(), &collection, "x", "", PutMode::Overwrite).await;
        assert!(matches!(
            outcome,
            Err(Error::Egress(oxidt_egress::Error::Scheme))
        ));
    }

    fn account() -> Account {
        Account {
            base: Url::parse("https://dav.example.com/").unwrap(),
            username: "anna".into(),
            password: "app-password".into(),
        }
    }

    /// A one-shot HTTP server on loopback: answers the first request with
    /// `status` and hands back the request head it received. Reached through a
    /// plain client, since the egress guard refuses loopback by design.
    fn serve_once(status: &'static str) -> (Url, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/cal/", listener.local_addr().unwrap())).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            tx.send(head).unwrap();
        });
        (url, rx)
    }

    #[tokio::test]
    async fn create_only_reports_a_412_as_already_exists() {
        let (collection, request) = serve_once("412 Precondition Failed");
        let url = resource_url(&collection, "abc").unwrap();
        let outcome = put_with(
            &reqwest::Client::new(),
            &account(),
            url,
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            PutMode::CreateOnly,
        )
        .await
        .unwrap();
        assert_eq!(outcome, PutOutcome::AlreadyExists);

        let head = request.recv().unwrap().to_ascii_lowercase();
        assert!(head.starts_with("put /cal/abc.ics "), "{head}");
        assert!(head.contains("if-none-match: *"), "{head}");
        assert!(head.contains("authorization: basic "), "{head}");
    }

    #[tokio::test]
    async fn overwrite_sends_no_precondition_and_treats_a_412_as_an_error() {
        let (collection, request) = serve_once("412 Precondition Failed");
        let url = resource_url(&collection, "abc").unwrap();
        let outcome = put_with(
            &reqwest::Client::new(),
            &account(),
            url,
            "",
            PutMode::Overwrite,
        )
        .await;
        assert!(matches!(outcome, Err(Error::PreconditionFailed)));
        assert!(
            !request
                .recv()
                .unwrap()
                .to_ascii_lowercase()
                .contains("if-none-match")
        );
    }
}
