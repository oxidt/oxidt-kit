//! SEP-2127 discovery documents for an MCP endpoint: the Server Card that
//! names a server and where it answers, and the AI Catalog that lets a client
//! find that card from nothing but the domain.
//!
//! Endpoints an app wires, and the function each calls:
//!
//! - `GET /.well-known/ai-catalog.json` — [`ai_catalog`], with [`CATALOG_MEDIA_TYPE`]
//! - `GET /mcp/server-card`             — [`server_card`], with [`CARD_MEDIA_TYPE`]
//!
//! Both with [`HEADERS`]. The card's location is `<endpoint>/server-card`,
//! the one the spec reserves, so a client that knows the endpoint finds it
//! without the catalog. The catalog embeds the card inline as well: one
//! document fewer to keep in step, and nothing for a client to fetch twice.
//!
//! A card carries no tools, resources or prompts — the spec leaves those to
//! the live `*/list` calls — so everything here is identity and transport.
//! Take `version` from the same constant the MCP server reports in its
//! `serverInfo`: a card that disagrees with the handshake is the one thing a
//! client checking it will flag.
//!
//! No axum, no clock, no I/O: documents in, `serde_json::Value` out.

use serde_json::{Value, json};

/// `Content-Type` for a Server Card.
pub const CARD_MEDIA_TYPE: &str = "application/mcp-server-card+json";

/// `Content-Type` for an AI Catalog.
pub const CATALOG_MEDIA_TYPE: &str = "application/ai-catalog+json";

/// The schema URL every v1 card must declare.
pub const CARD_SCHEMA: &str =
    "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json";

/// Response headers for both documents: wide-open CORS, which the spec
/// requires for browser clients and permits because both are public and
/// read-only, and an hour of caching, which it recommends.
pub const HEADERS: [(&str, &str); 5] = [
    ("access-control-allow-origin", "*"),
    ("access-control-allow-methods", "GET"),
    (
        "access-control-allow-headers",
        "Content-Type, If-None-Match",
    ),
    ("access-control-expose-headers", "ETag"),
    ("cache-control", "public, max-age=3600"),
];

/// What a card says about one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// Reverse-DNS with exactly one slash, `com.example/weather`.
    pub name: String,
    /// The version the server reports in `serverInfo.version`.
    pub version: String,
    /// What the server does, at most 100 characters.
    pub description: String,
    /// Display name, at most 100 characters.
    pub title: Option<String>,
    pub website_url: Option<String>,
    /// Public source repository, `("https://github.com/o/r", "github")`.
    pub repository: Option<(String, String)>,
    /// The absolute Streamable HTTP endpoint, `https://example.com/mcp`.
    pub endpoint: String,
    /// The protocol versions the endpoint negotiates, newest first. Empty
    /// leaves the field out, which claims nothing.
    pub protocol_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardError {
    #[error("name {0:?} is not reverse-DNS with exactly one slash (com.example/server)")]
    Name(String),
    #[error("{field} is {len} characters; the schema allows 1 to 100")]
    Length { field: &'static str, len: usize },
    #[error("endpoint {0:?} is not an absolute http(s) URL")]
    Endpoint(String),
    #[error("version is empty")]
    Version,
}

impl Card {
    /// The schema's constraints that are easy to break by hand. Call it in a
    /// test, so an over-long description fails the build rather than every
    /// client's validation.
    pub fn check(&self) -> Result<(), CardError> {
        let name_ok = self.name.len() >= 3
            && self.name.len() <= 200
            && self.name.split('/').count() == 2
            && self.name.split('/').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            })
            && !self
                .name
                .split('/')
                .next()
                .unwrap_or_default()
                .contains('_');
        if !name_ok {
            return Err(CardError::Name(self.name.clone()));
        }
        if self.version.is_empty() {
            return Err(CardError::Version);
        }
        let bounded = [
            ("description", Some(&self.description)),
            ("title", self.title.as_ref()),
        ];
        for (field, value) in bounded {
            if let Some(value) = value {
                let len = value.chars().count();
                if !(1..=100).contains(&len) {
                    return Err(CardError::Length { field, len });
                }
            }
        }
        let scheme_ok =
            self.endpoint.starts_with("https://") || self.endpoint.starts_with("http://");
        if !scheme_ok || self.endpoint.contains(char::is_whitespace) {
            return Err(CardError::Endpoint(self.endpoint.clone()));
        }
        Ok(())
    }

    /// Where [`server_card`] is served: `<endpoint>/server-card`.
    pub fn url(&self) -> String {
        format!("{}/server-card", self.endpoint.trim_end_matches('/'))
    }
}

/// The Server Card document.
pub fn server_card(card: &Card) -> Value {
    let mut remote = json!({ "type": "streamable-http", "url": card.endpoint });
    if !card.protocol_versions.is_empty() {
        remote["supportedProtocolVersions"] = json!(card.protocol_versions);
    }
    let mut doc = json!({
        "$schema": CARD_SCHEMA,
        "name": card.name,
        "version": card.version,
        "description": card.description,
        "remotes": [remote],
    });
    if let Some(title) = &card.title {
        doc["title"] = json!(title);
    }
    if let Some(url) = &card.website_url {
        doc["websiteUrl"] = json!(url);
    }
    if let Some((url, source)) = &card.repository {
        doc["repository"] = json!({ "url": url, "source": source });
    }
    doc
}

/// The AI Catalog for a domain, one entry per card, each embedded inline.
/// `domain` is the publisher in the entry identifiers, `example.com`.
pub fn ai_catalog(domain: &str, cards: &[Card]) -> Value {
    let entries: Vec<Value> = cards
        .iter()
        .map(|card| {
            json!({
                "identifier": identifier(domain, &card.name),
                "type": CARD_MEDIA_TYPE,
                "data": server_card(card),
            })
        })
        .collect();
    json!({ "specVersion": "1.0", "entries": entries })
}

/// `urn:air:{domain}:mcp:{server}` — the server half of the card's name.
pub fn identifier(domain: &str, name: &str) -> String {
    let server = name.rsplit('/').next().unwrap_or(name);
    format!("urn:air:{domain}:mcp:{server}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> Card {
        Card {
            name: "rs.thermite/thermite".into(),
            version: "1.4.0".into(),
            description: "Error tracking for Rust apps".into(),
            title: Some("Thermite".into()),
            website_url: Some("https://thermite.rs".into()),
            repository: None,
            endpoint: "https://thermite.rs/mcp".into(),
            protocol_versions: vec!["2025-06-18".into()],
        }
    }

    #[test]
    fn the_card_is_the_documented_shape() {
        assert_eq!(
            server_card(&card()),
            json!({
                "$schema": CARD_SCHEMA,
                "name": "rs.thermite/thermite",
                "version": "1.4.0",
                "description": "Error tracking for Rust apps",
                "title": "Thermite",
                "websiteUrl": "https://thermite.rs",
                "remotes": [{
                    "type": "streamable-http",
                    "url": "https://thermite.rs/mcp",
                    "supportedProtocolVersions": ["2025-06-18"],
                }],
            })
        );
        assert_eq!(card().url(), "https://thermite.rs/mcp/server-card");
    }

    #[test]
    fn no_protocol_versions_claims_nothing() {
        let doc = server_card(&Card {
            protocol_versions: Vec::new(),
            ..card()
        });
        assert!(doc["remotes"][0].get("supportedProtocolVersions").is_none());
    }

    #[test]
    fn the_catalog_embeds_each_card() {
        let doc = ai_catalog("thermite.rs", &[card()]);
        assert_eq!(doc["specVersion"], "1.0");
        let entry = &doc["entries"][0];
        assert_eq!(entry["identifier"], "urn:air:thermite.rs:mcp:thermite");
        assert_eq!(entry["type"], CARD_MEDIA_TYPE);
        assert_eq!(entry["data"], server_card(&card()));
    }

    #[test]
    fn check_catches_what_the_schema_rejects() {
        assert_eq!(card().check(), Ok(()));
        for name in ["thermite", "a/b/c", "rs.thermite/", "rs_x/y", "rs.x/sp ace"] {
            assert!(
                matches!(
                    Card {
                        name: name.into(),
                        ..card()
                    }
                    .check(),
                    Err(CardError::Name(_))
                ),
                "{name}"
            );
        }
        assert_eq!(
            Card {
                description: "x".repeat(101),
                ..card()
            }
            .check(),
            Err(CardError::Length {
                field: "description",
                len: 101
            })
        );
        assert_eq!(
            Card {
                endpoint: "/mcp".into(),
                ..card()
            }
            .check(),
            Err(CardError::Endpoint("/mcp".into()))
        );
    }
}
