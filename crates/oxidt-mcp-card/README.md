# oxidt-mcp-card

SEP-2127 discovery documents for an MCP endpoint: the Server Card and the AI
Catalog that lets a client find it from the domain alone.

```toml
[dependencies]
oxidt-mcp-card = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-mcp-card-v0.1.0" }
```

No axum, no I/O. Build a `Card`, serve two documents:

```rust
use oxidt_mcp_card::{ai_catalog, server_card, Card, CARD_MEDIA_TYPE, CATALOG_MEDIA_TYPE, HEADERS};

let card = Card {
    name: "rs.thermite/thermite".into(),
    version: env!("CARGO_PKG_VERSION").into(), // the same value as serverInfo.version
    description: "Error tracking for Rust apps".into(),
    title: Some("Thermite".into()),
    website_url: Some("https://thermite.rs".into()),
    repository: None,
    endpoint: "https://thermite.rs/mcp".into(),
    protocol_versions: vec!["2025-06-18".into()],
};

// GET /.well-known/ai-catalog.json  → ai_catalog("thermite.rs", &[card.clone()]), CATALOG_MEDIA_TYPE
// GET /mcp/server-card              → server_card(&card), CARD_MEDIA_TYPE
// both with every header in HEADERS
```

Put `card.check()` in a test: it catches what the schema rejects (name not
`namespace/server`, description over 100 characters) before a client does.

The card's `version` and `protocol_versions` are compared against the live
handshake by checking clients (mcpi does). Derive them from what the MCP server
actually reports, never a second hand-kept copy.
