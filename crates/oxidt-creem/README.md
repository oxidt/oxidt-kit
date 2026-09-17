# oxidt-creem

A small server-side Creem client for hosted Checkout and its retrieval, customer portal links, subscription retrieval, plan upgrades, seat changes and cancellation, a customer's subscription list, raw-body webhook verification, and the signed return URL. It has no database, Axum, Dioxus, or application plan dependency.

```rust,ignore
let client = oxidt_creem::Client::new(api_key.into(), test_mode)?;
let session = client.checkout(oxidt_creem::Checkout { product_id: "prod_…", ..Default::default() }).await?;
```

`Checkout` takes a trusted server product ID plus optional `request_id`, `success_url`, customer ID or email, `units`, `discount_code` and metadata; unset fields are omitted from the body rather than sent as null. Creem accepts only one of customer ID and email, so the ID wins when both are set. `checkout_session` retrieves a session by ID — the pull counterpart to the `checkout.completed` event.

Creem treats a plan change and a seat change as separate operations, so they are two calls: `upgrade_subscription` moves to a different product, and `update_subscription` sets `units` on one subscription item (the `sitem_…` ID from `Subscription::items`, not the subscription ID). Both take an `UpdateBehavior` controlling proration, whose Creem-side default differs between them. `customer_subscriptions` returns the first page only — Creem pages at 10, which is past what a subscription SaaS puts on one account; page through it yourself if you need more. `verify_webhook` checks the exact bytes against the hex `creem-signature` HMAC-SHA256 before JSON parsing, in constant time. Creem signs no timestamp, so the app must store event IDs itself to reject replays. `verify_return_url` takes the raw success-URL query and re-derives Creem's digest — non-empty parameters in URL order as `key=value`, then `salt=<api key>`, joined with `|` and SHA-256 hex — comparing in constant time. It proves the redirect came from Creem, not that the payment settled. Secrets and provider response bodies are omitted from errors/debug output.

The pooled HTTP client has a 20-second timeout and follows no redirects. `Client::new(key, test_mode)` picks `test-api.creem.io` or `api.creem.io`; the two environments share no data and their keys are not interchangeable. Unknown event types deserialize to `EventType::Other` instead of failing the delivery, and `product`/`customer` parse whether Creem expands them or returns a bare ID. `period_end_ms` converts Creem's RFC 3339 `current_period_end_date`, so an app can build an `oxidt_billing::Subscription` from it.

The application owns permissions, customer-to-tenant binding, idempotency, concurrency, and fulfillment — including retrieving current state on webhook receipt rather than trusting event arrival order.

References: [API introduction](https://docs.creem.io/api-reference/introduction), [Checkout API](https://docs.creem.io/features/checkout/checkout-api), [webhooks](https://docs.creem.io/code/webhooks), [customer portal](https://docs.creem.io/features/customer-portal).

Run `cargo test -p oxidt-creem`; tests use mock HTTP servers and require no Creem account. A live payment still requires your test-mode store and product configuration.

License: MIT (see `../../LICENSE`).
