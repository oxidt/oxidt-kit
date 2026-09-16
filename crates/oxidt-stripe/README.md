# oxidt-stripe

A small server-side Stripe client for hosted recurring Checkout, Billing Portal, subscription retrieval, and raw-body webhook verification. It has no database, Axum, Dioxus, or application plan dependency.

```rust,ignore
let client = oxidt_stripe::Client::new(secret.into(), "2025-03-31.basil")?;
let subscription = client.subscription("sub_...").await?;
```

`Checkout` accepts a trusted server price, organization reference, fixed return URLs, and a persisted idempotency key. Reference metadata is copied onto the subscription. `verify_event` checks the exact bytes and Stripe-Signature before JSON parsing, uses constant-time HMAC verification, supports rotated v1 signatures, and rejects timestamps more than five minutes away. Secrets and provider response bodies are omitted from errors/debug output.

The pooled HTTP client has a 20-second timeout and follows no redirects. API versions are explicit. Subscription parsing supports both legacy subscription-level and Basil item-level billing periods; the example app sells one recurring base price per subscription.

The application owns permissions, customer-to-tenant binding, retry receipts, concurrency, and fulfillment. The teams template demonstrates these responsibilities, including retrieving current state on webhook receipt rather than trusting event arrival order.

References: [Checkout](https://docs.stripe.com/api/checkout/sessions/create), [Portal](https://docs.stripe.com/api/customer_portal/sessions/create), [webhooks](https://docs.stripe.com/webhooks), [Basil billing periods](https://docs.stripe.com/changelog/basil/2025-03-31/deprecate-subscription-current-period-start-and-end).

Run `cargo test -p oxidt-stripe`; tests use mock HTTP servers and require no Stripe account. A live payment still requires your test-mode account and product configuration.

License: MIT (see `../../LICENSE`).
