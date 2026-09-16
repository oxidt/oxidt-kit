# oxidt-billing

Provider-neutral billing state and default plan entitlements. No database, HTTP client, async runtime, or Dioxus dependency.

- `Subscription`: provider, customer/subscription IDs, status, tier, billing-period end, update revision.
- `Subscription::grants_access()`: only known paid plans with active/trialing status.
- `seat_limit()`: free 1, Pro 5, Business 25, Enterprise unlimited.

Modify this small catalog for your product. Grace periods are an explicit application decision; past-due/unpaid/unknown statuses are denied by default. Period-end timestamps are display data: renewal/cancellation state comes from provider webhooks and reconciliation.

The application must authenticate webhooks, choose plan IDs on the server, verify tenant permissions, and persist changes transactionally. See `templates/teams/src/server/billing_provider.rs`.

License: MIT (see `../../LICENSE`).
