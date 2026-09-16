# oxidt-polar

Polar API client and signed webhook verification, adapted from oxidt-solo's `polar` crate. Includes customers, checkout sessions, subscriptions, and standard-webhook verification.

The template dependency is aliased as `polar` for existing call sites. Configure `PolarConfig` with your account token, application URL and product IDs. Consumers must implement entitlement changes, verified webhook routing, replay/idempotency handling, and private delivery for their own product. Possessing a checkout URL or receipt is not authorization to download source.

Source example and supported operations are documented in `src/lib.rs` and `src/client.rs`. The original MIT notice is preserved in `../../LICENSE`.
