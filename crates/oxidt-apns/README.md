# oxidt-apns

Apple push (APNs) with a `.p8` token key, for apps with an iPhone companion.

```rust
let Some(apns) = oxidt_apns::Apns::from_env("app.example.ios") else { return }; // push is off
match apns.wake(&device_token).await {            // silent: the app runs in the background
    oxidt_apns::Answer::Gone => { /* delete the token */ }
    oxidt_apns::Answer::Failed => { /* retry later */ }
    oxidt_apns::Answer::Sent => {}
}
apns.alert(&device_token, "Laundry", Some(&id)).await; // visible; same id replaces, not repeats
```

Environment: `APNS_KEY` (the `.p8` contents), `APNS_KEY_ID`, `APNS_TEAM_ID`, optional
`APNS_TOPIC` and `APNS_SANDBOX=true` for builds installed from Xcode.

iOS may delay a silent push or drop it for a force-quit app: keep a visible push or the
app's own refresh as the fallback. The app stores device tokens itself; check one a client
sent with `is_token` first.
