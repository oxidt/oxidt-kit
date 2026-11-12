//! Against a stand-in APNs over plain HTTP/1.1. The real one is reached over
//! HTTP/2, negotiated by TLS, which this does not cover.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use oxidt_apns::{Answer, Apns};
use serde_json::{Value, json};

const PHONE: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const GONE: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";

/// A throwaway P-256 key made for these tests only; it signs nothing real.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6+sxomTB8g7E7KPo
XdUA0UG5GpIWHILDcfYRA+yrz0WhRANCAAQX6vd++3Mi+dhBffx09WtmSMCArw3u
skJQ6aWI1H2/DOsh+OKufSXrq/lm/1rDhTMUx1tl47pVtpOEV8q4Uarn
-----END PRIVATE KEY-----";

type Seen = Arc<Mutex<Vec<(String, HeaderMap, Value)>>>;

/// Refuses `GONE` as Apple does a removed app, takes every other push.
async fn fake() -> (Apns, Seen) {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let record = record.clone();
        async move {
            let token = uri.path().trim_start_matches("/3/device/").to_owned();
            let sent = serde_json::from_slice(&body).unwrap_or(Value::Null);
            record.lock().unwrap().push((token.clone(), headers, sent));
            if token == GONE {
                let gone = json!({"reason": "Unregistered", "timestamp": 1});
                (StatusCode::GONE, Json(gone)).into_response()
            } else {
                StatusCode::OK.into_response()
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let apns = Apns::new(&base, TEST_KEY, "KEY123", "TEAM123", "app.example.ios").unwrap();
    (apns, seen)
}

#[tokio::test]
async fn a_wake_is_silent_and_an_alert_carries_its_text() {
    let (apns, seen) = fake().await;
    assert_eq!(apns.wake(PHONE).await, Answer::Sent);
    assert_eq!(
        apns.alert(PHONE, "Laundry", Some("one")).await,
        Answer::Sent
    );

    let seen = seen.lock().unwrap();
    let header = |at: usize, name: &str| seen[at].1[name].to_str().unwrap().to_owned();
    assert_eq!(seen[0].0, PHONE);
    assert_eq!(seen[0].2, json!({"aps": {"content-available": 1}}));
    assert_eq!(header(0, "apns-push-type"), "background");
    assert_eq!(header(0, "apns-priority"), "5");
    assert_eq!(header(0, "apns-topic"), "app.example.ios");
    assert!(!seen[0].1.contains_key("apns-collapse-id"));
    assert_eq!(seen[1].2["aps"]["alert"]["body"], "Laundry");
    assert_eq!(header(1, "apns-push-type"), "alert");
    assert_eq!(header(1, "apns-priority"), "10");
    assert_eq!(header(1, "apns-collapse-id"), "one");

    // Signed once with the key's id, and reused.
    let bearer = header(0, "authorization");
    assert_eq!(bearer, header(1, "authorization"));
    let jwt = jsonwebtoken::decode_header(bearer.trim_start_matches("Bearer ")).unwrap();
    assert_eq!(jwt.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(jwt.kid.as_deref(), Some("KEY123"));
}

#[tokio::test]
async fn a_token_apple_refuses_or_that_is_none_is_gone() {
    let (apns, seen) = fake().await;
    assert_eq!(apns.wake(GONE).await, Answer::Gone);
    // Never sent: it would change the address.
    assert_eq!(apns.wake("../../other").await, Answer::Gone);
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(oxidt_apns::is_token(PHONE));
}

#[tokio::test]
async fn an_unreachable_apple_or_an_unreadable_key_is_said() {
    let apns = Apns::new("http://127.0.0.1:1", TEST_KEY, "K", "T", "app.example.ios").unwrap();
    assert_eq!(apns.wake(PHONE).await, Answer::Failed);
    assert!(Apns::new("http://127.0.0.1:1", "not a key", "K", "T", "t").is_err());
}
