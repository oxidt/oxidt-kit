//! A small Stripe adapter: hosted recurring Checkout, customer portal, subscription
//! retrieval and authenticated event parsing. Applications own tenant permissions,
//! the price catalog, transactions, idempotency storage, and fulfillment.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::Sha256;
use std::{collections::HashMap, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Stripe configuration is invalid")]
    Configuration,
    #[error("Stripe request failed")]
    Transport(#[source] reqwest::Error),
    #[error("Stripe returned HTTP {0}")]
    Api(u16),
    #[error("Stripe response is invalid")]
    Response,
    #[error("Stripe signature is invalid or expired")]
    Signature,
    #[error("Stripe event is invalid")]
    Event,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    secret: SecretString,
    api_version: String,
    base_url: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeClient")
            .field("api_version", &self.api_version)
            .finish_non_exhaustive()
    }
}

/// Select recurring prices on the server. Never accept arbitrary provider price
/// IDs or return URLs directly from a browser request.
pub struct Checkout<'a> {
    pub price_id: &'a str,
    pub reference_id: &'a str,
    pub customer_id: Option<&'a str>,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    pub idempotency_key: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct Session {
    pub id: String,
    pub url: String,
}

impl Client {
    /// Require an explicit API version matching the account's tested contract.
    pub fn new(secret: SecretString, api_version: &str) -> Result<Self, Error> {
        if secret.expose_secret().is_empty() || api_version.trim().is_empty() {
            return Err(Error::Configuration);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::Transport)?;
        Ok(Self {
            http,
            secret,
            api_version: api_version.into(),
            base_url: "https://api.stripe.com/v1".into(),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(self.secret.expose_secret())
            .header("Stripe-Version", &self.api_version)
    }

    pub async fn checkout(&self, checkout: Checkout<'_>) -> Result<Session, Error> {
        let mut form = vec![
            ("mode", "subscription"),
            ("line_items[0][price]", checkout.price_id),
            ("line_items[0][quantity]", "1"),
            ("client_reference_id", checkout.reference_id),
            ("metadata[reference_id]", checkout.reference_id),
            (
                "subscription_data[metadata][reference_id]",
                checkout.reference_id,
            ),
            ("success_url", checkout.success_url),
            ("cancel_url", checkout.cancel_url),
        ];
        if let Some(customer) = checkout.customer_id {
            form.push(("customer", customer));
        }
        let response = self
            .request(reqwest::Method::POST, "/checkout/sessions")
            .header("Idempotency-Key", checkout.idempotency_key)
            .form(&form)
            .send()
            .await
            .map_err(Error::Transport)?;
        let session: Session = decode(response).await?;
        validate_session(session)
    }

    pub async fn portal(&self, customer_id: &str, return_url: &str) -> Result<Session, Error> {
        let response = self
            .request(reqwest::Method::POST, "/billing_portal/sessions")
            .form(&[("customer", customer_id), ("return_url", return_url)])
            .send()
            .await
            .map_err(Error::Transport)?;
        validate_session(decode(response).await?)
    }

    /// Retrieve current state when a webhook arrives; event delivery order is
    /// not subscription revision order. Serialize this per tenant in the app.
    pub async fn subscription(&self, id: &str) -> Result<Subscription, Error> {
        if !id.starts_with("sub_") || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::Event);
        }
        let response = self
            .request(reqwest::Method::GET, &format!("/subscriptions/{id}"))
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }
}

async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    if !response.status().is_success() {
        return Err(Error::Api(response.status().as_u16()));
    }
    response.json().await.map_err(|_| Error::Response)
}

fn validate_session(session: Session) -> Result<Session, Error> {
    let url = reqwest::Url::parse(&session.url).map_err(|_| Error::Response)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Response);
    }
    Ok(session)
}

#[derive(Debug, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub customer: String,
    pub status: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    pub items: SubscriptionItems,
    /// Older Stripe API versions placed this on the subscription itself.
    #[serde(default)]
    pub current_period_end: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionItems {
    pub data: Vec<SubscriptionItem>,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionItem {
    pub price: Price,
    #[serde(default)]
    pub current_period_end: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct Price {
    pub id: String,
}

impl Subscription {
    /// This template sells one recurring base plan per subscription.
    pub fn price_id(&self) -> Option<&str> {
        if self.items.data.len() != 1 {
            return None;
        }
        Some(&self.items.data[0].price.id)
    }

    pub fn period_end_ms(&self) -> Option<i64> {
        self.items
            .data
            .iter()
            .filter_map(|i| i.current_period_end)
            .min()
            .or(self.current_period_end)
            .and_then(|t| t.checked_mul(1000))
    }
}

#[derive(Debug, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub data: EventData,
}

#[derive(Debug, Deserialize)]
pub struct EventData {
    pub object: serde_json::Value,
}

/// Authenticate raw bytes before JSON parsing. Tolerance is five minutes in
/// either direction, using overflow-safe subtraction. Multiple v1 signatures
/// support rotation; MAC comparison is constant-time. Store event IDs yourself.
pub fn verify_event(
    secret: &str,
    header: &str,
    body: &[u8],
    now_seconds: i64,
) -> Result<Event, Error> {
    if secret.is_empty() {
        return Err(Error::Signature);
    }
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", value)) => {
                if timestamp.is_some() {
                    return Err(Error::Signature);
                }
                timestamp = Some(value.parse::<i64>().map_err(|_| Error::Signature)?);
            }
            Some(("v1", value)) => signatures.push(value),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or(Error::Signature)?;
    if now_seconds.abs_diff(timestamp) > 300 {
        return Err(Error::Signature);
    }
    let valid = signatures.iter().any(|candidate| {
        let Ok(bytes) = hex::decode(candidate) else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(body);
        mac.verify_slice(&bytes).is_ok()
    });
    if !valid {
        return Err(Error::Signature);
    }
    let event: Event = serde_json::from_slice(body).map_err(|_| Error::Event)?;
    if event.id.is_empty() {
        return Err(Error::Event);
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, header, method, path},
    };

    fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(body);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn verification_rejects_tampering_expiry_future_and_overflow() {
        let body = br#"{"id":"evt_1","type":"customer.subscription.updated","data":{"object":{}}}"#;
        let sig = signature("whsec_test", 1000, body);
        assert_eq!(
            verify_event("whsec_test", &sig, body, 1000).unwrap().id,
            "evt_1"
        );
        assert!(verify_event("whsec_test", &format!("{sig},v1=bad"), body, 1000).is_ok());
        for now in [699, 1301, i64::MIN, i64::MAX] {
            assert!(verify_event("whsec_test", &sig, body, now).is_err());
        }
        assert!(verify_event("whsec_test", &sig, b"modified", 1000).is_err());
        assert!(verify_event("wrong", &sig, body, 1000).is_err());
        assert!(verify_event("", &sig, body, 1000).is_err());
        assert!(verify_event("whsec_test", &format!("{sig},t=1000"), body, 1000).is_err());
    }

    #[tokio::test]
    async fn checkout_sets_subscription_metadata_and_portal_uses_saved_customer() {
        let server = MockServer::start().await;
        let mut client = Client::new("sk_test_secret".into(), "2025-03-31.basil").unwrap();
        client.base_url = server.uri();
        Mock::given(method("POST"))
            .and(path("/checkout/sessions"))
            .and(header("Authorization", "Bearer sk_test_secret"))
            .and(header("Stripe-Version", "2025-03-31.basil"))
            .and(header("Idempotency-Key", "checkout_org_1"))
            .and(body_string_contains(
                "subscription_data%5Bmetadata%5D%5Breference_id%5D=org_1",
            ))
            .and(body_string_contains("mode=subscription"))
            .and(body_string_contains(
                "line_items%5B0%5D%5Bprice%5D=price_pro",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id":"cs_1","url":"https://checkout.stripe.com/test"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        client
            .checkout(Checkout {
                price_id: "price_pro",
                reference_id: "org_1",
                customer_id: None,
                success_url: "https://app.test/settings",
                cancel_url: "https://app.test/settings",
                idempotency_key: "checkout_org_1",
            })
            .await
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/billing_portal/sessions"))
            .and(body_string_contains("customer=cus_saved"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id":"bps_1","url":"https://billing.stripe.com/test"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        client
            .portal("cus_saved", "https://app.test/settings")
            .await
            .unwrap();
        assert!(!format!("{client:?}").contains("sk_test_secret"));
    }

    #[tokio::test]
    async fn provider_errors_are_redacted_and_paths_validated() {
        let server = MockServer::start().await;
        let mut client = Client::new("secret".into(), "2025-03-31.basil").unwrap();
        client.base_url = server.uri();
        Mock::given(method("GET"))
            .and(path("/subscriptions/sub_1"))
            .respond_with(ResponseTemplate::new(401).set_body_string("private provider details"))
            .mount(&server)
            .await;
        assert_eq!(
            client.subscription("sub_1").await.unwrap_err().to_string(),
            "Stripe returned HTTP 401"
        );
        assert!(matches!(
            client.subscription("sub_1/../../customers").await,
            Err(Error::Event)
        ));
    }

    #[test]
    fn modern_and_legacy_periods_and_multi_item_plans() {
        let mut sub: Subscription = serde_json::from_value(serde_json::json!({
            "id":"sub_1","customer":"cus_1","status":"active",
            "items":{"data":[{"price":{"id":"price_1"},"current_period_end":2000}]}
        }))
        .unwrap();
        assert_eq!(sub.period_end_ms(), Some(2_000_000));
        assert_eq!(sub.price_id(), Some("price_1"));
        sub.items.data.clear();
        sub.current_period_end = Some(3000);
        assert_eq!(sub.period_end_ms(), Some(3_000_000));
        assert_eq!(sub.price_id(), None);
    }
}
