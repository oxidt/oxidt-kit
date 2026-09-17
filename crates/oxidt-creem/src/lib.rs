//! A small Creem adapter: hosted Checkout and its retrieval, customer portal
//! links, subscription retrieval, plan upgrades, seat changes and cancellation,
//! authenticated event parsing and signed return URLs. Applications own tenant
//! permissions, the product catalog, transactions, idempotency storage, and
//! fulfillment.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Creem configuration is invalid")]
    Configuration,
    #[error("Creem request failed")]
    Transport(#[source] reqwest::Error),
    #[error("Creem returned HTTP {0}")]
    Api(u16),
    #[error("Creem response is invalid")]
    Response,
    #[error("Creem identifier is invalid")]
    Identifier,
    #[error("Creem signature is invalid")]
    Signature,
    #[error("Creem event is invalid")]
    Event,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    api_key: SecretString,
    base_url: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreemClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Select products on the server. Never accept arbitrary provider product IDs or
/// return URLs directly from a browser request.
#[derive(Debug, Default)]
pub struct Checkout<'a> {
    pub product_id: &'a str,
    /// Your own correlation ID; echoed on the return URL and in `checkout.completed`.
    pub request_id: Option<&'a str>,
    pub success_url: Option<&'a str>,
    /// Binds the checkout to an existing Creem customer. Creem allows only one
    /// of customer id and email, so this wins when both are set.
    pub customer_id: Option<&'a str>,
    /// Pre-fills the hosted page; Creem still owns customer identity.
    pub customer_email: Option<&'a str>,
    pub units: Option<u32>,
    pub discount_code: Option<&'a str>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
struct CheckoutBody<'a> {
    product_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    units: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discount_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer: Option<CustomerBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CustomerBody<'a> {
    Id { id: &'a str },
    Email { email: &'a str },
}

/// How Creem bills a mid-cycle plan or seat change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateBehavior {
    /// Prorate and charge now. Creem's default on upgrade.
    ProrationChargeImmediately,
    /// Prorate and charge at the next billing cycle. Creem's default on update.
    ProrationCharge,
    /// Switch without proration.
    ProrationNone,
}

#[derive(Debug, Deserialize)]
pub struct Session {
    pub id: String,
    pub checkout_url: String,
}

impl Client {
    /// Test-mode keys only work against the test host, and production keys only
    /// against the production host; the two environments share no data.
    pub fn new(api_key: SecretString, test_mode: bool) -> Result<Self, Error> {
        if api_key.expose_secret().is_empty() {
            return Err(Error::Configuration);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(Error::Transport)?;
        let host = if test_mode {
            "https://test-api.creem.io"
        } else {
            "https://api.creem.io"
        };
        Ok(Self {
            http,
            api_key,
            base_url: format!("{host}/v1"),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base_url))
            .header("x-api-key", self.api_key.expose_secret())
    }

    pub async fn checkout(&self, checkout: Checkout<'_>) -> Result<Session, Error> {
        let body = CheckoutBody {
            product_id: checkout.product_id,
            request_id: checkout.request_id,
            success_url: checkout.success_url,
            units: checkout.units,
            discount_code: checkout.discount_code,
            customer: match (checkout.customer_id, checkout.customer_email) {
                (Some(id), _) => Some(CustomerBody::Id { id }),
                (None, Some(email)) => Some(CustomerBody::Email { email }),
                (None, None) => None,
            },
            metadata: checkout.metadata.as_ref(),
        };
        let response = self
            .request(reqwest::Method::POST, "/checkouts")
            .json(&body)
            .send()
            .await
            .map_err(Error::Transport)?;
        let session: Session = decode(response).await?;
        https(&session.checkout_url)?;
        Ok(session)
    }

    /// Retrieve current state when a webhook arrives; event delivery order is
    /// not subscription revision order. Serialize this per tenant in the app.
    pub async fn subscription(&self, id: &str) -> Result<Subscription, Error> {
        let response = self
            .request(reqwest::Method::GET, "/subscriptions")
            .query(&[("subscription_id", id)])
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// Retrieve a checkout session by ID, the pull counterpart to the
    /// `checkout.completed` event and the signed return URL.
    pub async fn checkout_session(&self, id: &str) -> Result<CompletedCheckout, Error> {
        let response = self
            .request(reqwest::Method::GET, "/checkouts")
            .query(&[("checkout_id", id)])
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// Move a subscription to a different product.
    pub async fn upgrade_subscription(
        &self,
        id: &str,
        product_id: &str,
        behavior: UpdateBehavior,
    ) -> Result<Subscription, Error> {
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/subscriptions/{}/upgrade", identifier(id)?),
            )
            .json(&serde_json::json!({
                "product_id": product_id,
                "update_behavior": behavior,
            }))
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// Change the seat count on one subscription item. `item_id` is the
    /// `sitem_…` ID from [`Subscription::items`], not the subscription ID.
    /// Creem treats a product change and a quantity change as separate
    /// operations, so upgrade and update are two calls, not one.
    pub async fn update_subscription(
        &self,
        id: &str,
        item_id: &str,
        units: u32,
        behavior: UpdateBehavior,
    ) -> Result<Subscription, Error> {
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/subscriptions/{}", identifier(id)?),
            )
            .json(&serde_json::json!({
                "items": [{ "id": item_id, "units": units }],
                "update_behavior": behavior,
            }))
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// The first page only — Creem defaults to 10 per customer, which is past
    /// what a subscription SaaS puts on one account. Page through it yourself
    /// if you need more.
    pub async fn customer_subscriptions(
        &self,
        customer_id: &str,
    ) -> Result<Vec<Subscription>, Error> {
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/customers/{}/subscriptions", identifier(customer_id)?),
            )
            .send()
            .await
            .map_err(Error::Transport)?;
        let page: SubscriptionPage = decode(response).await?;
        Ok(page.items)
    }

    /// Cancellation timing follows the store's billing settings.
    pub async fn cancel_subscription(&self, id: &str) -> Result<Subscription, Error> {
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/subscriptions/{}/cancel", identifier(id)?),
            )
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    pub async fn customer(&self, id: &str) -> Result<Customer, Error> {
        let response = self
            .request(reqwest::Method::GET, "/customers")
            .query(&[("customer_id", id)])
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    pub async fn customer_by_email(&self, email: &str) -> Result<Customer, Error> {
        let response = self
            .request(reqwest::Method::GET, "/customers")
            .query(&[("email", email)])
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    pub async fn product(&self, id: &str) -> Result<Product, Error> {
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/products/{}", identifier(id)?),
            )
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// One-time login link into Creem's hosted portal. Treat it as a credential.
    pub async fn billing_portal(&self, customer_id: &str) -> Result<String, Error> {
        let response = self
            .request(reqwest::Method::POST, "/customers/billing")
            .json(&serde_json::json!({ "customer_id": customer_id }))
            .send()
            .await
            .map_err(Error::Transport)?;
        let portal: Portal = decode(response).await?;
        https(&portal.customer_portal_link)?;
        Ok(portal.customer_portal_link)
    }
}

#[derive(Deserialize)]
struct Portal {
    customer_portal_link: String,
}

#[derive(Deserialize)]
struct SubscriptionPage {
    items: Vec<Subscription>,
}

async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    if !response.status().is_success() {
        return Err(Error::Api(response.status().as_u16()));
    }
    response.json().await.map_err(|_| Error::Response)
}

fn identifier(id: &str) -> Result<&str, Error> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(Error::Identifier);
    }
    Ok(id)
}

fn https(url: &str) -> Result<(), Error> {
    let url = reqwest::Url::parse(url).map_err(|_| Error::Response)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Response);
    }
    Ok(())
}

/// Creem returns nested resources either expanded or as a bare ID string.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Expandable<T> {
    Id(String),
    Object(T),
}

impl<T> Expandable<T> {
    pub fn object(&self) -> Option<&T> {
        match self {
            Self::Id(_) => None,
            Self::Object(object) => Some(object),
        }
    }
}

/// `status` is one of `active`, `canceled`, `unpaid`, `paused`, `trialing`,
/// `scheduled_cancel`, `past_due`. Kept a string so a new one is not a parse error.
#[derive(Debug, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub status: String,
    pub product: Expandable<Product>,
    pub customer: Expandable<Customer>,
    /// Absent from webhook payloads; present when fetched from the API.
    #[serde(default)]
    pub items: Vec<SubscriptionItem>,
    #[serde(default)]
    pub current_period_start_date: Option<String>,
    #[serde(default)]
    pub current_period_end_date: Option<String>,
    #[serde(default)]
    pub canceled_at: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    /// `test`, `prod`, `sandbox`, or `local` for webhook samples.
    #[serde(default)]
    pub mode: Option<String>,
}

impl Subscription {
    pub fn product_id(&self) -> &str {
        match &self.product {
            Expandable::Id(id) => id,
            Expandable::Object(product) => &product.id,
        }
    }

    pub fn customer_id(&self) -> &str {
        match &self.customer {
            Expandable::Id(id) => id,
            Expandable::Object(customer) => &customer.id,
        }
    }

    /// Unix milliseconds. Creem sends RFC 3339 here, not epoch seconds.
    pub fn period_end_ms(&self) -> Option<i64> {
        let end = self.current_period_end_date.as_deref()?;
        chrono::DateTime::parse_from_rfc3339(end)
            .ok()
            .map(|t| t.timestamp_millis())
    }
}

/// One billable line. `id` is what [`Client::update_subscription`] takes.
#[derive(Debug, Deserialize)]
pub struct SubscriptionItem {
    pub id: String,
    #[serde(default)]
    pub product_id: Option<String>,
    #[serde(default)]
    pub price_id: Option<String>,
    #[serde(default)]
    pub units: Option<u32>,
}

/// `price` is in cents; `billing_period` is Creem's own vocabulary
/// (`every-month`, `every-three-months`, …).
#[derive(Debug, Deserialize)]
pub struct Product {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub price: Option<i64>,
    #[serde(default)]
    pub billing_period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Customer {
    pub id: String,
    #[serde(default)]
    pub email: Option<String>,
}

/// The `object` of a `checkout.completed` event, and what
/// [`Client::checkout_session`] returns.
#[derive(Debug, Deserialize)]
pub struct CompletedCheckout {
    pub id: String,
    /// `pending`, `processing`, `completed` or `expired`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub subscription: Option<Expandable<Subscription>>,
    #[serde(default)]
    pub customer: Option<Expandable<Customer>>,
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "eventType")]
    pub event_type: EventType,
    /// Unix milliseconds, unlike the RFC 3339 timestamps inside `object`.
    #[serde(default)]
    pub created_at: Option<i64>,
    pub object: serde_json::Value,
}

impl Event {
    /// The subscription carried by every `subscription.*` event.
    pub fn subscription(&self) -> Option<Subscription> {
        serde_json::from_value(self.object.clone()).ok()
    }

    pub fn checkout(&self) -> Option<CompletedCheckout> {
        serde_json::from_value(self.object.clone()).ok()
    }
}

/// Creem keeps adding event types; unknown ones arrive as `Other` rather than
/// failing the whole delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    CheckoutCompleted,
    SubscriptionActive,
    SubscriptionPaid,
    SubscriptionCanceled,
    SubscriptionScheduledCancel,
    SubscriptionPastDue,
    SubscriptionUnpaid,
    SubscriptionExpired,
    SubscriptionUpdate,
    SubscriptionTrialing,
    SubscriptionPaused,
    RefundCreated,
    DisputeCreated,
    Other(String),
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::CheckoutCompleted => "checkout.completed",
            Self::SubscriptionActive => "subscription.active",
            Self::SubscriptionPaid => "subscription.paid",
            Self::SubscriptionCanceled => "subscription.canceled",
            Self::SubscriptionScheduledCancel => "subscription.scheduled_cancel",
            Self::SubscriptionPastDue => "subscription.past_due",
            Self::SubscriptionUnpaid => "subscription.unpaid",
            Self::SubscriptionExpired => "subscription.expired",
            Self::SubscriptionUpdate => "subscription.update",
            Self::SubscriptionTrialing => "subscription.trialing",
            Self::SubscriptionPaused => "subscription.paused",
            Self::RefundCreated => "refund.created",
            Self::DisputeCreated => "dispute.created",
            Self::Other(other) => other,
        }
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "checkout.completed" => Self::CheckoutCompleted,
            "subscription.active" => Self::SubscriptionActive,
            "subscription.paid" => Self::SubscriptionPaid,
            "subscription.canceled" => Self::SubscriptionCanceled,
            "subscription.scheduled_cancel" => Self::SubscriptionScheduledCancel,
            "subscription.past_due" => Self::SubscriptionPastDue,
            "subscription.unpaid" => Self::SubscriptionUnpaid,
            "subscription.expired" => Self::SubscriptionExpired,
            "subscription.update" => Self::SubscriptionUpdate,
            "subscription.trialing" => Self::SubscriptionTrialing,
            "subscription.paused" => Self::SubscriptionPaused,
            "refund.created" => Self::RefundCreated,
            "dispute.created" => Self::DisputeCreated,
            _ => Self::Other(value),
        })
    }
}

/// Authenticate raw bytes before JSON parsing. `signature` is the hex-encoded
/// `creem-signature` header: HMAC-SHA256 of the exact body under the endpoint's
/// signing secret, compared in constant time. Creem signs no timestamp, so the
/// app must store event IDs itself to reject replays.
pub fn verify_webhook(secret: &str, signature: &str, body: &[u8]) -> Result<Event, Error> {
    if secret.is_empty() {
        return Err(Error::Signature);
    }
    let provided = hex::decode(signature).map_err(|_| Error::Signature)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| Error::Signature)?;
    mac.update(body);
    mac.verify_slice(&provided).map_err(|_| Error::Signature)?;
    let event: Event = serde_json::from_slice(body).map_err(|_| Error::Event)?;
    if event.id.is_empty() {
        return Err(Error::Event);
    }
    Ok(event)
}

/// Verify the query string Creem appends to `success_url`. Pass everything after
/// the `?`. The canonical string is the non-empty parameters in URL order as
/// `key=value`, then `salt=<api key>`, joined with `|` and hashed with SHA-256 —
/// a plain digest, not an HMAC, so the API key is the only shared secret.
///
/// A valid signature proves the redirect came from Creem; it does not prove the
/// payment settled. Confirm state through `subscription` or a webhook.
pub fn verify_return_url(api_key: &str, query: &str) -> Result<(), Error> {
    if api_key.is_empty() {
        return Err(Error::Signature);
    }
    let url = reqwest::Url::parse(&format!("https://creem.invalid/?{query}"))
        .map_err(|_| Error::Signature)?;
    let mut signature = None;
    let mut data = String::new();
    for (key, value) in url.query_pairs() {
        if key == "signature" {
            if signature.is_some() {
                return Err(Error::Signature);
            }
            signature = Some(value.into_owned());
            continue;
        }
        if value.is_empty() {
            continue;
        }
        data.push_str(&key);
        data.push('=');
        data.push_str(&value);
        data.push('|');
    }
    let signature = signature.ok_or(Error::Signature)?;
    data.push_str("salt=");
    data.push_str(api_key);
    let provided = hex::decode(&signature).map_err(|_| Error::Signature)?;
    if bool::from(provided.ct_eq(Sha256::digest(data.as_bytes()).as_slice())) {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    fn signature(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn subscription_json() -> serde_json::Value {
        serde_json::json!({
            "id": "sub_1",
            "object": "subscription",
            "status": "active",
            "product": {"id": "prod_1", "name": "Monthly", "price": 1000, "billing_period": "every-month"},
            "customer": {"id": "cust_1", "object": "customer", "email": "a@b.test"},
            "items": [{
                "object": "subscription_item",
                "id": "sitem_1",
                "product_id": "prod_1",
                "price_id": "pprice_1",
                "units": 1
            }],
            "current_period_start_date": "2024-10-12T11:58:38.000Z",
            "current_period_end_date": "2024-11-12T11:58:38.000Z",
            "canceled_at": null,
            "mode": "prod"
        })
    }

    async fn client(server: &MockServer) -> Client {
        let mut client = Client::new("creem_test_key".into(), true).unwrap();
        client.base_url = server.uri();
        client
    }

    #[tokio::test]
    async fn checkout_sends_only_the_fields_that_were_set() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        let mut metadata = serde_json::Map::new();
        metadata.insert("org_id".into(), "org_1".into());
        Mock::given(method("POST"))
            .and(path("/checkouts"))
            .and(header("x-api-key", "creem_test_key"))
            .and(body_json(serde_json::json!({
                "product_id": "prod_1",
                "request_id": "org_1",
                "success_url": "https://app.test/settings",
                "units": 3,
                "discount_code": "SUMMER2024",
                "customer": {"email": "a@b.test"},
                "metadata": {"org_id": "org_1"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "ch_1",
                "checkout_url": "https://checkout.creem.io/ch_1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let session = client
            .checkout(Checkout {
                product_id: "prod_1",
                request_id: Some("org_1"),
                success_url: Some("https://app.test/settings"),
                customer_email: Some("a@b.test"),
                units: Some(3),
                discount_code: Some("SUMMER2024"),
                metadata: Some(metadata),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(session.id, "ch_1");
        assert!(!format!("{client:?}").contains("creem_test_key"));
    }

    /// Creem allows only one of customer id and email, so the id wins.
    #[tokio::test]
    async fn checkout_prefers_customer_id_over_email() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("POST"))
            .and(path("/checkouts"))
            .and(body_json(serde_json::json!({
                "product_id": "prod_1",
                "customer": {"id": "cust_1"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "ch_1",
                "checkout_url": "https://checkout.creem.io/ch_1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        client
            .checkout(Checkout {
                product_id: "prod_1",
                customer_id: Some("cust_1"),
                customer_email: Some("a@b.test"),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn minimal_checkout_omits_optional_fields() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("POST"))
            .and(path("/checkouts"))
            .and(body_json(serde_json::json!({"product_id": "prod_1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "ch_1",
                "checkout_url": "https://checkout.creem.io/ch_1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        client
            .checkout(Checkout {
                product_id: "prod_1",
                ..Default::default()
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn subscription_cancel_and_portal_use_the_documented_shapes() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .and(header("x-api-key", "creem_test_key"))
            .and(query_param("subscription_id", "sub_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(subscription_json()))
            .expect(1)
            .mount(&server)
            .await;
        let sub = client.subscription("sub_1").await.unwrap();
        assert_eq!(sub.product_id(), "prod_1");
        assert_eq!(sub.customer_id(), "cust_1");
        assert_eq!(sub.period_end_ms(), Some(1_731_412_718_000));
        assert_eq!(sub.product.object().unwrap().price, Some(1000));

        let mut canceled = subscription_json();
        canceled["status"] = "canceled".into();
        Mock::given(method("POST"))
            .and(path("/subscriptions/sub_1/cancel"))
            .and(body_json(serde_json::json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(canceled))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client.cancel_subscription("sub_1").await.unwrap().status,
            "canceled"
        );

        Mock::given(method("POST"))
            .and(path("/customers/billing"))
            .and(body_json(serde_json::json!({"customer_id": "cust_1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"customer_portal_link": "https://creem.io/my-orders/login/x"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client.billing_portal("cust_1").await.unwrap(),
            "https://creem.io/my-orders/login/x"
        );
    }

    /// A product change and a seat change are two separate Creem operations,
    /// with `units` nested in `items[]` keyed by the subscription item ID.
    #[tokio::test]
    async fn upgrade_and_update_send_the_documented_bodies() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("POST"))
            .and(path("/subscriptions/sub_1/upgrade"))
            .and(header("x-api-key", "creem_test_key"))
            .and(body_json(serde_json::json!({
                "product_id": "prod_2",
                "update_behavior": "proration-charge-immediately"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(subscription_json()))
            .expect(1)
            .mount(&server)
            .await;
        client
            .upgrade_subscription(
                "sub_1",
                "prod_2",
                UpdateBehavior::ProrationChargeImmediately,
            )
            .await
            .unwrap();

        Mock::given(method("POST"))
            .and(path("/subscriptions/sub_1"))
            .and(header("x-api-key", "creem_test_key"))
            .and(body_json(serde_json::json!({
                "items": [{"id": "sitem_1", "units": 5}],
                "update_behavior": "proration-none"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(subscription_json()))
            .expect(1)
            .mount(&server)
            .await;
        let sub = client
            .update_subscription("sub_1", "sitem_1", 5, UpdateBehavior::ProrationNone)
            .await
            .unwrap();
        assert_eq!(sub.items[0].id, "sitem_1");
        assert_eq!(sub.items[0].units, Some(1));

        for behavior in [
            (UpdateBehavior::ProrationCharge, "proration-charge"),
            (UpdateBehavior::ProrationNone, "proration-none"),
            (
                UpdateBehavior::ProrationChargeImmediately,
                "proration-charge-immediately",
            ),
        ] {
            assert_eq!(serde_json::to_value(behavior.0).unwrap(), behavior.1);
        }
        assert!(matches!(
            client
                .upgrade_subscription("sub_1/../cancel", "prod_2", UpdateBehavior::ProrationCharge)
                .await,
            Err(Error::Identifier)
        ));
        assert!(matches!(
            client
                .update_subscription(
                    "../customers",
                    "sitem_1",
                    5,
                    UpdateBehavior::ProrationCharge
                )
                .await,
            Err(Error::Identifier)
        ));
    }

    #[tokio::test]
    async fn customer_subscriptions_returns_the_first_page_and_checkouts_are_retrievable() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("GET"))
            .and(path("/customers/cust_1/subscriptions"))
            .and(header("x-api-key", "creem_test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [subscription_json()],
                "pagination": {
                    "total_records": 1, "total_pages": 1, "current_page": 1,
                    "next_page": null, "prev_page": null
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let subs = client.customer_subscriptions("cust_1").await.unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].product_id(), "prod_1");
        assert!(matches!(
            client.customer_subscriptions("cust_1/../orders").await,
            Err(Error::Identifier)
        ));

        Mock::given(method("GET"))
            .and(path("/checkouts"))
            .and(query_param("checkout_id", "ch_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "ch_1",
                "object": "checkout",
                "status": "completed",
                "request_id": "org_1",
                "subscription": subscription_json(),
                "customer": "cust_1",
                "metadata": {"org_id": "org_1"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let checkout = client.checkout_session("ch_1").await.unwrap();
        assert_eq!(checkout.status.as_deref(), Some("completed"));
        assert_eq!(checkout.request_id.as_deref(), Some("org_1"));
        assert_eq!(checkout.subscription.unwrap().object().unwrap().id, "sub_1");
    }

    #[tokio::test]
    async fn customers_are_looked_up_by_id_or_email() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        let body = serde_json::json!({"id": "cust_1", "object": "customer", "email": "a@b.test"});
        Mock::given(method("GET"))
            .and(path("/customers"))
            .and(query_param("customer_id", "cust_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(client.customer("cust_1").await.unwrap().id, "cust_1");
        Mock::given(method("GET"))
            .and(path("/customers"))
            .and(query_param("email", "a@b.test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client
                .customer_by_email("a@b.test")
                .await
                .unwrap()
                .email
                .as_deref(),
            Some("a@b.test")
        );
    }

    #[tokio::test]
    async fn provider_errors_are_redacted_and_path_ids_validated() {
        let server = MockServer::start().await;
        let client = client(&server).await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("private provider details"))
            .mount(&server)
            .await;
        assert_eq!(
            client.subscription("sub_1").await.unwrap_err().to_string(),
            "Creem returned HTTP 401"
        );
        assert!(matches!(
            client.cancel_subscription("sub_1/../../customers").await,
            Err(Error::Identifier)
        ));
        assert!(matches!(client.product("").await, Err(Error::Identifier)));
        assert!(matches!(
            Client::new("".into(), false),
            Err(Error::Configuration)
        ));
    }

    #[test]
    fn webhook_verification_rejects_tampering_and_wrong_secrets() {
        let body = br#"{"id":"evt_1","eventType":"subscription.paid","created_at":1728734327355,"object":{"id":"sub_1"}}"#;
        let sig = signature("whsec_test", body);
        let event = verify_webhook("whsec_test", &sig, body).unwrap();
        assert_eq!(event.id, "evt_1");
        assert_eq!(event.event_type, EventType::SubscriptionPaid);
        assert_eq!(event.event_type.as_str(), "subscription.paid");
        assert_eq!(event.created_at, Some(1_728_734_327_355));
        assert!(verify_webhook("whsec_test", &sig, b"modified").is_err());
        assert!(verify_webhook("wrong", &sig, body).is_err());
        assert!(verify_webhook("", &sig, body).is_err());
        assert!(verify_webhook("whsec_test", "not-hex", body).is_err());
        assert!(verify_webhook("whsec_test", &sig[..62], body).is_err());
    }

    #[test]
    fn unknown_event_types_survive_and_payloads_stay_typed() {
        let mut payload = serde_json::json!({
            "id": "evt_2",
            "eventType": "credits.granted",
            "object": subscription_json()
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let event = verify_webhook("s", &signature("s", &body), &body).unwrap();
        assert_eq!(event.event_type, EventType::Other("credits.granted".into()));
        assert_eq!(event.subscription().unwrap().status, "active");

        payload["eventType"] = "checkout.completed".into();
        payload["object"] = serde_json::json!({
            "id": "ch_1",
            "object": "checkout",
            "request_id": "org_1",
            "subscription": subscription_json(),
            "customer": "cust_1"
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let checkout = verify_webhook("s", &signature("s", &body), &body)
            .unwrap()
            .checkout()
            .unwrap();
        assert_eq!(checkout.request_id.as_deref(), Some("org_1"));
        assert_eq!(checkout.subscription.unwrap().object().unwrap().id, "sub_1");
        assert!(matches!(checkout.customer, Some(Expandable::Id(_))));
    }

    #[test]
    fn return_url_signature_covers_non_empty_params_in_order() {
        let key = "creem_test_key";
        let signed = |data: &str| hex::encode(Sha256::digest(data.as_bytes()));

        let sig = signed("checkout_id=ch_1|order_id=ord_1|product_id=prod_1|salt=creem_test_key");
        let query = format!(
            "checkout_id=ch_1&order_id=ord_1&customer_id=&subscription_id=&product_id=prod_1&signature={sig}"
        );
        assert!(verify_return_url(key, &query).is_ok());
        assert!(verify_return_url("other_key", &query).is_err());
        assert!(verify_return_url("", &query).is_err());
        assert!(verify_return_url(key, &query.replace("ch_1", "ch_2")).is_err());
        assert!(verify_return_url(key, &format!("{query}&signature={sig}")).is_err());
        assert!(verify_return_url(key, "checkout_id=ch_1").is_err());
        assert!(verify_return_url(key, "checkout_id=ch_1&signature=zz").is_err());

        // request_id is signed where present, and values arrive percent-encoded.
        let sig = signed("checkout_id=ch_1|request_id=org 1|salt=creem_test_key");
        assert!(
            verify_return_url(
                key,
                &format!("checkout_id=ch_1&request_id=org%201&signature={sig}")
            )
            .is_ok()
        );
    }
}
