//! Organization checkout without product-specific plan names or email-based
//! customer lookup. External customer IDs keep tenants separate.
use crate::{PolarError, PolarResult};

#[derive(Clone)]
pub struct OrganizationClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl std::fmt::Debug for OrganizationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl OrganizationClient {
    pub fn new(token: String, sandbox: bool) -> PolarResult<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            token,
            base_url: if sandbox {
                "https://sandbox-api.polar.sh/v1".into()
            } else {
                "https://api.polar.sh/v1".into()
            },
        })
    }

    pub async fn checkout(
        &self,
        org_id: &str,
        product_id: &str,
        return_url: &str,
    ) -> PolarResult<String> {
        self.post_url(
            "/checkouts/",
            serde_json::json!({
                "products": [product_id], "external_customer_id": org_id,
                "metadata": { "reference_id": org_id },
                "success_url": return_url, "return_url": return_url,
            }),
            "url",
        )
        .await
    }

    pub async fn portal(&self, customer_id: &str, return_url: &str) -> PolarResult<String> {
        self.post_url(
            "/customer-sessions/",
            serde_json::json!({
                "customer_id": customer_id, "return_url": return_url,
            }),
            "customer_portal_url",
        )
        .await
    }

    async fn post_url(
        &self,
        path: &str,
        body: serde_json::Value,
        field: &str,
    ) -> PolarResult<String> {
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(PolarError::Api {
                status: response.status().as_u16(),
                message: "Polar request failed".into(),
            });
        }
        let data: serde_json::Value = response.json().await?;
        let value = data[field]
            .as_str()
            .ok_or_else(|| PolarError::Validation("Missing redirect URL".into()))?;
        let url = reqwest::Url::parse(value)
            .map_err(|_| PolarError::Validation("Invalid redirect URL".into()))?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(PolarError::Validation("Invalid redirect URL".into()));
        }
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{bearer_token, body_partial_json, method, path},
    };

    #[tokio::test]
    async fn checkout_binds_to_org_and_portal_uses_stored_customer() {
        let server = MockServer::start().await;
        let mut client = OrganizationClient::new("private-token".into(), true).unwrap();
        client.base_url = server.uri();
        Mock::given(method("POST")).and(path("/checkouts/"))
            .and(bearer_token("private-token"))
            .and(body_partial_json(serde_json::json!({"products":["product_pro"],
                "external_customer_id":"org_a", "metadata":{"reference_id":"org_a"},
                "success_url":"https://app.test/settings", "return_url":"https://app.test/settings"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"url":"https://polar.sh/checkout/test"})))
            .expect(1).mount(&server).await;
        assert_eq!(
            client
                .checkout("org_a", "product_pro", "https://app.test/settings")
                .await
                .unwrap(),
            "https://polar.sh/checkout/test"
        );
        Mock::given(method("POST"))
            .and(path("/customer-sessions/"))
            .and(body_partial_json(
                serde_json::json!({"customer_id":"customer_a"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"customer_portal_url":"https://polar.sh/portal/test"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client
                .portal("customer_a", "https://app.test/settings")
                .await
                .unwrap(),
            "https://polar.sh/portal/test"
        );
        assert!(!format!("{client:?}").contains("private-token"));
    }

    #[tokio::test]
    async fn untrusted_redirects_and_provider_error_bodies_are_rejected() {
        let server = MockServer::start().await;
        let mut client = OrganizationClient::new("private-token".into(), true).unwrap();
        client.base_url = server.uri();
        Mock::given(path("/checkouts/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"url":"javascript:alert(1)"})),
            )
            .mount(&server)
            .await;
        assert!(
            client
                .checkout("org_a", "product_pro", "https://app.test/settings")
                .await
                .is_err()
        );
        Mock::given(path("/customer-sessions/"))
            .respond_with(ResponseTemplate::new(403).set_body_string("private provider response"))
            .mount(&server)
            .await;
        let error = client
            .portal("customer_a", "https://app.test/settings")
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private provider response"));
    }
}
