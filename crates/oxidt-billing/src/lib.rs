//! Billing domain types. No HTTP client, database, framework, or runtime.
//! Provider adapters normalize state; applications own persistence and authorization.

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    #[default]
    Polar,
    Stripe,
    Creem,
}

/// Normalized state stored by the app after verified provider updates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    /// Defaults to Polar for compatibility with existing template records.
    #[serde(default)]
    pub provider: Provider,
    pub subscription_id: String,
    pub customer_id: String,
    pub status: String,
    pub tier: Option<String>,
    /// Unix milliseconds; not a signal to revoke at a renewal boundary.
    /// Webhooks/reconciliation determine status after renewals and cancellations.
    pub current_period_end: Option<i64>,
    /// RFC 3339 provider revision time, or reconciliation time for Stripe.
    pub updated_at: String,
}

impl Subscription {
    /// Strict default: no grace period for past_due, unpaid, paused or unknown.
    /// A cancellation scheduled for period end remains active at the provider.
    pub fn is_active(&self) -> bool {
        matches!(self.status.as_str(), "active" | "trialing")
    }

    /// Unknown plans never unlock paid functionality.
    pub fn grants_access(&self) -> bool {
        self.is_active() && self.tier.as_deref().and_then(Plan::from_key).is_some()
    }
}

/// Default catalog. Provider price/product IDs stay in server configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Pro,
    Business,
    Enterprise,
}

impl Plan {
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "pro" => Some(Self::Pro),
            "business" => Some(Self::Business),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Pro => "pro",
            Self::Business => "business",
            Self::Enterprise => "enterprise",
        }
    }

    /// None explicitly means unlimited seats.
    pub fn seats(self) -> Option<i64> {
        match self {
            Self::Pro => Some(5),
            Self::Business => Some(25),
            Self::Enterprise => None,
        }
    }
}

pub fn seat_limit(subscription: Option<&Subscription>) -> Option<i64> {
    subscription
        .filter(|s| s.is_active())
        .and_then(|s| s.tier.as_deref())
        .and_then(Plan::from_key)
        .map(Plan::seats)
        .unwrap_or(Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(status: &str, tier: &str) -> Subscription {
        Subscription {
            provider: Provider::Stripe,
            subscription_id: "sub_1".into(),
            customer_id: "cus_1".into(),
            status: status.into(),
            tier: Some(tier.into()),
            current_period_end: None,
            updated_at: "2026-09-06T00:00:00Z".into(),
        }
    }

    #[test]
    fn access_and_seats_fail_closed() {
        for status in [
            "past_due",
            "unpaid",
            "canceled",
            "paused",
            "incomplete",
            "surprise",
        ] {
            let sub = subscription(status, "enterprise");
            assert!(!sub.grants_access());
            assert_eq!(seat_limit(Some(&sub)), Some(1));
        }
        for status in ["active", "trialing"] {
            assert!(subscription(status, "pro").grants_access());
            assert_eq!(seat_limit(Some(&subscription(status, "pro"))), Some(5));
            assert_eq!(
                seat_limit(Some(&subscription(status, "business"))),
                Some(25)
            );
            assert_eq!(seat_limit(Some(&subscription(status, "enterprise"))), None);
        }
        assert!(!subscription("active", "typo").grants_access());
        assert_eq!(seat_limit(Some(&subscription("active", "typo"))), Some(1));
        assert_eq!(seat_limit(None), Some(1));
    }

    #[test]
    fn legacy_records_default_to_polar() {
        let mut value = serde_json::to_value(subscription("active", "pro")).unwrap();
        value.as_object_mut().unwrap().remove("provider");
        let sub: Subscription = serde_json::from_value(value).unwrap();
        assert_eq!(sub.provider, Provider::Polar);
    }
}
