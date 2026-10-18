//! The response contract for agent-driven setup: an agent in the user's repo
//! calls an app's `setup_*` MCP tool, writes what comes back into the
//! codebase, then polls `verify_setup` until the first event lands — without
//! the user opening the dashboard.
//!
//! Every app returns the same two shapes so an agent learns them once:
//!
//! - [`Setup`] — from `setup_*`: the resource, env vars to write, install
//!   snippets, and the [`HumanStep`]s an agent cannot do (billing, third-party
//!   OAuth consent), each as a URL to hand the user.
//! - [`Verification`] — from `verify_setup`: has the app seen the first
//!   event / error / feedback yet.
//!
//! `setup_*` must be idempotent: called twice with the same input it returns
//! the existing resource with `created: false`, never a duplicate.
//!
//! Types only. No clock is read inside the crate.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a `setup_*` tool returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Setup {
    pub resource: Resource,
    /// `false` when an existing resource matched the input and was returned
    /// unchanged.
    pub created: bool,
    /// Variables to write into the project's env file.
    pub env: Vec<EnvVar>,
    /// Code to add to the codebase, one entry per target the app supports.
    pub install: Vec<Snippet>,
    /// Existing SDKs that already accept these env vars, e.g. `sentry`. When
    /// the repo has one, the agent configures it instead of adding a snippet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compatible_with: Vec<String>,
    /// Steps only the user can do. Empty when setup is complete.
    pub human_steps: Vec<HumanStep>,
    /// The tool to call to confirm the install, usually `verify_setup`.
    pub verify_with: String,
}

/// The app's core resource: a project, website, site, …
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Resource {
    /// `project`, `website`, `site`, …
    pub kind: String,
    pub id: String,
    pub name: String,
    /// Where the user sees it, for the agent's final report.
    pub dashboard_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    /// `true`: the agent writes it to the env file but never echoes it to the
    /// user or commits it. `false`: safe to commit, e.g. into deploy config.
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Snippet {
    /// What it integrates with: `html`, `dioxus`, `axum`, `nextjs`, …
    pub target: String,
    /// Where it usually goes, e.g. `index.html <head>`. The agent decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_hint: Option<String>,
    pub code: String,
}

/// Something the agent must hand to the user instead of doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HumanStep {
    /// Shown to the user, e.g. "Connect Google Search Console".
    pub why: String,
    pub url: String,
}

/// What `verify_setup` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Verification {
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_event_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<DateTime<Utc>>,
    /// While waiting: how to trigger the first event, e.g. "load any page".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Nothing received yet.
    Waiting,
    /// At least one event received; the install works.
    Receiving,
}

impl Verification {
    /// Build from the app's first/last event timestamps. `hint` is kept only
    /// while waiting.
    pub fn from_events(
        first: Option<DateTime<Utc>>,
        last: Option<DateTime<Utc>>,
        hint: impl Into<String>,
    ) -> Self {
        match first {
            None => Self {
                status: Status::Waiting,
                first_event_at: None,
                last_event_at: None,
                hint: Some(hint.into()),
            },
            Some(first) => Self {
                status: Status::Receiving,
                first_event_at: Some(first),
                last_event_at: last.or(Some(first)),
                hint: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn waiting_keeps_the_hint_and_omits_timestamps() {
        let v = Verification::from_events(None, None, "load any page");
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            json!({ "status": "waiting", "hint": "load any page" })
        );
    }

    #[test]
    fn receiving_drops_the_hint_and_defaults_last_to_first() {
        let t: DateTime<Utc> = "2026-10-18T12:00:00Z".parse().unwrap();
        let v = Verification::from_events(Some(t), None, "load any page");
        assert_eq!(v.status, Status::Receiving);
        assert_eq!(v.last_event_at, Some(t));
        assert_eq!(v.hint, None);
    }

    #[test]
    fn setup_round_trips_and_omits_an_absent_file_hint() {
        let s = Setup {
            resource: Resource {
                kind: "project".into(),
                id: "p_1".into(),
                name: "acme".into(),
                dashboard_url: "https://example.com/p/p_1".into(),
            },
            created: true,
            env: vec![EnvVar {
                name: "SENTRY_DSN".into(),
                value: "https://k@example.com/1".into(),
                secret: false,
            }],
            install: vec![Snippet {
                target: "html".into(),
                file_hint: None,
                code: "<script></script>".into(),
            }],
            compatible_with: vec![],
            human_steps: vec![],
            verify_with: "verify_setup".into(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v["install"][0].get("file_hint").is_none());
        assert!(v.get("compatible_with").is_none());
        assert_eq!(serde_json::from_value::<Setup>(v).unwrap(), s);
    }

    #[test]
    fn schema_generates() {
        let schema = schemars::schema_for!(Setup);
        assert!(
            serde_json::to_string(&schema)
                .unwrap()
                .contains("verify_with")
        );
    }
}
