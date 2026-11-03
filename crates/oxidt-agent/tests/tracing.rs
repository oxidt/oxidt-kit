use std::sync::{Arc, Mutex};

use oxidt_agent::{Agent, Capability, Effect, Principal, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

/// Collects every field recorded on spans, as `name=value` strings.
#[derive(Clone, Default)]
struct Fields(Arc<Mutex<Vec<String>>>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        let value = value.trim_matches('"');
        self.0
            .lock()
            .unwrap()
            .push(format!("{}={value}", field.name()));
    }
}

impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Fields {
    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
        attrs.record(&mut self.clone());
    }
    fn on_record(&self, _: &Id, values: &Record<'_>, _: Context<'_, S>) {
        values.record(&mut self.clone());
    }
}

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)] // Only deserialized, to prove it is never recorded.
struct Input {
    secret: String,
}

#[derive(Serialize, JsonSchema)]
struct Output {}

#[tokio::test]
async fn tool_span_records_otel_fields_without_arguments() {
    let fields = Fields::default();
    let _guard = tracing_subscriber::registry()
        .with(fields.clone())
        .set_default();
    let mut agent = Agent::new();
    agent
        .register(
            Capability::new("fail", "Always fails", "notes:read", Effect::Read),
            |_, _: Input| async { Err::<Output, _>(ToolError::new("not_found", "Missing")) },
        )
        .unwrap();
    let principal = Principal {
        user_id: "u".into(),
        tenant_id: "t".into(),
        client_id: "c".into(),
        grant_id: "g".into(),
        permissions: ["notes:read".into()].into(),
    };
    let result = agent
        .invoke(principal, "fail", json!({"secret": "hunter2"}))
        .await;
    assert_eq!(result.unwrap_err().code, "not_found");

    let recorded = fields.0.lock().unwrap().clone();
    for expected in [
        "otel.name=execute_tool fail",
        "gen_ai.operation.name=execute_tool",
        "gen_ai.tool.name=fail",
        "agent.effect=Read",
        "tenant_id=t",
        "error.type=not_found",
        "otel.status_code=ERROR",
    ] {
        assert!(
            recorded.iter().any(|f| f == expected),
            "{expected} missing: {recorded:?}"
        );
    }
    assert!(!recorded.iter().any(|f| f.contains("hunter2")));
}
