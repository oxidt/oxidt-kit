//! What a call to a remote tool meets: the user's setting for it, the
//! default when they chose none, and the hold on a tool whose definition
//! changed since they last accepted it.

use serde::{Deserialize, Serialize};

/// Whether a tool may run without the user confirming each call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolPolicy {
    Allow,
    Ask,
    Block,
}

impl ToolPolicy {
    pub fn as_db_str(self) -> &'static str {
        match self {
            ToolPolicy::Allow => "allow",
            ToolPolicy::Ask => "ask",
            ToolPolicy::Block => "block",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(ToolPolicy::Allow),
            "ask" => Some(ToolPolicy::Ask),
            "block" => Some(ToolPolicy::Block),
            _ => None,
        }
    }

    /// The setting a tool has when the user chose none: one the server marks
    /// read-only runs, anything else asks. The mark is the remote server's
    /// own claim; an app that does not trust it passes `None`.
    pub fn default_for(read_only: Option<bool>) -> Self {
        if read_only == Some(true) {
            ToolPolicy::Allow
        } else {
            ToolPolicy::Ask
        }
    }
}

/// What a call to a tool meets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolGate {
    /// Runs without asking.
    Run,
    /// Runs once the user approved this call.
    Approve,
    /// Never runs.
    Blocked,
    /// Its definition changed, or it appeared after connecting: it waits
    /// until the user accepts it.
    Held,
}

/// `held` wins over every setting: a tool the user allowed is not the tool
/// the server offers now.
pub fn tool_gate(policy: Option<ToolPolicy>, read_only: Option<bool>, held: bool) -> ToolGate {
    if held {
        return ToolGate::Held;
    }
    match policy.unwrap_or(ToolPolicy::default_for(read_only)) {
        ToolPolicy::Allow => ToolGate::Run,
        ToolPolicy::Ask => ToolGate::Approve,
        ToolPolicy::Block => ToolGate::Blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_tool_waits_whatever_its_setting() {
        assert_eq!(
            tool_gate(Some(ToolPolicy::Allow), Some(true), true),
            ToolGate::Held
        );
        assert_eq!(
            tool_gate(Some(ToolPolicy::Block), None, true),
            ToolGate::Held
        );
    }

    #[test]
    fn without_a_setting_only_a_read_only_tool_runs_unasked() {
        assert_eq!(tool_gate(None, Some(true), false), ToolGate::Run);
        assert_eq!(tool_gate(None, Some(false), false), ToolGate::Approve);
        assert_eq!(tool_gate(None, None, false), ToolGate::Approve);
    }

    #[test]
    fn the_users_setting_beats_the_servers_mark() {
        assert_eq!(
            tool_gate(Some(ToolPolicy::Ask), Some(true), false),
            ToolGate::Approve
        );
        assert_eq!(
            tool_gate(Some(ToolPolicy::Allow), Some(false), false),
            ToolGate::Run
        );
        assert_eq!(
            tool_gate(Some(ToolPolicy::Block), Some(true), false),
            ToolGate::Blocked
        );
    }

    #[test]
    fn settings_round_trip_through_storage() {
        for policy in [ToolPolicy::Allow, ToolPolicy::Ask, ToolPolicy::Block] {
            assert_eq!(ToolPolicy::from_db_str(policy.as_db_str()), Some(policy));
        }
        assert_eq!(ToolPolicy::from_db_str("maybe"), None);
    }
}
