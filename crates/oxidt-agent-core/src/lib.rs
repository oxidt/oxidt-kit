//! Agent access policy, independent of HTTP, MCP, sessions and storage.

use std::collections::BTreeSet;

/// Constructed by the host application's authentication adapter, never from tool arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub user_id: String,
    pub tenant_id: String,
    pub client_id: String,
    /// Stable API-key or OAuth-grant identifier, never the credential itself.
    pub grant_id: String,
    pub permissions: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Read,
    Write,
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approval {
    NotRequired,
    Required,
}

#[derive(Clone, Debug)]
pub struct Capability {
    pub name: String,
    /// Bump when handler behavior changes, even if its schema stays the same.
    pub version: String,
    pub description: String,
    pub permission: String,
    pub effect: Effect,
    pub approval: Approval,
    /// A reviewer may pre-approve this durable action for a limited time. Off by default.
    pub allowances: bool,
}

impl Capability {
    /// Writes and external effects require approval unless the app explicitly opts out.
    pub fn new(name: &str, description: &str, permission: &str, effect: Effect) -> Self {
        Self {
            name: name.into(),
            version: "1".into(),
            description: description.into(),
            permission: permission.into(),
            effect,
            approval: if effect == Effect::Read {
                Approval::NotRequired
            } else {
                Approval::Required
            },
            allowances: false,
        }
    }

    pub fn with_approval(mut self, approval: Approval) -> Self {
        self.approval = approval;
        self
    }

    /// Only for actions safe to run with any arguments once a reviewer trusts the
    /// client: an allowance covers every later submission, not one reviewed payload.
    pub fn with_allowances(mut self) -> Self {
        self.allowances = true;
        self
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.into();
        self
    }

    /// Visibility is not authorization: call `authorize` again for every invocation.
    pub fn visible_to(&self, principal: &Principal) -> bool {
        !principal.user_id.is_empty()
            && !principal.tenant_id.is_empty()
            && !principal.client_id.is_empty()
            && !principal.grant_id.is_empty()
            && principal.permissions.contains(&self.permission)
    }

    /// Immediate calls fail closed for actions requiring approval. Durable actions
    /// use the persisted approval path instead; no client flag bypasses this check.
    pub fn authorize(&self, principal: &Principal) -> Result<(), AccessError> {
        if !self.visible_to(principal) {
            return Err(AccessError::Forbidden);
        }
        if self.approval == Approval::Required {
            return Err(AccessError::ApprovalRequired);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("Permission denied")]
    Forbidden,
    #[error("This action requires approval through the durable action workflow")]
    ApprovalRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_permission_and_approval_are_separate_checks() {
        let read = Capability::new("read", "Read notes", "notes:read", Effect::Read);
        let mut principal = Principal {
            user_id: "user".into(),
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            grant_id: "grant".into(),
            permissions: BTreeSet::new(),
        };
        assert_eq!(read.authorize(&principal), Err(AccessError::Forbidden));
        principal.permissions.insert("notes:read".into());
        assert_eq!(read.authorize(&principal), Ok(()));
        let write = Capability::new("write", "Write notes", "notes:read", Effect::Write);
        assert_eq!(
            write.authorize(&principal),
            Err(AccessError::ApprovalRequired)
        );
        principal.tenant_id.clear();
        assert_eq!(read.authorize(&principal), Err(AccessError::Forbidden));
    }
}
