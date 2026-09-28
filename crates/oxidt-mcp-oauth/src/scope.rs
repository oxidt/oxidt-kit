/// The scopes a server grants: every token carries all `required` scopes, and
/// a client may add any of the `optional` ones.
///
/// dowat: required `tasks:write`, optional `offline_access`. smiet: required
/// `mcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scopes {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

/// Why a requested scope was refused. Maps to `invalid_scope`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    #[error("scope `{0}` is required")]
    MissingRequired(String),
    #[error("scope `{0}` is not supported")]
    Unsupported(String),
}

impl Scopes {
    /// Validate a space-separated `scope` parameter. Returns its scopes in
    /// request order, duplicates removed.
    ///
    /// Also use it to re-check a stored grant's scope on every token use, so a
    /// scope retired from the server stops working without a migration.
    pub fn validate_scope(&self, scope: &str) -> Result<Vec<String>, ScopeError> {
        let mut granted: Vec<String> = Vec::new();
        for s in scope.split_whitespace() {
            if !self.required.iter().chain(&self.optional).any(|k| k == s) {
                return Err(ScopeError::Unsupported(s.into()));
            }
            if !granted.iter().any(|g| g == s) {
                granted.push(s.into());
            }
        }
        if let Some(missing) = self.required.iter().find(|r| !granted.contains(r)) {
            return Err(ScopeError::MissingRequired(missing.clone()));
        }
        Ok(granted)
    }

    /// The scope granted when the client sends none: the required scopes.
    pub(crate) fn default_scope(&self) -> String {
        self.required.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dowat() -> Scopes {
        Scopes {
            required: vec!["tasks:write".into()],
            optional: vec!["offline_access".into()],
        }
    }

    #[test]
    fn required_scope_must_be_present_and_optional_may_be_added() {
        let s = dowat();
        assert_eq!(s.validate_scope("tasks:write").unwrap(), ["tasks:write"]);
        assert_eq!(
            s.validate_scope("offline_access  tasks:write tasks:write")
                .unwrap(),
            ["offline_access", "tasks:write"]
        );
        assert_eq!(
            s.validate_scope("offline_access"),
            Err(ScopeError::MissingRequired("tasks:write".into()))
        );
        assert_eq!(
            s.validate_scope(""),
            Err(ScopeError::MissingRequired("tasks:write".into()))
        );
        assert_eq!(
            s.validate_scope("tasks:write calendar:read"),
            Err(ScopeError::Unsupported("calendar:read".into()))
        );
    }

    #[test]
    fn smiet_accepts_only_mcp() {
        let s = Scopes {
            required: vec!["mcp".into()],
            optional: vec![],
        };
        assert_eq!(s.validate_scope("mcp").unwrap(), ["mcp"]);
        assert!(s.validate_scope("mcp offline_access").is_err());
        assert_eq!(s.default_scope(), "mcp");
    }
}
