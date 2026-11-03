# oxidt-agent-core

Framework-independent capability, identity and authorization types for
[`oxidt-agent`](../oxidt-agent). No MCP, Topcoat, HTTP, authentication implementation,
database or rendering dependencies.

The host constructs a validated `Principal`; a capability checks its permission
and approval requirement. Application services still enforce ownership and
business rules. Writes and external effects require approval by default.
Immediate calls refuse approval-required actions. The optional `durable`
feature in `oxidt-agent` persists requests, authenticates review through host
hooks, and executes approved actions through `oxidt-jobs`.

`Principal::grant_id` identifies the API key or OAuth authorization grant,
never its secret. Durable execution revalidates that grant. Capability versions
must change when handler behavior changes, so old approvals cannot authorize
new behavior.
