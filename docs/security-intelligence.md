# v1.9 Security Intelligence, Attack Paths, and Simulator

## Behavioral detection

`firewall detect <state>` runs deterministic, explainable rules over
the network's verified artifacts. Every detection carries: what
happened, why it was detected, supporting evidence (artifact + event
sequence), severity, affected entities, and a recommended response.

```bash
firewall detect network.json
firewall detect network.json --min-severity high --json
```

Rules (all `inferred` by design -- heuristics, never facts):

| rule | signal | severity |
| --- | --- | --- |
| `repeated_denials` | N denied actions for the same agent+action | medium |
| `capability_escalation` | many distinct capabilities issued to one agent | medium |
| `unexpected_delegation` | authority delegated to an agent with no recorded session | high |
| `structural_denials` | revoked/untrusted/broken-chain denials | high |
| `credential_shaped_access` | requests targeting credential-like resources | high |

There is no magic AI scoring. If a heuristic fires, the rule says so,
and the evidence is right there in the report.

## The network graph

```bash
firewall network graph network.json --agent agent-a --reach
firewall network graph network.json --agent agent-a --why payments.send
firewall network graph network.json --who-can-reach /etc/shadow
firewall network graph network.json --shared /etc/shadow --agents agent-a,agent-b
```

Queries:

- **reachable(agent)** -- capabilities, tools, resources, allowed
  actions, all `derived` from recorded edges, with path evidence.
- **why_can(agent, action)** -- the recorded allow edges plus the
  authority trail (issuance/delegation) backing them.
- **who_can_reach(resource)** -- the reverse query.
- **shortest_path(a, b)** and **shared_paths(agents, resource)** --
  derived BFS over observed edges.

## Attack-path discovery

```bash
firewall attack-path network.json --summary
firewall attack-path network.json --to /etc/shadow
firewall attack-path network.json --agent agent-a --to /etc/shadow
```

Statuses are never conflated: `simulated` < `reachable` <
`policy-permitted` < `observed`. A path labeled `potentially_dangerous`
is an analytical finding about recorded authority -- reachable is not
exploitable. `break_path` suggests revoking or attenuating the
enabling capabilities, but enforcement always goes through the normal
revocation/issuer-trust mechanisms.

## Scenario simulator

`firewall network simulate <state> <scenario.json>` answers *what would
happen if...* in an isolated throwaway workspace seeded from recorded
facts:

```json
{
  "scenario_id": "s1",
  "kind": "compromised_agent",
  "title": "agent-a compromised",
  "agent": "agent-a",
  "added_capabilities": ["admin.bypass"],
  "removed_capabilities": [],
  "policy": {"max_delegation_depth": 2},
  "containment": "none",
  "added_tools": []
}
```

Kinds: `compromised_agent`, `stolen_capability`, `changed_policy`,
`revoked_capability`, `unexpected_delegation`, `additional_tool`,
`resource_compromise`, `containment`.

The report walks the whole chain: initial capabilities, available
paths, reachable resources, policy decisions (via the real pipeline),
security events, potential impact (sensitive vs general), and
containment opportunities. Everything is labeled `simulated`; a
contradiction (removing a capability the agent never held) is reported
`unverifiable`, never hidden. The simulator never modifies live state.

## Response automation

`firewall respond <state> --policy policy.json` evaluates current
detections against a policy and applies graduated responses through the
containment controller:

```json
{
  "rules": [
    {"rule_id": "repeated_denials", "min_severity": "medium", "stage": "restrict"},
    {"rule_id": "credential_shaped_access", "min_severity": "high", "stage": "quarantine"}
  ]
}
```

Stages: `observe -> warn -> restrict -> quarantine -> contain`.
`quarantine`/`contain` require human approval unless
`"auto_approve": true`. Responses are audited in the flight recorder
and the control-plane audit; enforcement is routed through the SDK's
revocation and risk mechanisms -- never around `authorize()`.
