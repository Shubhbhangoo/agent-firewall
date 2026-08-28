# v1.9 Browser Security Operations

The console's new **Security operations** panel is the visual home of
the Agent Security Network. It answers, in the browser, the same
questions as the v1.9 CLI -- from the same modules.

## What the panel shows

- **Active agents** -- every agent in the network, its reachable
  capabilities, tools, and resources, and its detection count. Agents
  with high-severity detections are highlighted.
- **Suspicious behavior** -- the full detection list with what/why/
  evidence (artifact#event)/severity/recommended response.
- **Correlation** -- bundles grouping artifacts by shared correlation
  ids, incidents, agents, or provenance.
- **Sensitive resources** -- the attack-path summary: credential-shaped
  resources present in the network, with evidence counts.
- **Attack paths** -- query a target (optionally from one agent) and
  get recorded paths with status labels and break-path suggestions.
- **Scenario simulator** -- pick an agent, a scenario kind (compromised
  agent, stolen capability, changed policy, ...), added capabilities,
  and a containment option; get the full explainable report.

## Routes

| route | auth | purpose |
| --- | --- | --- |
| `GET /api/soc` | none | full SOC overview (agents, detections, bundles, sensitive resources, graph) |
| `POST /api/soc/attack-paths` | none | read-only attack-path query (isolated analysis) |
| `POST /api/soc/simulate` | none | read-only scenario simulation (isolated workspace) |
| `POST /api/control/respond` | bearer token | audited graduated response through the containment controller |

The SOC analysis routes need no control token because they are
read-only projections over verified evidence -- they never touch a live
SDK. Response automation is a write, so it stays behind the control
plane's bearer-token gate and lands in the audit stream.

## One system, two interfaces

- CLI and browser call the same `firewall.network` modules.
- Identical terminology: detections, bundles, sensitive resources,
  attack paths, scenarios, stages.
- The demo mode network is built from genuinely recorded sessions
  (allow/deny/delegation/containment), so the panel shows real material
  -- not mock JSON.
