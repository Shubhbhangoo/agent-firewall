"""Update README, SECURITY.md, CHANGELOG, pyproject, CI for v2.0."""

import io

# 1. README
path = "README.md"
source = io.open(path, encoding="utf-8").read()


def replace_once(old, new, label):
    global source
    count = source.count(old)
    assert count == 1, f"{label}: found {count}"
    source = source.replace(old, new, 1)


replace_once(
    """### 4. The Agent Security Network (v1.9)""",
    """### 5. The Agent Security Control Plane (v2.0)

v2.0 is the flagship architectural release: a complete, cryptographically
verifiable security control plane for autonomous agents. Every
consequential action connects IDENTITY -> TASK -> AUTHORITY -> CAPABILITY
-> PROVENANCE -> POLICY -> DECISION -> EXECUTION -> EVIDENCE -> POSTURE
-> RISK -> RESPONSE.

```bash
# Identity: who is this agent (create/rotate/revoke)
firewall identity create agent-a --registry identities.json --passphrase pw
firewall identity show --registry identities.json

# Task-bound authority: what it is doing (delegation only narrows)
firewall task create agent-a --permissions '{"allowed_actions": ["read"]}'
firewall task delegate <task-id> agent-b --permissions '{"allowed_actions": ["read"]}'

# A verifiable security passport (identity + posture, signed)
firewall passport show agent-a --out passport.json
firewall passport verify passport.json --registry identities.json

# Supply-chain provenance (a name is never trust)
firewall provenance register tool payments.send --integrity sha256:...
firewall provenance trust trust tool:payments.send:1.0 --reason reviewed

# Continuous posture, trust graph, and the Security Lab
firewall posture state.json --agent agent-a
firewall trust network.json --radius agent-a
firewall lab sweep network.json
firewall lab counterfactual network.json --agent agent-a --added admin.bypass
```

New primitives: persistent cryptographic **agent identity** with full
lifecycle, **task-bound authority** whose delegation chains can only
narrow, **security passports** (deterministic, signed, never containing
private keys), **cryptographic attestation** with explicit algorithm
metadata and a verified/failed/unverifiable verifier, **supply-chain
provenance** with integrity and explicit trust, a **continuous
evidence-backed posture engine**, a cross-agent **trust graph** with
blast-radius queries, the **Security Lab 2.0** automated environment
sweep, and **adaptive response** with TTL, approval, and attestation.

Identity proves who; the authorization pipeline alone decides what.

See `docs/v2.0-architecture.md`, `docs/v2.0-identity.md`,
`docs/v2.0-threat-model.md`, `docs/v2.0-migration.md`,
`docs/v2.0-cli.md`, and `docs/v2.0-boundaries.md`.

### 4. The Agent Security Network (v1.9)""",
    "v2.0-section",
)

replace_once(
    "pip install agent-firewall-security==1.9.0",
    "pip install agent-firewall-security==2.0.0",
    "install-pin",
)
replace_once(
    "## Version\n\n```text\n1.9.0\n```",
    "## Version\n\n```text\n2.0.0\n```",
    "version-block",
)
replace_once(
    "The v1.9 validation result is **2,700+ passing tests**",
    "The v2.0 validation result is **2,800+ passing tests**",
    "tests-count",
)
replace_once(
    "| Version | `1.9.0` |",
    "| Version | `2.0.0` |",
    "package-table",
)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("README patched")

# 2. SECURITY.md.
path = "SECURITY.md"
source = io.open(path, encoding="utf-8").read()

replace_once(
    """| 1.9.x | Yes |
| 1.8.x | Yes |""",
    """| 2.0.x | Yes |
| 1.9.x | Yes |""",
    "version-table",
)
replace_once(
    """## v1.9 Security Boundary""",
    """## v2.0 Security Boundary

v2.0 adds agent identity, task-bound authority, security passports,
cryptographic attestation, supply-chain provenance, continuous posture,
a trust graph, the Security Lab, and adaptive response. Everything is
additive over v1.8/v1.9 and observational/analytical above the existing
authorization pipeline, except response, which routes through the SDK's
own revocation and risk mechanisms.

- Identity is not authorization. Verification checks signatures, status,
  and key fingerprints; forged, stolen, rotated-out, revoked, retired,
  and unknown identities fail. Parent/child identity is provenance, not
  authority.
- Task delegation only narrows: child effective permissions are the
  intersection of the parent's and the grant. Chains (A -> B -> C) can
  never escalate. Root revocation propagates to the whole subtree.
- Passports and attestations are signed over canonical payloads with
  the recorded identity key and never contain private keys. Their
  verifiers distinguish verified / failed / unverifiable and never
  conflate them (unsupported algorithms and unknown identities are
  unverifiable).
- Supply-chain provenance requires explicit trust decisions and
  integrity digests; a name is never trust, and revoking a component
  marks its dependents untrusted.
- Posture is evidence-backed: posture moves only on recorded signals,
  and every transition names its evidence.
- The Security Lab runs in isolated workspaces and never mutates live
  state; its outcomes are simulated.
- Adaptive response is policy-driven, audited, attestable, TTL-bound,
  and requires human approval for high-impact stages unless explicitly
  auto-approved.

## v1.9 Security Boundary""",
    "v2.0-boundary",
)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("SECURITY.md patched")

# 3. pyproject.
path = "pyproject.toml"
source = io.open(path, encoding="utf-8").read()
old = 'version = "1.9.0"'
new = 'version = "2.0.0"'
assert source.count(old) == 1, source.count(old)
source = source.replace(old, new, 1)
io.open(path, "w", encoding="utf-8", newline="\n").write(source)
print("pyproject patched")

# 4. CI.
for wf in (".github/workflows/security.yml", ".github/workflows/cli.yml"):
    source = io.open(wf, encoding="utf-8").read()
    before = source.count("      - v1.9\n")
    assert before >= 1, wf
    source = source.replace(
        "      - v1.9\n",
        "      - v1.9\n      - v2.0\n",
    )
    io.open(wf, "w", encoding="utf-8", newline="\n").write(source)
    print(f"{wf}: added v2.0")
