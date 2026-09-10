import yaml
import json
import math
import uuid
import hashlib
import threading
import time
import os
import tempfile

from datetime import datetime
from dataclasses import dataclass
from typing import Any

from firewall.authorization import authorize
from firewall.security_decision import SecurityDecision
from firewall.delegation_lineage import DelegationLineage
from firewall.capability import (
    CapabilityVerifier,
    capability_fingerprint,
)
from firewall.evidence import make_evidence
from firewall.replay import ReplayProtector, make_replay_key
from firewall.revocation import (
    RevocationRegistry,
    AlreadyRevokedError,
)
from firewall.revocation_store import (
    SQLiteRevocationStore,
)


@dataclass
class Decision:
    action: str
    reason: str
    request_id: str = ""
    evidence: Any = None

    @property
    def security_decision(self) -> SecurityDecision:
        reason_map = {
            "authorized": "authorized",
            "Policy matched": "authorized",

            "capability_revoked": "revoked",
            "Replay detected": "replay",
            "Budget exceeded": "budget_exceeded",

            "Unauthenticated agent identity": "invalid_request",
            "Invalid agent identity": "verification_error",
            "Invalid arguments": "invalid_request",
            "No matching policy": "constraint_denied",
            "Invalid policy action": "invalid_request",
            "Rate limit exceeded": "constraint_denied",

            "Invalid approval request": "invalid_request",
            "Request does not require approval": "invalid_request",
            "Approval request has no identity": "invalid_request",
            "Approval request is invalid or already used": "invalid_request",
            "Approval identity mismatch": "invalid_request",

            "Invalid payment amount": "constraint_denied",
            "Payment amount must be greater than zero": "constraint_denied",
        }

        canonical_reason = reason_map.get(
            self.reason,
            self.reason,
        )

        return SecurityDecision(
            allowed=self.action == "allow",
            reason=canonical_reason,
            metadata={
                "request_id": self.request_id,
                "legacy_action": self.action,
                "legacy_reason": self.reason,
            },
        )


PRIORITY = {
    "allow": 1,
    "approval": 2,
    "deny": 3,
}


class Firewall:

    def __init__(
        self,
        policy_file="policies.yaml",
        identity_verifier=None,
        revocation_registry=None,
        revocation_store_path=None,
        delegation_lineage=None,
    ):
        with open(
            policy_file,
            "r",
            encoding="utf-8",
        ) as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(
                "Policy file must contain a dictionary"
            )

        rules = data.get("rules", [])

        if not isinstance(rules, list):
            raise ValueError(
                "Policy 'rules' must be a list"
            )

        for rule in rules:

            if not isinstance(rule, dict):
                raise ValueError(
                    "Each policy rule must be a dictionary"
                )

            if "tool" not in rule:
                raise ValueError(
                    "Each policy rule requires a tool"
                )

            if not isinstance(rule["tool"], str):
                raise ValueError(
                    "Policy tool must be a string"
                )

            if "agent" in rule:
                if not isinstance(rule["agent"], str):
                    raise ValueError(
                        "Policy agent must be a string"
                    )

            if "capability" in rule:

                if not isinstance(
                    rule["capability"],
                    str,
                ):
                    raise ValueError(
                        "Policy capability must be a string"
                    )

                if not rule["capability"]:
                    raise ValueError(
                        "Policy capability cannot be empty"
                    )

            if "capabilities" in rule:

                capabilities = rule["capabilities"]

                if not isinstance(
                    capabilities,
                    list,
                ):
                    raise ValueError(
                        "Policy capabilities must be a list"
                    )

                for capability in capabilities:

                    if not isinstance(
                        capability,
                        str,
                    ):
                        raise ValueError(
                            "Policy capabilities must contain strings"
                        )

                    if not capability:
                        raise ValueError(
                            "Policy capabilities cannot contain empty values"
                        )

            if (
                "capability" in rule
                and "capabilities" in rule
            ):
                raise ValueError(
                    "Policy cannot define both capability and capabilities"
                )

            if "rate_limit" in rule:

                rate_limit = rule["rate_limit"]

                if (
                    isinstance(rate_limit, bool)
                    or not isinstance(
                        rate_limit,
                        int,
                    )
                    or rate_limit <= 0
                ):
                    raise ValueError(
                        "Policy rate_limit must be a positive integer"
                    )

            if "rate_limit_window" in rule:

                rate_limit_window = (
                    rule["rate_limit_window"]
                )

                if (
                    isinstance(
                        rate_limit_window,
                        bool,
                    )
                    or not isinstance(
                        rate_limit_window,
                        (int, float),
                    )
                    or not math.isfinite(
                        rate_limit_window
                    )
                    or rate_limit_window <= 0
                ):
                    raise ValueError(
                        "Policy rate_limit_window must be a positive finite number"
                    )

                if "rate_limit" not in rule:
                    raise ValueError(
                        "rate_limit_window requires rate_limit"
                    )

            if "budget" in rule:

                budget = rule["budget"]

                if (
                    isinstance(budget, bool)
                    or not isinstance(
                        budget,
                        (int, float),
                    )
                    or not math.isfinite(budget)
                    or budget <= 0
                ):
                    raise ValueError(
                        "Policy budget must be a positive finite number"
                    )

            if "action" not in rule:
                raise ValueError(
                    "Each policy rule requires an action"
                )

            if rule["action"] not in PRIORITY:
                raise ValueError(
                    f"Invalid policy action: {rule['action']}"
                )

            for field in (
                "amount_gt",
                "amount_gte",
            ):

                if field in rule:

                    value = rule[field]

                    if (
                        isinstance(value, bool)
                        or not isinstance(
                            value,
                            (int, float),
                        )
                        or not math.isfinite(value)
                    ):
                        raise ValueError(
                            f"Policy {field} must be a finite number"
                        )

        self.rules = rules

        self.identity_verifier = (
            identity_verifier
        )

        # v0.6 capability verification is separate from
        # the legacy agent identity verifier.
        self.capability_verifier = CapabilityVerifier()

        # v0.6 replay protection. The cache is intentionally
        # separate from persistent budget/rate-limit state.
        self.replay_protector = ReplayProtector(
            clock=time.time
        )

        if (
            revocation_registry is not None
            and revocation_store_path is not None
        ):
            raise ValueError(
                "provide either revocation_registry "
                "or revocation_store_path, not both"
            )

        self._revocation_store = None

        if revocation_registry is not None:
            self.revocation_registry = (
                revocation_registry
            )
        elif revocation_store_path is not None:
            self._revocation_store = (
                SQLiteRevocationStore(
                    revocation_store_path,
                    clock=time.time,
                )
            )
            self.revocation_registry = (
                RevocationRegistry(
                    clock=time.time,
                    backend=self._revocation_store,
                )
            )
        else:
            self.revocation_registry = (
                RevocationRegistry(
                    clock=time.time
                )
            )

        if delegation_lineage is not None:
            if not isinstance(
                delegation_lineage,
                DelegationLineage,
            ):
                raise TypeError(
                    "delegation_lineage must be a DelegationLineage"
                )

            self.delegation_lineage = (
                delegation_lineage
            )
        else:
            self.delegation_lineage = (
                DelegationLineage()
            )

        self._log_lock = threading.Lock()

        self._rate_limit_lock = threading.RLock()
        self._rate_limit_counts = {}

        self._budget_lock = threading.RLock()
        self._budget_usage = {}

        self._approval_lock = threading.Lock()
        self._approval_requests = {}

        self._state_lock = threading.Lock()

        policy_directory = os.path.dirname(
            os.path.abspath(policy_file)
        )

        self._state_file = os.path.join(
            policy_directory,
            "firewall_state.json",
        )

        # Keep the audit chain anchored to the policy location
        # rather than the process working directory.
        self._audit_file = os.path.join(
            policy_directory,
            "audit.log",
        )

        self._last_audit_hash = ""

        self._load_state()
        self._load_last_audit_hash()

    # =========================================================
    # Lifecycle
    # =========================================================

    def close(self):
        if self._revocation_store is not None:
            self._revocation_store.close()
            self._revocation_store = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    # =========================================================
    # Persistent state
    # =========================================================

    def _state_payload(self):

        with self._rate_limit_lock:

            rate_limits = {}

            for key, state in (
                self._rate_limit_counts.items()
            ):

                count, monotonic_start = state

                rate_limits[
                    self._encode_key(key)
                ] = {
                    "count": count,
                    "monotonic_start": monotonic_start,
                    "wall_timestamp": time.time(),
                }

        with self._budget_lock:

            budgets = {}

            for key, amount in (
                self._budget_usage.items()
            ):

                budgets[
                    self._encode_key(key)
                ] = amount

        return {
            "version": 1,
            "created_at": time.time(),
            "rate_limits": rate_limits,
            "budget_usage": budgets,
        }

    def _encode_key(self, key):

        if not isinstance(key, tuple):
            raise ValueError(
                "Invalid state key"
            )

        return json.dumps(
            list(key),
            separators=(",", ":"),
        )

    def _decode_key(self, value):

        decoded = json.loads(value)

        if (
            not isinstance(decoded, list)
            or len(decoded) != 2
        ):
            raise ValueError(
                "Invalid state key"
            )

        if not all(
            isinstance(item, str)
            for item in decoded
        ):
            raise ValueError(
                "Invalid state key"
            )

        return (
            decoded[0],
            decoded[1],
        )

    def _state_integrity(self, payload):

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    def _save_state(self):

        payload = self._state_payload()

        document = {
            "payload": payload,
            "integrity_hash": self._state_integrity(
                payload
            ),
        }

        directory = os.path.dirname(
            self._state_file
        )

        with self._state_lock:

            fd = None
            temp_path = None

            try:

                fd, temp_path = tempfile.mkstemp(
                    prefix=".firewall_state_",
                    suffix=".tmp",
                    dir=directory,
                )

                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                ) as f:

                    fd = None

                    json.dump(
                        document,
                        f,
                        sort_keys=True,
                    )

                    f.flush()
                    os.fsync(
                        f.fileno()
                    )

                os.replace(
                    temp_path,
                    self._state_file,
                )

                temp_path = None

            finally:

                if fd is not None:

                    try:
                        os.close(fd)
                    except OSError:
                        pass

                if temp_path is not None:

                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

    def _load_state(self):

        try:

            with open(
                self._state_file,
                "r",
                encoding="utf-8",
            ) as f:
                document = json.load(f)

        except (
            FileNotFoundError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return

        try:

            if not isinstance(
                document,
                dict,
            ):
                return

            payload = document.get(
                "payload"
            )

            stored_hash = document.get(
                "integrity_hash"
            )

            if not isinstance(
                payload,
                dict,
            ):
                return

            if not isinstance(
                stored_hash,
                str,
            ):
                return

            if (
                self._state_integrity(payload)
                != stored_hash
            ):
                return

            if payload.get("version") != 1:
                return

            self._load_budget_state(
                payload.get(
                    "budget_usage",
                    {},
                )
            )

            self._load_rate_limit_state(
                payload.get(
                    "rate_limits",
                    {},
                )
            )

        except (
            TypeError,
            ValueError,
            KeyError,
            OverflowError,
        ):

            self._budget_usage = {}
            self._rate_limit_counts = {}

    def _load_budget_state(self, state):

        if not isinstance(state, dict):
            return

        loaded = {}

        for encoded_key, amount in state.items():

            try:

                key = self._decode_key(
                    encoded_key
                )

                if (
                    isinstance(amount, bool)
                    or not isinstance(
                        amount,
                        (int, float),
                    )
                    or not math.isfinite(amount)
                    or amount < 0
                ):
                    continue

                loaded[key] = amount

            except (
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ):
                continue

        with self._budget_lock:
            self._budget_usage = loaded

    def _load_rate_limit_state(self, state):

        if not isinstance(state, dict):
            return

        loaded = {}

        current_wall = time.time()
        current_monotonic = time.monotonic()

        for encoded_key, entry in state.items():

            try:

                key = self._decode_key(
                    encoded_key
                )

                if not isinstance(
                    entry,
                    dict,
                ):
                    continue

                count = entry.get("count")
                saved_monotonic = entry.get(
                    "monotonic_start"
                )
                saved_wall = entry.get(
                    "wall_timestamp"
                )

                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count <= 0
                ):
                    continue

                if not isinstance(
                    saved_monotonic,
                    (int, float),
                ):
                    continue

                if not isinstance(
                    saved_wall,
                    (int, float),
                ):
                    continue

                if not math.isfinite(
                    saved_monotonic
                ):
                    continue

                if not math.isfinite(
                    saved_wall
                ):
                    continue

                wall_elapsed = max(
                    0.0,
                    current_wall - saved_wall,
                )

                monotonic_elapsed = (
                    current_monotonic
                    - saved_monotonic
                )

                if (
                    monotonic_elapsed >= 0
                    and monotonic_elapsed < 86400
                ):
                    elapsed = monotonic_elapsed
                else:
                    elapsed = wall_elapsed

                reconstructed_start = (
                    current_monotonic - elapsed
                )

                loaded[key] = (
                    count,
                    reconstructed_start,
                )

            except (
                ValueError,
                TypeError,
                OverflowError,
                json.JSONDecodeError,
            ):
                continue

        with self._rate_limit_lock:
            self._rate_limit_counts = loaded

    # =========================================================
    # Audit
    # =========================================================

    def _load_last_audit_hash(self):

        try:

            with open(
                self._audit_file,
                "r",
                encoding="utf-8",
            ) as f:
                lines = f.readlines()

            for line in reversed(lines):

                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)

                except json.JSONDecodeError:
                    self._last_audit_hash = ""
                    return

                if not isinstance(entry, dict):
                    self._last_audit_hash = ""
                    return

                stored_hash = entry.get(
                    "integrity_hash"
                )

                if isinstance(
                    stored_hash,
                    str,
                ):
                    self._last_audit_hash = (
                        stored_hash
                    )

                return

        except FileNotFoundError:

            self._last_audit_hash = ""

        except (
            OSError,
            UnicodeDecodeError,
        ):

            self._last_audit_hash = ""

    # =========================================================
    # Identity
    # =========================================================

    def _agent_key(self, agent):

        if hasattr(agent, "agent_id"):
            return agent.agent_id

        return str(agent)

    # =========================================================
    # Rate limiting
    # =========================================================

    def _check_rate_limit(
        self,
        agent,
        tool,
        rule,
    ):

        if "rate_limit" not in rule:
            return True

        limit = rule["rate_limit"]

        window = rule.get(
            "rate_limit_window",
            60.0,
        )

        key = (
            self._agent_key(agent),
            tool,
        )

        now = time.monotonic()

        with self._rate_limit_lock:

            state = self._rate_limit_counts.get(
                key
            )

            if state is None:

                self._rate_limit_counts[key] = (
                    1,
                    now,
                )

            else:

                count, window_start = state

                if (
                    now - window_start
                    >= window
                ):

                    self._rate_limit_counts[key] = (
                        1,
                        now,
                    )

                elif count >= limit:

                    return False

                else:

                    self._rate_limit_counts[key] = (
                        count + 1,
                        window_start,
                    )

        self._save_state()

        return True

    # =========================================================
    # Budget
    # =========================================================

    def _check_budget(
        self,
        agent,
        tool,
        arguments,
        rule,
    ):

        if "budget" not in rule:
            return True

        amount = arguments.get("amount")

        if not isinstance(
            amount,
            (int, float),
        ):
            return False

        if isinstance(amount, bool):
            return False

        if not math.isfinite(amount):
            return False

        if amount <= 0:
            return False

        budget = rule["budget"]

        key = (
            self._agent_key(agent),
            tool,
        )

        with self._budget_lock:

            used = self._budget_usage.get(
                key,
                0,
            )

            if used + amount > budget:
                return False

            self._budget_usage[key] = (
                used + amount
            )

        self._save_state()

        return True

    # =========================================================
    # Approvals
    # =========================================================

    def _create_approval(
        self,
        agent,
        tool,
        arguments,
        rule,
        capability=None,
    ):

        request_id = str(uuid.uuid4())

        with self._approval_lock:

            self._approval_requests[
                request_id
            ] = {
                "agent": agent,
                "tool": tool,
                "arguments": dict(arguments),
                "rule": dict(rule),
                "capability": capability,
            }

        return request_id

    def approve(
        self,
        request,
        approver=None,
    ):

        if not isinstance(
            request,
            Decision,
        ):
            return Decision(
                "deny",
                "Invalid approval request",
            )

        if request.action != "approval":
            return Decision(
                "deny",
                "Request does not require approval",
            )

        request_id = request.request_id

        if not request_id:
            return Decision(
                "deny",
                "Approval request has no identity",
            )

        with self._approval_lock:

            approval_data = (
                self._approval_requests.get(
                    request_id
                )
            )

            if approval_data is None:
                return Decision(
                    "deny",
                    "Approval request is invalid or already used",
                    request_id,
                )

            original_agent = (
                approval_data["agent"]
            )

            if approver is not None:

                if (
                    self._agent_key(approver)
                    != self._agent_key(
                        original_agent
                    )
                ):
                    return Decision(
                        "deny",
                        "Approval identity mismatch",
                        request_id,
                    )

            del self._approval_requests[
                request_id
            ]

        tool = approval_data["tool"]

        arguments = approval_data["arguments"]

        rule = approval_data["rule"]

        capability = approval_data.get(
            "capability"
        )

        if (
            hasattr(
                original_agent,
                "authenticated",
            )
            and original_agent.authenticated
            is False
        ):

            return self.deny(
                original_agent,
                tool,
                arguments,
                "Unauthenticated agent identity",
            )

        if self.identity_verifier is not None:

            if not self.identity_verifier.verify(
                original_agent
            ):

                return self.deny(
                    original_agent,
                    tool,
                    arguments,
                    "Invalid agent identity",
                )

        if (
            capability is not None
            and self.is_capability_revoked(
                capability
            )
        ):
            return self.deny(
                original_agent,
                tool,
                arguments,
                "capability_revoked",
                evidence=make_evidence(
                    "deny",
                    "capability_revoked",
                    agent_id=getattr(
                        original_agent,
                        "agent_id",
                        str(original_agent),
                    ),
                    capability=(
                        capability.capability
                    ),
                    request_id=request_id,
                    details={
                        "revoked": True,
                    },
                ),
            )

        if not self._check_budget(
            original_agent,
            tool,
            arguments,
            rule,
        ):

            return self.deny(
                original_agent,
                tool,
                arguments,
                "Budget exceeded",
            )

        replay_result = self._consume_replay(
            original_agent,
            capability,
            arguments,
        )

        if replay_result is False:
            return self.deny(
                original_agent,
                tool,
                arguments,
                "Replay detected",
                evidence=make_evidence(
                    "deny",
                    "Replay detected",
                    agent_id=getattr(
                        original_agent,
                        "agent_id",
                        str(original_agent),
                    ),
                    capability=(
                        capability.capability
                        if capability is not None
                        else None
                    ),
                    request_id=request_id,
                    details={
                        "replay": True,
                    },
                ),
            )

        decision = Decision(
            "allow",
            f"Approval granted for {tool}",
            request_id,
            make_evidence(
                "allow",
                f"Approval granted for {tool}",
                agent_id=getattr(
                    original_agent,
                    "agent_id",
                    str(original_agent),
                ),
                request_id=request_id,
            ),
        )

        self.log(
            original_agent,
            tool,
            arguments,
            decision,
        )

        return decision

    # =========================================================
    # Audit logging
    # =========================================================

    def log(
        self,
        agent,
        tool,
        arguments,
        decision,
    ):

        if hasattr(agent, "agent_id"):
            agent_name = agent.agent_id
        else:
            agent_name = agent

        entry = {
            "request_id": (
                decision.request_id
                or str(uuid.uuid4())
            ),
            "timestamp": (
                datetime.utcnow().isoformat()
            ),
            "agent": agent_name,
            "tool": tool,
            "arguments": arguments,
            "decision": decision.action,
            "reason": decision.reason,
        }

        if hasattr(agent, "public_key"):
            entry["public_key"] = (
                agent.public_key
            )

        if hasattr(agent, "issuer"):
            entry["issuer"] = agent.issuer

        with self._log_lock:

            entry["previous_hash"] = (
                self._last_audit_hash
            )

            integrity_payload = json.dumps(
                entry,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")

            entry["integrity_hash"] = (
                hashlib.sha256(
                    integrity_payload
                ).hexdigest()
            )

            self._last_audit_hash = (
                entry["integrity_hash"]
            )

            with open(
                self._audit_file,
                "a",
                encoding="utf-8",
            ) as f:

                f.write(
                    json.dumps(
                        entry,
                        default=str,
                    )
                    + "\n"
                )

    def verify_audit_chain(self):

        try:

            with open(
                self._audit_file,
                "r",
                encoding="utf-8",
            ) as f:
                lines = f.readlines()

            previous_hash = ""

            for line in lines:

                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)

                except json.JSONDecodeError:
                    return False

                if not isinstance(entry, dict):
                    return False

                stored_hash = entry.get(
                    "integrity_hash"
                )

                stored_previous_hash = (
                    entry.get(
                        "previous_hash"
                    )
                )

                if not isinstance(
                    stored_hash,
                    str,
                ):
                    return False

                if not isinstance(
                    stored_previous_hash,
                    str,
                ):
                    return False

                if (
                    stored_previous_hash
                    != previous_hash
                ):
                    return False

                payload = dict(entry)

                payload.pop(
                    "integrity_hash",
                    None,
                )

                integrity_payload = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")

                calculated_hash = (
                    hashlib.sha256(
                        integrity_payload
                    ).hexdigest()
                )

                if (
                    calculated_hash
                    != stored_hash
                ):
                    return False

                previous_hash = stored_hash

            return True

        except FileNotFoundError:
            return True

        except (
            OSError,
            UnicodeDecodeError,
        ):
            return False

    def deny(
        self,
        agent,
        tool,
        arguments,
        reason,
        evidence=None,
    ):
        if evidence is None:
            evidence = make_evidence(
                "deny",
                reason,
                agent_id=getattr(
                    agent,
                    "agent_id",
                    str(agent),
                ),
            )

        decision = Decision(
            "deny",
            reason,
            evidence=evidence,
        )

        self.log(
            agent,
            tool,
            arguments,
            decision,
        )

        return decision

    # =========================================================
    # Policy matching
    # =========================================================

    def matches(
        self,
        rule,
        agent,
        tool,
        arguments,
    ):

        if "agent" in rule:

            if hasattr(
                agent,
                "agent_id",
            ):
                agent_name = agent.agent_id
            else:
                agent_name = agent

            if agent_name != rule["agent"]:
                return False

        if rule.get("tool") != tool:
            return False

        required_capabilities = set()

        if "capability" in rule:
            required_capabilities.add(
                rule["capability"]
            )

        if "capabilities" in rule:
            required_capabilities.update(
                rule["capabilities"]
            )

        if required_capabilities:

            agent_capabilities = getattr(
                agent,
                "capabilities",
                frozenset(),
            )

            if not isinstance(
                agent_capabilities,
                (set, frozenset),
            ):
                return False

            if not required_capabilities.issubset(
                agent_capabilities
            ):
                return False

        if "path" in rule:

            if arguments.get(
                "path"
            ) != rule["path"]:
                return False

        if "arguments" in rule:

            expected_arguments = (
                rule["arguments"]
            )

            if not isinstance(
                expected_arguments,
                dict,
            ):
                return False

            for (
                key,
                expected_value,
            ) in expected_arguments.items():

                if key not in arguments:
                    return False

                if (
                    arguments[key]
                    != expected_value
                ):
                    return False

        has_amount_rule = (
            "amount_gt" in rule
            or "amount_gte" in rule
        )

        if has_amount_rule:

            amount = arguments.get(
                "amount"
            )

            if not isinstance(
                amount,
                (int, float),
            ):
                return False

            if isinstance(amount, bool):
                return False

            if not math.isfinite(amount):
                return False

            if "amount_gt" in rule:

                if amount <= rule["amount_gt"]:
                    return False

            if "amount_gte" in rule:

                if amount < rule["amount_gte"]:
                    return False

        return True

    def _authorize_v06(
        self,
        agent,
        tool,
        arguments,
    ):
        capabilities = getattr(
            agent,
            "capabilities",
            None,
        )

        if not capabilities:
            return None, None, None

        v06_capabilities = [
            capability
            for capability in capabilities
            if hasattr(capability, "capability")
            and hasattr(capability, "constraints")
            and hasattr(capability, "agent_id")
        ]

        if not v06_capabilities:
            return None, None, None

        agent_id = self._agent_key(agent)
        last_reason = "Capability authorization denied"
        last_evidence = None

        for capability in v06_capabilities:
            if capability.agent_id != agent_id:
                continue

            if self.is_capability_revoked(
                capability
            ):
                last_reason = "capability_revoked"
                last_evidence = make_evidence(
                    "deny",
                    "capability_revoked",
                    agent_id=agent_id,
                    capability=capability.capability,
                    details={
                        "tool": tool,
                        "revoked": True,
                    },
                )
                continue

            result = authorize(
                capability,
                tool,
                arguments,
                verifier=self.capability_verifier,
                clock=time.time,
            )

            reason = result.reason

            if result.allowed:
                evidence = make_evidence(
                    "allow",
                    "authorized",
                    agent_id=agent_id,
                    capability=capability.capability,
                    namespace_match=True,
                    constraints_ok=True,
                    time_valid=True,
                    details={
                        "authorization_reason": reason,
                        "tool": tool,
                    },
                )
                return None, evidence, capability

            last_reason = (
                "Capability authorization denied"
            )

            namespace_match = (
                False
                if reason == "namespace_denied"
                else None
            )

            constraints_ok = (
                False
                if reason == "constraint_denied"
                else None
            )

            time_valid = (
                False
                if reason in (
                    "expired",
                    "not_yet_valid",
                )
                else None
            )

            last_evidence = make_evidence(
                "deny",
                reason,
                agent_id=agent_id,
                capability=capability.capability,
                namespace_match=namespace_match,
                constraints_ok=constraints_ok,
                time_valid=time_valid,
                details={
                    "tool": tool,
                },
            )

        return last_reason, last_evidence, None

    def _replay_key_for(
        self,
        agent,
        capability,
        arguments,
    ):
        """
        Build the replay key from an explicit nonce.

        v0.5/legacy requests without a nonce remain compatible.
        v0.6 callers may supply the nonce on the agent or request.
        """

        nonce = getattr(
            agent,
            "nonce",
            None,
        )

        if nonce is None and isinstance(
            arguments,
            dict,
        ):
            nonce = arguments.get(
                "nonce"
            )

        if not nonce:
            return None

        return make_replay_key(
            self._agent_key(agent),
            capability,
            str(nonce),
        )

    def _consume_replay(
        self,
        agent,
        capability,
        arguments,
    ):
        """
        Consume a v0.6 replay nonce.

        Returns:
            True  -> first valid use
            False -> replay detected
            None  -> no nonce supplied (legacy compatibility)
        """

        if capability is None:
            return None

        key = self._replay_key_for(
            agent,
            capability,
            arguments,
        )

        if key is None:
            return None

        return self.replay_protector.check_and_consume(
            key,
            capability.expires_at,
        )

    # =========================================================
    # Capability revocation
    # =========================================================

    def revoke_capability(
        self,
        capability,
        *,
        reason="",
    ):
        """Revoke a capability permanently by fingerprint."""
        fingerprint = capability_fingerprint(
            capability
        )

        return self.revocation_registry.revoke(
            fingerprint,
            reason=reason,
        )

    def is_capability_revoked(
        self,
        capability,
    ):
        """Return True when the capability or any registered ancestor is revoked."""
        fingerprint = capability_fingerprint(
            capability
        )

        if self.revocation_registry.is_revoked(
            fingerprint
        ):
            return True

        try:
            ancestors = self.delegation_lineage.chain(
                fingerprint
            )
        except Exception:
            return True

        for ancestor in ancestors:
            if self.revocation_registry.is_revoked(
                ancestor
            ):
                return True

        return False

    # =========================================================
    # Main enforcement
    # =========================================================

    def check(
        self,
        agent,
        tool,
        arguments,
    ):

        if hasattr(
            agent,
            "authenticated",
        ):

            if agent.authenticated is False:

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Unauthenticated agent identity",
                )

        if self.identity_verifier is not None:

            if not self.identity_verifier.verify(
                agent
            ):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid agent identity",
                )

        if not isinstance(
            arguments,
            dict,
        ):

            return self.deny(
                agent,
                tool,
                arguments,
                "Invalid arguments",
            )

        capability_denial, v06_evidence, v06_capability = (
            self._authorize_v06(
                agent,
                tool,
                arguments,
            )
        )

        if capability_denial is not None:
            return self.deny(
                agent,
                tool,
                arguments,
                capability_denial,
                evidence=v06_evidence,
            )

        if tool == "payments.send":

            amount = arguments.get(
                "amount"
            )

            if not isinstance(
                amount,
                (int, float),
            ):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount",
                )

            if isinstance(amount, bool):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount",
                )

            if not math.isfinite(amount):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount",
                )

            if amount <= 0:

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Payment amount must be greater than zero",
                )

        matches = [
            rule
            for rule in self.rules
            if self.matches(
                rule,
                agent,
                tool,
                arguments,
            )
        ]

        if not matches:

            return self.deny(
                agent,
                tool,
                arguments,
                "No matching policy",
            )

        strongest = max(
            matches,
            key=lambda rule:
                PRIORITY.get(
                    rule.get("action"),
                    PRIORITY["deny"],
                ),
        )

        action = strongest.get(
            "action"
        )

        if action not in PRIORITY:

            return self.deny(
                agent,
                tool,
                arguments,
                "Invalid policy action",
            )

        if action == "allow":

            if not self._check_rate_limit(
                agent,
                tool,
                strongest,
            ):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Rate limit exceeded",
                )

            if not self._check_budget(
                agent,
                tool,
                arguments,
                strongest,
            ):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Budget exceeded",
                )

        if action == "approval":

            request_id = self._create_approval(
                agent,
                tool,
                arguments,
                strongest,
                capability=v06_capability,
            )

            decision = Decision(
                "approval",
                f"Approval required for {tool}",
                request_id,
                make_evidence(
                    "approval",
                    f"Approval required for {tool}",
                    agent_id=getattr(
                        agent,
                        "agent_id",
                        str(agent),
                    ),
                    capability=(
                        v06_evidence.capability
                        if v06_evidence is not None
                        else None
                    ),
                    namespace_match=(
                        v06_evidence.namespace_match
                        if v06_evidence is not None
                        else None
                    ),
                    constraints_ok=(
                        v06_evidence.constraints_ok
                        if v06_evidence is not None
                        else None
                    ),
                    time_valid=(
                        v06_evidence.time_valid
                        if v06_evidence is not None
                        else None
                    ),
                    request_id=request_id,
                ),
            )

            self.log(
                agent,
                tool,
                arguments,
                decision,
            )

            return decision

        if action == "allow":
            replay_result = self._consume_replay(
                agent,
                v06_capability,
                arguments,
            )

            if replay_result is False:
                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Replay detected",
                    evidence=make_evidence(
                        "deny",
                        "Replay detected",
                        agent_id=getattr(
                            agent,
                            "agent_id",
                            str(agent),
                        ),
                        capability=(
                            v06_capability.capability
                            if v06_capability is not None
                            else None
                        ),
                        namespace_match=(
                            v06_evidence.namespace_match
                            if v06_evidence is not None
                            else None
                        ),
                        constraints_ok=(
                            v06_evidence.constraints_ok
                            if v06_evidence is not None
                            else None
                        ),
                        time_valid=(
                            v06_evidence.time_valid
                            if v06_evidence is not None
                            else None
                        ),
                        details={
                            "replay": True,
                        },
                    ),
                )

        decision = Decision(
            action,
            f"Policy matched for {tool}",
            evidence=make_evidence(
                action,
                f"Policy matched for {tool}",
                agent_id=getattr(
                    agent,
                    "agent_id",
                    str(agent),
                ),
                capability=(
                    v06_evidence.capability
                    if v06_evidence is not None
                    else None
                ),
                namespace_match=(
                    v06_evidence.namespace_match
                    if v06_evidence is not None
                    else None
                ),
                constraints_ok=(
                    v06_evidence.constraints_ok
                    if v06_evidence is not None
                    else None
                ),
                time_valid=(
                    v06_evidence.time_valid
                    if v06_evidence is not None
                    else None
                ),
                policy=str(strongest),
                details={
                    "tool": tool,
                },
            ),
        )

        self.log(
            agent,
            tool,
            arguments,
            decision,
        )

        return decision