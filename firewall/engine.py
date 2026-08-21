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


@dataclass
class Decision:
    action: str
    reason: str
    request_id: str = ""


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

        self._log_lock = threading.Lock()

        self._rate_limit_lock = threading.RLock()
        self._rate_limit_counts = {}

        self._budget_lock = threading.RLock()
        self._budget_usage = {}

        self._approval_lock = threading.Lock()
        self._approval_requests = {}

        self._state_lock = threading.Lock()

        self._state_file = os.path.join(
            os.path.dirname(
                os.path.abspath(policy_file)
            ),
            "firewall_state.json",
        )

        self._last_audit_hash = ""

        self._load_state()
        self._load_last_audit_hash()

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
                "audit.log",
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

        decision = Decision(
            "allow",
            f"Approval granted for {tool}",
            request_id,
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
                "audit.log",
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
                "audit.log",
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
    ):

        decision = Decision(
            "deny",
            reason,
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
            )

            decision = Decision(
                "approval",
                f"Approval required for {tool}",
                request_id,
            )

            self.log(
                agent,
                tool,
                arguments,
                decision,
            )

            return decision

        decision = Decision(
            action,
            f"Policy matched for {tool}",
        )

        self.log(
            agent,
            tool,
            arguments,
            decision,
        )

        return decision