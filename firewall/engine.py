import yaml
import json
import math
import uuid
import hashlib
import threading

from datetime import datetime
from dataclasses import dataclass


@dataclass
class Decision:
    action: str
    reason: str


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

            if not isinstance(
                rule["tool"],
                str,
            ):
                raise ValueError(
                    "Policy tool must be a string"
                )

            if "agent" in rule:

                if not isinstance(
                    rule["agent"],
                    str,
                ):
                    raise ValueError(
                        "Policy agent must be a string"
                    )

            if "action" not in rule:
                raise ValueError(
                    "Each policy rule requires an action"
                )

            if rule["action"] not in PRIORITY:
                raise ValueError(
                    f"Invalid policy action: "
                    f"{rule['action']}"
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
                            f"Policy {field} "
                            f"must be a finite number"
                        )

        self.rules = rules

        self.identity_verifier = (
            identity_verifier
        )

        self._log_lock = threading.Lock()

        self._last_audit_hash = ""

    def log(
        self,
        agent,
        tool,
        arguments,
        decision,
    ):

        if hasattr(
            agent,
            "agent_id",
        ):
            agent_name = agent.agent_id
        else:
            agent_name = agent

        entry = {
            "request_id": str(
                uuid.uuid4()
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

        if hasattr(
            agent,
            "public_key",
        ):
            entry["public_key"] = (
                agent.public_key
            )

        if hasattr(
            agent,
            "issuer",
        ):
            entry["issuer"] = (
                agent.issuer
            )

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

                if not isinstance(
                    entry,
                    dict,
                ):
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

            if isinstance(
                amount,
                bool,
            ):
                return False

            if not math.isfinite(
                amount
            ):
                return False

            if "amount_gt" in rule:

                if (
                    amount
                    <= rule["amount_gt"]
                ):
                    return False

            if "amount_gte" in rule:

                if (
                    amount
                    < rule["amount_gte"]
                ):
                    return False

        return True

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

        if (
            self.identity_verifier
            is not None
        ):

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

            if isinstance(
                amount,
                bool,
            ):

                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount",
                )

            if not math.isfinite(
                amount
            ):

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
                    (
                        "Payment amount "
                        "must be greater "
                        "than zero"
                    ),
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