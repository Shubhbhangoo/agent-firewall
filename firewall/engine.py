import yaml
import json
import math
import uuid
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

    def __init__(self, policy_file="policies.yaml"):
        with open(policy_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError("Policy file must contain a dictionary")

        rules = data.get("rules", [])

        if not isinstance(rules, list):
            raise ValueError("Policy 'rules' must be a list")

        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("Each policy rule must be a dictionary")

            if "tool" not in rule:
                raise ValueError("Each policy rule requires a tool")

            if not isinstance(rule["tool"], str):
                raise ValueError("Policy tool must be a string")

            if "action" not in rule:
                raise ValueError("Each policy rule requires an action")

            if rule["action"] not in PRIORITY:
                raise ValueError(
                    f"Invalid policy action: {rule['action']}"
                )

        self.rules = rules

    def log(self, agent, tool, arguments, decision):

        entry = {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": agent,
            "tool": tool,
            "arguments": arguments,
            "decision": decision.action,
            "reason": decision.reason,
        }

        with open("audit.log", "a", encoding="utf-8") as f:
            f.write(
                json.dumps(entry, default=str) + "\n"
            )

    def deny(self, agent, tool, arguments, reason):

        decision = Decision(
            "deny",
            reason
        )

        self.log(
            agent,
            tool,
            arguments,
            decision
        )

        return decision

    def matches(self, rule, tool, arguments):

        if rule.get("tool") != tool:
            return False

        # Legacy exact path matching
        if "path" in rule:
            if arguments.get("path") != rule["path"]:
                return False

        # v0.2 generic argument matching
        if "arguments" in rule:

            expected_arguments = rule["arguments"]

            if not isinstance(expected_arguments, dict):
                return False

            for key, expected_value in expected_arguments.items():

                if key not in arguments:
                    return False

                if arguments[key] != expected_value:
                    return False

        # Numeric amount conditions
        has_amount_rule = (
            "amount_gt" in rule
            or "amount_gte" in rule
        )

        if has_amount_rule:

            amount = arguments.get("amount")

            if not isinstance(amount, (int, float)):
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

    def check(self, agent, tool, arguments):

        # Arguments must be a dictionary
        if not isinstance(arguments, dict):
            return self.deny(
                agent,
                tool,
                arguments,
                "Invalid arguments"
            )

        # Payment-specific validation
        if tool == "payments.send":

            amount = arguments.get("amount")

            # Missing / wrong type
            if not isinstance(amount, (int, float)):
                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount"
                )

            # bool is technically an int in Python
            if isinstance(amount, bool):
                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount"
                )

            # NaN / infinity
            if not math.isfinite(amount):
                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Invalid payment amount"
                )

            # Zero or negative
            if amount <= 0:
                return self.deny(
                    agent,
                    tool,
                    arguments,
                    "Payment amount must be greater than zero"
                )

        # Find every applicable rule
        matches = [
            rule
            for rule in self.rules
            if self.matches(
                rule,
                tool,
                arguments
            )
        ]

        # Fail closed
        if not matches:
            return self.deny(
                agent,
                tool,
                arguments,
                "No matching policy"
            )

        # Strongest restriction wins
        strongest = max(
            matches,
            key=lambda rule:
                PRIORITY.get(
                    rule.get("action"),
                    PRIORITY["deny"]
                )
        )

        action = strongest.get("action")

        # Unknown policy action = deny
        if action not in PRIORITY:
            return self.deny(
                agent,
                tool,
                arguments,
                "Invalid policy action"
            )

        decision = Decision(
            action,
            f"Policy matched for {tool}"
        )

        self.log(
            agent,
            tool,
            arguments,
            decision
        )

        return decision