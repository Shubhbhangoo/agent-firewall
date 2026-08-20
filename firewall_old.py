import yaml
import json
import math
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

        self.rules = data.get("rules", [])

    def log(self, agent, tool, arguments, decision):

        entry = {
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

        # Exact path matching
        if "path" in rule:
            if arguments.get("path") != rule["path"]:
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