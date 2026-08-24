from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
from typing import Any, Optional

from firewall.namespace import matches


DEFAULT_CHAIN_ID = "default"


class SemanticChainError(Exception):
    """Base semantic-chain error."""


class SemanticChainDenied(SemanticChainError):
    """Raised when a semantic chain would complete a denied outcome."""


@dataclass(frozen=True)
class SemanticRule:
    """
    Deterministic semantic workflow rule.

    A rule matches an ordered action sequence over one resource
    identity. Rules with allowed=False mark a protected workflow.
    A matching allowed=True rule explicitly permits that workflow.
    """

    outcome: str
    sequence: tuple[str, ...]
    resource_key: str = "account"
    allowed: bool = False
    capability: Optional[str] = None
    resource_value: Any = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.outcome, str)
            or not self.outcome.strip()
        ):
            raise ValueError(
                "outcome must be a non-empty string"
            )

        if not isinstance(
            self.sequence,
            tuple,
        ):
            object.__setattr__(
                self,
                "sequence",
                tuple(self.sequence),
            )

        if not self.sequence:
            raise ValueError(
                "sequence must not be empty"
            )

        for action in self.sequence:
            if (
                not isinstance(action, str)
                or not action.strip()
            ):
                raise ValueError(
                    "sequence actions must be non-empty strings"
                )

        if (
            not isinstance(self.resource_key, str)
            or not self.resource_key.strip()
        ):
            raise ValueError(
                "resource_key must be a non-empty string"
            )

        if not isinstance(
            self.allowed,
            bool,
        ):
            raise TypeError(
                "allowed must be a bool"
            )

        if self.capability is not None:
            if (
                not isinstance(self.capability, str)
                or not self.capability.strip()
            ):
                raise ValueError(
                    "capability must be a non-empty string"
                )


@dataclass(frozen=True)
class SemanticActionRecord:
    agent: str
    chain_id: str
    action: str
    request: dict[str, Any]
    capability_fingerprint: str
    capability: str
    resources: dict[str, Any]
    amount: float
    index: int


@dataclass(frozen=True)
class SemanticDeniedRecord:
    agent: str
    chain_id: str
    action: str
    request: dict[str, Any]
    capability_fingerprint: str
    capability: str
    outcome: str
    resource_key: str
    resource_value: Any


@dataclass(frozen=True)
class SemanticChainSnapshot:
    agent: str
    chain_id: str
    actions: tuple[SemanticActionRecord, ...]
    capability_fingerprints: tuple[str, ...]
    stages: tuple[str, ...]
    terminal_outcomes: tuple[str, ...]
    total_amount: float
    denied: tuple[SemanticDeniedRecord, ...]


class SemanticChainContext:
    """
    Runtime semantic state for deterministic tool-chain checks.

    State is scoped by agent + chain_id. Successful primitive
    authorizations are recorded atomically with semantic checks.
    """

    def __init__(
        self,
        *,
        agent: str,
        rules: Optional[
            tuple[SemanticRule, ...]
        ] = None,
        default_chain_id: str = DEFAULT_CHAIN_ID,
    ) -> None:
        if (
            not isinstance(agent, str)
            or not agent.strip()
        ):
            raise ValueError(
                "agent must be a non-empty string"
            )

        if (
            not isinstance(default_chain_id, str)
            or not default_chain_id.strip()
        ):
            raise ValueError(
                "default_chain_id must be a non-empty string"
            )

        self.agent = agent
        self.default_chain_id = default_chain_id

        self.rules = tuple(
            rules or ()
        )

        for rule in self.rules:
            if not isinstance(
                rule,
                SemanticRule,
            ):
                raise TypeError(
                    "rules must contain SemanticRule values"
                )

        self._chains: dict[
            tuple[str, str],
            list[SemanticActionRecord],
        ] = {}

        self._denied: dict[
            tuple[str, str],
            list[SemanticDeniedRecord],
        ] = {}

        self._lock = RLock()

    # ========================================================
    # Validation
    # ========================================================

    @staticmethod
    def _validate_text(
        value: str,
        name: str,
    ) -> None:
        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise ValueError(
                f"{name} must be a non-empty string"
            )

    def _effective_chain_id(
        self,
        chain_id: Optional[str],
    ) -> str:
        if chain_id is None:
            return self.default_chain_id

        self._validate_text(
            chain_id,
            "chain_id",
        )

        return chain_id

    # ========================================================
    # Resource extraction
    # ========================================================

    @classmethod
    def _extract_value(
        cls,
        data: Any,
        resource_key: str,
    ) -> Any:
        if isinstance(
            data,
            dict,
        ):
            if resource_key in data:
                return data[resource_key]

            for key in sorted(
                data.keys(),
                key=str,
            ):
                value = cls._extract_value(
                    data[key],
                    resource_key,
                )

                if value is not None:
                    return value

        elif isinstance(
            data,
            (
                list,
                tuple,
            ),
        ):
            for item in data:
                value = cls._extract_value(
                    item,
                    resource_key,
                )

                if value is not None:
                    return value

        return None

    @classmethod
    def extract_resources(
        cls,
        request: dict[str, Any],
        rules: tuple[SemanticRule, ...],
    ) -> dict[str, Any]:
        resources: dict[str, Any] = {}

        for key in sorted(
            {
                rule.resource_key
                for rule in rules
            }
        ):
            value = cls._extract_value(
                request,
                key,
            )

            if value is not None:
                resources[key] = value

        return resources

    @staticmethod
    def _amount(
        request: dict[str, Any],
    ) -> float:
        value = request.get(
            "amount",
            0,
        )

        if isinstance(value, bool):
            return 0.0

        if isinstance(
            value,
            (int, float),
        ):
            if value < 0:
                return 0.0

            return float(value)

        return 0.0

    # ========================================================
    # Rule matching
    # ========================================================

    @staticmethod
    def _rule_capability_matches(
        rule: SemanticRule,
        records: tuple[
            SemanticActionRecord,
            ...
        ],
    ) -> bool:
        if rule.capability is None:
            return True

        return all(
            matches(
                rule.capability,
                record.capability,
            )
            for record in records
        )

    @staticmethod
    def _sequence_resource(
        rule: SemanticRule,
        records: tuple[
            SemanticActionRecord,
            ...
        ],
    ) -> tuple[bool, Any]:
        value = None
        found = False

        for record in records:
            if (
                rule.resource_key
                not in record.resources
            ):
                continue

            current = record.resources[
                rule.resource_key
            ]

            if not found:
                value = current
                found = True
                continue

            if current != value:
                return False, None

        return found, value

    @classmethod
    def _matches_rule(
        cls,
        rule: SemanticRule,
        records: tuple[
            SemanticActionRecord,
            ...
        ],
    ) -> tuple[bool, Any]:
        if len(records) < len(
            rule.sequence
        ):
            return False, None

        candidate = records[
            -len(rule.sequence) :
        ]

        if tuple(
            record.action
            for record in candidate
        ) != rule.sequence:
            return False, None

        if not cls._rule_capability_matches(
            rule,
            candidate,
        ):
            return False, None

        resource_found, resource_value = (
            cls._sequence_resource(
                rule,
                candidate,
            )
        )

        if not resource_found:
            return False, None

        if (
            rule.resource_value is not None
            and resource_value != rule.resource_value
        ):
            return False, None

        return True, resource_value

    # ========================================================
    # Atomic authorize + record
    # ========================================================

    def authorize_and_record(
        self,
        *,
        agent: str,
        action: str,
        request: dict[str, Any],
        capability_fingerprint: str,
        capability: str,
        chain_id: Optional[str] = None,
    ) -> None:
        if agent != self.agent:
            raise ValueError(
                "semantic context agent mismatch"
            )

        self._validate_text(
            action,
            "action",
        )
        self._validate_text(
            capability_fingerprint,
            "capability_fingerprint",
        )
        self._validate_text(
            capability,
            "capability",
        )

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        effective_chain_id = (
            self._effective_chain_id(
                chain_id
            )
        )

        key = (
            agent,
            effective_chain_id,
        )

        with self._lock:
            chain = self._chains.setdefault(
                key,
                [],
            )

            record = SemanticActionRecord(
                agent=agent,
                chain_id=effective_chain_id,
                action=action,
                request=deepcopy(request),
                capability_fingerprint=(
                    capability_fingerprint
                ),
                capability=capability,
                resources=self.extract_resources(
                    request,
                    self.rules,
                ),
                amount=self._amount(
                    request
                ),
                index=len(chain),
            )

            candidate = tuple(
                [
                    *chain,
                    record,
                ]
            )

            denied_match = None
            allow_match = None

            for rule in self.rules:
                matched, resource_value = (
                    self._matches_rule(
                        rule,
                        candidate,
                    )
                )

                if not matched:
                    continue

                if rule.allowed:
                    allow_match = (
                        rule,
                        resource_value,
                    )
                else:
                    denied_match = (
                        rule,
                        resource_value,
                    )

            if (
                denied_match is not None
                and allow_match is None
            ):
                rule, resource_value = denied_match

                denied_record = SemanticDeniedRecord(
                    agent=agent,
                    chain_id=effective_chain_id,
                    action=action,
                    request=deepcopy(request),
                    capability_fingerprint=(
                        capability_fingerprint
                    ),
                    capability=capability,
                    outcome=rule.outcome,
                    resource_key=rule.resource_key,
                    resource_value=resource_value,
                )

                self._denied.setdefault(
                    key,
                    [],
                ).append(
                    denied_record
                )

                raise SemanticChainDenied(
                    rule.outcome
                )

            chain.append(
                record
            )

    # ========================================================
    # Snapshot
    # ========================================================

    def snapshot(
        self,
        *,
        chain_id: Optional[str] = None,
    ) -> tuple[SemanticChainSnapshot, ...]:
        with self._lock:
            if chain_id is not None:
                effective_chain_id = (
                    self._effective_chain_id(
                        chain_id
                    )
                )

                keys = [
                    (
                        self.agent,
                        effective_chain_id,
                    )
                ]
            else:
                keys = sorted(
                    set(self._chains.keys())
                    | set(self._denied.keys())
                )

            snapshots = []

            for key in keys:
                actions = tuple(
                    self._chains.get(
                        key,
                        [],
                    )
                )

                denied = tuple(
                    self._denied.get(
                        key,
                        [],
                    )
                )

                snapshots.append(
                    SemanticChainSnapshot(
                        agent=key[0],
                        chain_id=key[1],
                        actions=actions,
                        capability_fingerprints=tuple(
                            sorted(
                                {
                                    action.capability_fingerprint
                                    for action in actions
                                }
                            )
                        ),
                        stages=tuple(
                            action.action
                            for action in actions
                        ),
                        terminal_outcomes=tuple(
                            denied_record.outcome
                            for denied_record in denied
                        ),
                        total_amount=sum(
                            action.amount
                            for action in actions
                        ),
                        denied=denied,
                    )
                )

            return tuple(
                snapshots
            )

    # ========================================================
    # Reset
    # ========================================================

    def reset(
        self,
        *,
        chain_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            if chain_id is None:
                self._chains.clear()
                self._denied.clear()
                return

            effective_chain_id = (
                self._effective_chain_id(
                    chain_id
                )
            )

            key = (
                self.agent,
                effective_chain_id,
            )

            self._chains.pop(
                key,
                None,
            )
            self._denied.pop(
                key,
                None,
            )
