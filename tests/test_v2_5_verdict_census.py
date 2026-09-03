"""v2.5 -- the verdict census, and the hole it was hiding.

``AUTHORIZATION_UNIQUENESS`` claimed that "an authorization verdict is
constructed only inside the authorization boundary". In v2.4 it checked
that claim at *module* granularity: ``firewall/sdk.py`` is an owner, so
every construction inside it was waved through. ``MODEL_NON_AUTHORITY``
covered the gate chain, but only functions literally named ``_gate_*``.

Between them was a hole shaped like a name prefix. This was appended to
``FirewallSDK`` and the whole 15-invariant suite reported
``8 holds, 0 violated``::

    def _fast_path_verdict(self, action, request):
        return AuthorizationResult(
            allowed=True,
            reason="fast_path",
            action=action,
        )

A literal ``True``, inside the class that owns the boundary, invisible to
both structural invariants -- exactly the second authorization path the
Prime Directive forbids.

The census now runs at function granularity and pins three claims. Every
test below is a negative control on one of them, run against a synthetic
package tree so the *check* is what is under test rather than the current
contents of the real one. The two real-tree tests at the end assert that
the declared allowlist still matches the code it describes.

What these tests do NOT establish: that an *existing* forwarding site is
safe. ``_withhold_on_degraded_dependencies`` is trusted here because its
verdict comes from ``effective_verdict``, which can only return
``(result.allowed, None)`` or ``(False, reason)`` -- a semantic argument,
checked by tests in ``test_continuous_auth.py``, not by this census. A
hostile rewrite inside a declared site passes claim 2 by construction;
claim 3 catches it only if the rewrite mints an allow from a *literal*.
The census closes "a new place appeared and nobody looked", not "the
declared places are correct".
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Optional

import pytest

from firewall.invariants import source, static
from firewall.invariants.model import InvariantStatus

# A faithful miniature of ``firewall/authorization.py``: the private
# factory, the denials, and the single allow origin.
AUTHORIZATION = '''
from dataclasses import dataclass


@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str


def _result(capability, action, allowed, reason):
    return AuthorizationResult(allowed=allowed, reason=reason)


def authorize(capability, action, request):
    if capability is None:
        return _result(capability, action, False, "invalid_capability")

    return _result(capability, action, True, "authorized")
'''

# ...and of ``firewall/sdk.py``: forwards, never originates.
SDK = '''
from firewall.authorization import AuthorizationResult, authorize


class FirewallSDK:
    def _trace_result(self, result):
        return AuthorizationResult(
            allowed=result.allowed,
            reason=result.reason,
        )

    def _gate_transaction(self, capability, action, request):
        return None

    def authorize(self, capability, action, request):
        return AuthorizationResult(allowed=False, reason="denied")
'''


def tree(tmp_path: Path, sdk: str, authorization: str = AUTHORIZATION) -> Path:
    """Write a synthetic ``firewall`` package and return its root."""

    root = tmp_path / "firewall"
    root.mkdir()
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "authorization.py").write_text(
        textwrap.dedent(authorization),
        encoding="utf-8",
    )
    (root / "sdk.py").write_text(textwrap.dedent(sdk), encoding="utf-8")

    return root


def census(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
) -> object:
    """Run the census against ``root`` instead of the real package."""

    monkeypatch.setattr(source, "package_root", lambda: root)

    return static.check_authorization_uniqueness()


def findings_of(result: object) -> str:
    return " | ".join(getattr(result, "findings", ()))


class TestTheCensusAcceptsTheShapeItDescribes:
    """The miniature must pass, or every failure below proves nothing."""

    def test_a_faithful_miniature_holds(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        result = census(monkeypatch, tree(tmp_path, SDK))

        assert result.status is InvariantStatus.HOLDS, findings_of(result)
        assert result.details["forwarding_sites"] == 3
        assert result.details["denial_sites"] == 2

    def test_a_reordered_factory_is_still_read_correctly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``allowed``'s position is read from the definition.

        A hard-coded index would inspect ``reason`` here, find a string
        that is not a literal ``False``, and report findings for all
        nine call sites -- or worse, inspect ``capability`` and pass.
        """

        moved = AUTHORIZATION.replace(
            "def _result(capability, action, allowed, reason):",
            "def _result(allowed, capability, action, reason):",
        ).replace(
            "_result(capability, action, False, \"invalid_capability\")",
            "_result(False, capability, action, \"invalid_capability\")",
        ).replace(
            "_result(capability, action, True, \"authorized\")",
            "_result(True, capability, action, \"authorized\")",
        )

        result = census(
            monkeypatch,
            tree(tmp_path, SDK, authorization=moved),
        )

        assert result.status is InvariantStatus.HOLDS, findings_of(result)


class TestTheHoleThatWasThere:
    """The v2.5 finding, reproduced and then closed."""

    FAST_PATH = SDK + '''
    def _fast_path_verdict(self, action, request):
        return AuthorizationResult(
            allowed=True,
            reason="fast_path",
        )
'''

    def test_a_non_gate_helper_that_allows_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        result = census(monkeypatch, tree(tmp_path, self.FAST_PATH))

        assert result.status is InvariantStatus.VIOLATED
        assert "_fast_path_verdict" in findings_of(result)

    def test_the_gate_census_alone_does_not_see_it(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Why the strengthening was needed, pinned as a limitation.

        ``MODEL_NON_AUTHORITY`` inspects functions named ``_gate_*``. On
        the same hostile tree it reports ``HOLDS``. That is not a bug in
        it -- its statement is about the gate chain -- but it is the
        reason a module-granularity companion check was not enough.
        """

        monkeypatch.setattr(
            source,
            "package_root",
            lambda: tree(tmp_path, self.FAST_PATH),
        )

        assert (
            static.check_model_non_authority().status
            is InvariantStatus.HOLDS
        )

    def test_a_forwarded_subsystem_verdict_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A risk score reaching ``allowed`` need not be a literal."""

        hostile = SDK + '''
    def _risk_verdict(self, action, request):
        return AuthorizationResult(
            allowed=self.risk.below_threshold(request),
            reason="risk_ok",
        )
'''
        result = census(monkeypatch, tree(tmp_path, hostile))

        assert result.status is InvariantStatus.VIOLATED
        assert "_risk_verdict" in findings_of(result)

    def test_a_closure_is_its_own_owner(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Hiding the construction inside a declared site's body.

        ``_trace_result`` is a declared forwarding site. A closure
        defined inside it is attributed to the closure, so borrowing the
        enclosing name does not borrow its permission.
        """

        hostile = SDK.replace(
            "    def _gate_transaction(self, capability, action, request):",
            '''    def _trace_result_inner(self, result):
        def smuggle():
            return AuthorizationResult(allowed=True, reason="inner")

        return smuggle()

    def _gate_transaction(self, capability, action, request):''',
        )

        result = census(monkeypatch, tree(tmp_path, hostile))

        assert result.status is InvariantStatus.VIOLATED
        assert "in smuggle" in findings_of(result)

    def test_an_unresolvable_argument_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``**kwargs`` is not provably a denial, so it is not one."""

        hostile = SDK + '''
    def _splat_verdict(self, **fields):
        return AuthorizationResult(**fields)
'''
        result = census(monkeypatch, tree(tmp_path, hostile))

        assert result.status is InvariantStatus.VIOLATED
        assert "not provably a denial" in findings_of(result)

    def test_a_module_level_construction_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An owner module is not a blanket permission."""

        hostile = SDK + '\nPRESET = AuthorizationResult(allowed=True, reason="preset")\n'
        result = census(monkeypatch, tree(tmp_path, hostile))

        assert result.status is InvariantStatus.VIOLATED
        assert "in <module>" in findings_of(result)


class TestTheAllowOriginIsExactlyOne:
    """Claim 3: not "at most one", and not "at least one"."""

    def test_a_second_allow_branch_inside_the_boundary_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The case claim 2 structurally cannot see.

        ``authorize`` is a declared site, so a second allow *inside* it
        is invisible to the forwarding-site check -- the function is
        already permitted to pass a non-literal ``False``. Counting
        origins is what catches it: an early-return fast path added to
        the canonical boundary is still a second place an allow is
        minted.
        """

        doubled = AUTHORIZATION.replace(
            "    if capability is None:",
            '''    if getattr(request, "trusted", False):
        return _result(capability, action, True, "trusted_fast_path")

    if capability is None:''',
        )
        result = census(
            monkeypatch,
            tree(tmp_path, SDK, authorization=doubled),
        )

        assert result.status is InvariantStatus.VIOLATED
        assert "exactly one place" in result.reason
        assert len(result.findings) == 2

    def test_a_second_origin_outside_the_allowlist_is_named(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Claim 2 fires first here, and reports the better finding.

        A new allow in a *new* function trips the forwarding-site check
        before the origin count is reached, which is the preferable
        order: the finding names the function to delete rather than
        reporting an arithmetic mismatch.
        """

        doubled = AUTHORIZATION + '''
def authorize_fast(capability, action, request):
    return _result(capability, action, True, "authorized_fast")
'''
        result = census(
            monkeypatch,
            tree(tmp_path, SDK, authorization=doubled),
        )

        assert result.status is InvariantStatus.VIOLATED
        assert "authorize_fast" in findings_of(result)

    def test_an_origin_in_the_wrong_function_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        moved = AUTHORIZATION.replace("def authorize(", "def decide(")
        result = census(
            monkeypatch,
            tree(tmp_path, SDK, authorization=moved),
        )

        assert result.status is InvariantStatus.VIOLATED

    def test_no_origin_at_all_is_a_finding_not_a_pass(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The guard against passing vacuously.

        If the allow origin is refactored into a shape the census cannot
        see, the census must say so. A structural check that reports
        ``HOLDS`` because it found nothing to check is worse than no
        check: it is a false assurance.
        """

        blind = AUTHORIZATION.replace(
            "_result(capability, action, True, \"authorized\")",
            "_result(capability, action, verdict, \"authorized\")",
        )
        result = census(
            monkeypatch,
            tree(tmp_path, SDK, authorization=blind),
        )

        assert result.status is InvariantStatus.VIOLATED
        assert "no site in the package passes a literal True" in (
            findings_of(result)
        )


class TestTheOwnerCensusStillHolds:
    """Claim 1, the v2.4 behaviour, unchanged."""

    def test_a_construction_outside_the_owners_is_a_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tree(tmp_path, SDK)
        (root / "risk.py").write_text(
            textwrap.dedent(
                '''
                from firewall.authorization import AuthorizationResult


                def score(request):
                    return AuthorizationResult(
                        allowed=False,
                        reason="low_risk",
                    )
                '''
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(source, "package_root", lambda: root)
        result = static.check_authorization_uniqueness()

        assert result.status is InvariantStatus.VIOLATED
        assert "outside the authorization boundary" in findings_of(result)

    def test_an_aliased_import_does_not_evade_the_census(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tree(tmp_path, SDK)
        (root / "twin.py").write_text(
            textwrap.dedent(
                '''
                from firewall.authorization import (
                    AuthorizationResult as Verdict,
                )


                def simulate(request):
                    return Verdict(allowed=False, reason="simulated")
                '''
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(source, "package_root", lambda: root)
        result = static.check_authorization_uniqueness()

        assert result.status is InvariantStatus.VIOLATED
        assert "firewall/twin.py" in findings_of(result)


class TestTheAllowlistDescribesTheRealCode:
    """The allowlist is only useful while it matches the package."""

    def test_the_real_package_holds(self) -> None:
        result = static.check_authorization_uniqueness()

        assert result.status is InvariantStatus.HOLDS, findings_of(result)
        assert result.details["denial_sites"] >= 50
        assert (
            static.ALLOW_ORIGIN
            == ("firewall/authorization.py", "authorize")
        )

    def test_every_declared_forwarding_site_is_exercised(self) -> None:
        """No stale entries.

        A declared site that no longer forwards anything is a standing
        permission for a function that may since have changed purpose,
        so the count is asserted rather than the mere absence of
        findings.
        """

        result = static.check_authorization_uniqueness()

        assert result.details["forwarding_sites"] == len(
            static.VERDICT_FORWARDING_SITES
        )

    def test_each_declared_site_carries_a_reason(self) -> None:
        for key, reason in static.VERDICT_FORWARDING_SITES.items():
            assert len(reason) > 40, key


class TestTheCensusHelpers:
    """The AST helpers, exercised directly."""

    def test_call_owners_attributes_the_innermost_function(self) -> None:
        import ast

        module = ast.parse(
            textwrap.dedent(
                '''
                def outer():
                    def inner():
                        f()
                    g()
                h()
                '''
            )
        )
        owners = source.call_owners(module)
        by_name = {
            source.called_name(call): owners.get(id(call))
            for call in source.walk_calls(module)
        }

        assert by_name == {"f": "inner", "g": "outer", "h": None}

    def test_parameter_index_reads_the_signature(self) -> None:
        import ast

        module = ast.parse("def f(a, allowed, b): pass")
        function = next(iter(source.function_defs(module)))

        assert source.parameter_index(function, "allowed") == 1
        assert source.parameter_index(function, "missing") is None

    def test_argument_resolution_prefers_the_keyword(self) -> None:
        import ast

        call = ast.parse("f(1, 2, allowed=False)").body[0].value
        argument = source.argument_by_name_or_position(call, "allowed", 0)

        assert source.is_literal_false(argument)

    def test_argument_resolution_reports_an_absent_position(self) -> None:
        import ast

        call = ast.parse("f(1)").body[0].value

        assert (
            source.argument_by_name_or_position(call, "allowed", 2)
            is None
        )
