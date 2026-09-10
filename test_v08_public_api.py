from __future__ import annotations


EXPECTED_EXPORTS = {
    "Firewall",
    "Decision",

    "FirewallSDK",

    "Capability",
    "CapabilityVerifier",
    "capability_fingerprint",
    "generate_capability_key_pair",
    "sign_capability",

    "Delegation",

    "RevocationRegistry",
    "RevocationRecord",
    "RevocationError",
    "AlreadyRevokedError",
    "InvalidFingerprintError",
    "RevokedCapabilityError",

    "LifecycleEvent",
    "LifecycleEventType",
    "LifecycleRecorder",

    "LifecycleStore",
    "LifecycleStoreError",
    "LifecycleStoreClosedError",
    "SQLiteLifecycleStore",
}


def test_v08_public_api_exports():
    import firewall

    for name in EXPECTED_EXPORTS:
        assert hasattr(
            firewall,
            name,
        ), f"firewall.{name} is not exported"


def test_public_api_matches_all():
    import firewall

    assert set(
        firewall.__all__
    ) == EXPECTED_EXPORTS


def test_public_api_contains_no_duplicates():
    import firewall

    assert len(
        firewall.__all__
    ) == len(
        set(firewall.__all__)
    )


def test_public_api_exports_are_not_none():
    import firewall

    for name in firewall.__all__:
        assert getattr(
            firewall,
            name,
        ) is not None


def test_engine_exports_preserved():
    import firewall

    assert firewall.Firewall is not None
    assert firewall.Decision is not None


def test_sdk_export_is_correct_class():
    import firewall
    from firewall.sdk import FirewallSDK

    assert firewall.FirewallSDK is FirewallSDK


def test_capability_exports_are_correct():
    import firewall

    from firewall.capability import (
        Capability,
        CapabilityVerifier,
        capability_fingerprint,
        generate_capability_key_pair,
        sign_capability,
    )

    assert firewall.Capability is Capability
    assert (
        firewall.CapabilityVerifier
        is CapabilityVerifier
    )
    assert (
        firewall.capability_fingerprint
        is capability_fingerprint
    )
    assert (
        firewall.generate_capability_key_pair
        is generate_capability_key_pair
    )
    assert (
        firewall.sign_capability
        is sign_capability
    )


def test_delegation_export_is_correct():
    import firewall
    from firewall.delegation import Delegation

    assert firewall.Delegation is Delegation


def test_revocation_exports_are_correct():
    import firewall

    from firewall.revocation import (
        RevocationRegistry,
        RevocationRecord,
        RevocationError,
        AlreadyRevokedError,
        InvalidFingerprintError,
        RevokedCapabilityError,
    )

    assert (
        firewall.RevocationRegistry
        is RevocationRegistry
    )

    assert (
        firewall.RevocationRecord
        is RevocationRecord
    )

    assert (
        firewall.RevocationError
        is RevocationError
    )

    assert (
        firewall.AlreadyRevokedError
        is AlreadyRevokedError
    )

    assert (
        firewall.InvalidFingerprintError
        is InvalidFingerprintError
    )

    assert (
        firewall.RevokedCapabilityError
        is RevokedCapabilityError
    )


def test_lifecycle_exports_are_correct():
    import firewall

    from firewall.lifecycle import (
        LifecycleEvent,
        LifecycleEventType,
        LifecycleRecorder,
    )

    assert (
        firewall.LifecycleEvent
        is LifecycleEvent
    )

    assert (
        firewall.LifecycleEventType
        is LifecycleEventType
    )

    assert (
        firewall.LifecycleRecorder
        is LifecycleRecorder
    )


def test_lifecycle_store_exports_are_correct():
    import firewall

    from firewall.lifecycle_store import (
        LifecycleStore,
        LifecycleStoreError,
        LifecycleStoreClosedError,
        SQLiteLifecycleStore,
    )

    assert (
        firewall.LifecycleStore
        is LifecycleStore
    )

    assert (
        firewall.LifecycleStoreError
        is LifecycleStoreError
    )

    assert (
        firewall.LifecycleStoreClosedError
        is LifecycleStoreClosedError
    )

    assert (
        firewall.SQLiteLifecycleStore
        is SQLiteLifecycleStore
    )


def test_star_import_surface():
    namespace = {}

    exec(
        "from firewall import *",
        namespace,
    )

    for name in EXPECTED_EXPORTS:
        assert name in namespace


def test_star_import_does_not_expose_private_names():
    namespace = {}

    exec(
        "from firewall import *",
        namespace,
    )

    public_names = {
        key
        for key in namespace
        if not key.startswith("__")
    }

    assert public_names == EXPECTED_EXPORTS