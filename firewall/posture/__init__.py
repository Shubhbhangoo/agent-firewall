"""Continuous Security Posture (v2.0).

Evidence-backed posture states (unknown -> healthy -> degraded ->
suspicious -> high_risk -> compromised -> contained -> recovering ->
retired) with explainable transitions and a deterministic signal
engine. Never invented: posture moves only on recorded evidence.
"""

from firewall.posture.engine import (
    POSTURES,
    PostureEngine,
    PostureError,
    PostureSignal,
    PostureState,
    PostureTransition,
    _signal,
)

__all__ = [
    "POSTURES",
    "PostureEngine",
    "PostureError",
    "PostureSignal",
    "PostureState",
    "PostureTransition",
    "_signal",
]
