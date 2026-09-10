"""Security Lab 2.0 (v2.0).

Automated security evaluation over verified network graphs: attack
surface, dangers, sensitive resources, containment opportunities,
policy weaknesses, and supply-chain status, plus counterfactual
questions answered by the isolated simulator.
"""

from firewall.lab.engine import (
    LabError,
    SecurityLab,
)

__all__ = [
    "LabError",
    "SecurityLab",
]
