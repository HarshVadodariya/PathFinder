"""Shared constants and configuration objects for PathFinder."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields

INTERNET = "INTERNET"

SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
SEVERITY_RANK = {"Unknown": -1, "Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEV_COLORS = {
    "Critical": "#E5645B", "High": "#E8894F", "Medium": "#E3C04F",
    "Low": "#6BAE8B", "Informational": "#7C93B0", "Unknown": "#8A98A8",
}

ROLES = ["Web Server", "Application Server", "Database Server", "Workstation",
         "Domain Controller", "Internal Service", "Network Gateway"]
# Tier used only for *inferred* relationships (imported scans): traffic is assumed to flow tier N -> N+1.
ROLE_TIER = {"Web Server": 0, "Network Gateway": 0, "Workstation": 0,
             "Application Server": 1, "Internal Service": 1,
             "Database Server": 2, "Domain Controller": 2}
ROLE_DEFAULT_CRITICALITY = {"Web Server": 3, "Application Server": 4, "Database Server": 5,
                            "Workstation": 2, "Domain Controller": 5, "Internal Service": 3,
                            "Network Gateway": 3}
ZONES = ["DMZ", "Corporate LAN", "Internal", "Restricted"]
EXPOSURES = {"Internet-facing": 1.0, "Partner/VPN": 0.7, "Internal": 0.5, "Restricted": 0.3}

STATUS_CONFIDENCE = {"confirmed": 1.0, "manual_lab": 0.9, "potential": 0.5}
STATUS_LABELS = {"confirmed": "Confirmed", "manual_lab": "Manual lab finding", "potential": "Potential match"}
CATEGORIES = ["outdated_software", "exposed_service", "weak_access", "excessive_access",
              "critical_exposure", "misconfiguration"]
RELATIONSHIP_TYPES = ["CONNECTS_TO", "TRUSTS"]

# Risk score weights (sum = 1.0). See About page / README for the formula.
WEIGHTS = {"severity": 0.35, "criticality": 0.20, "sensitive": 0.05, "exposure": 0.20, "length": 0.20}


def risk_band(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


@dataclass
class RuleConfig:
    """Configurable transition rules and search limits for the attack-path engine."""
    start: str = INTERNET            # INTERNET or "host:<asset id>" (assumed-breach start)
    min_cvss: float = 4.0            # R2: minimum CVSS for a vulnerability to create a transition
    include_potential: bool = True   # R2: allow 'potential match' findings (confidence-penalised)
    include_unknown: bool = False    # R2: allow findings with unknown CVSS
    unknown_cvss_default: float = 5.0  # assumed CVSS when unknown findings are included
    allow_trust: bool = True         # R3: allow TRUSTS relationships as direct transitions
    max_transitions: int = 5         # limit: maximum host-to-host transitions per path
    max_edges: int = 20              # limit: maximum graph depth explored (edges)
    max_paths: int = 100             # limit: maximum paths returned

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict | None) -> "RuleConfig":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (d or {}).items() if k in known})
