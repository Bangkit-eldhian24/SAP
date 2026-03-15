"""
SAPT CVSS Score Calculator — Basic CVSS v3.1 scoring helper.
"""

from __future__ import annotations

from typing import Optional


def calculate_cvss_base(
    attack_vector: str = "N",        # N=Network, A=Adjacent, L=Local, P=Physical  
    attack_complexity: str = "L",     # L=Low, H=High
    privileges_required: str = "N",   # N=None, L=Low, H=High
    user_interaction: str = "N",      # N=None, R=Required
    scope: str = "U",                 # U=Unchanged, C=Changed
    confidentiality: str = "H",       # N=None, L=Low, H=High
    integrity: str = "H",             # N=None, L=Low, H=High
    availability: str = "N",          # N=None, L=Low, H=High
) -> float:
    """Calculate CVSS v3.1 base score (simplified)."""
    
    # Attack vector weights
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}
    
    av = av_weights.get(attack_vector, 0.85)
    ac = ac_weights.get(attack_complexity, 0.77)
    pr = (pr_weights_changed if scope == "C" else pr_weights_unchanged).get(privileges_required, 0.85)
    ui = ui_weights.get(user_interaction, 0.85)
    
    c = cia_weights.get(confidentiality, 0.0)
    i = cia_weights.get(integrity, 0.0)
    a = cia_weights.get(availability, 0.0)
    
    # ISS = 1 - [(1-C) × (1-I) × (1-A)]
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    if iss <= 0:
        return 0.0
    
    # Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    
    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    if impact <= 0:
        return 0.0
    
    if scope == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)
    
    return round(score * 10) / 10


def severity_from_score(score: float) -> str:
    """Get severity label from CVSS score."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "info"
