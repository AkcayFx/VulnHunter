"""CVSS v3.1 scoring utilities."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass
class CVSSVector:
    """Represents a CVSS v3.1 base metric vector."""

    attack_vector: str = "N"       # N(etwork), A(djacent), L(ocal), P(hysical)
    attack_complexity: str = "L"   # L(ow), H(igh)
    privileges_required: str = "N" # N(one), L(ow), H(igh)
    user_interaction: str = "N"    # N(one), R(equired)
    scope: str = "U"               # U(nchanged), C(hanged)
    confidentiality: str = "N"     # N(one), L(ow), H(igh)
    integrity: str = "N"           # N(one), L(ow), H(igh)
    availability: str = "N"        # N(one), L(ow), H(igh)

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}"
            f"/I:{self.integrity}/A:{self.availability}"
        )

    @classmethod
    def from_string(cls, vector_str: str) -> CVSSVector:
        parts: dict[str, str] = {}
        for segment in vector_str.replace("CVSS:3.1/", "").split("/"):
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k] = v
        return cls(
            attack_vector=parts.get("AV", "N"),
            attack_complexity=parts.get("AC", "L"),
            privileges_required=parts.get("PR", "N"),
            user_interaction=parts.get("UI", "N"),
            scope=parts.get("S", "U"),
            confidentiality=parts.get("C", "N"),
            integrity=parts.get("I", "N"),
            availability=parts.get("A", "N"),
        )


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def calculate_base_score(v: CVSSVector) -> float:
    """Compute CVSS v3.1 base score from a vector."""
    iss = 1.0 - ((1 - _CIA[v.confidentiality]) * (1 - _CIA[v.integrity]) * (1 - _CIA[v.availability]))

    if iss <= 0:
        return 0.0

    if v.scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    pr_table = _PR_CHANGED if v.scope == "C" else _PR_UNCHANGED
    exploitability = 8.22 * _AV[v.attack_vector] * _AC[v.attack_complexity] * pr_table[v.privileges_required] * _UI[v.user_interaction]

    if impact <= 0:
        return 0.0

    if v.scope == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    return math.ceil(raw * 10) / 10


def score_to_severity(score: float) -> str:
    """Map a CVSS score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def estimate_vector_from_vuln(title: str, description: str) -> CVSSVector:
    """Heuristic: guess a CVSS vector from vulnerability text.

    This is a rough approximation — real scoring should be done by an analyst
    or the LLM with proper context.
    """
    text = (title + " " + description).lower()

    av = "N"
    ac = "L"
    pr = "N"
    ui = "N"
    scope = "U"
    c = "L"
    i = "L"
    a = "N"

    if "remote code execution" in text or "rce" in text:
        c, i, a = "H", "H", "H"
        scope = "C"
    elif "sql injection" in text or "sqli" in text:
        c, i = "H", "H"
    elif "xss" in text or "cross-site scripting" in text:
        c, i = "L", "L"
        ui = "R"
    elif "denial of service" in text or "dos" in text:
        a = "H"
        c, i = "N", "N"
    elif "information disclosure" in text or "info leak" in text:
        c = "L"
        i, a = "N", "N"
    elif "authentication bypass" in text:
        c, i = "H", "H"
        pr = "N"
    elif "privilege escalation" in text:
        c, i = "H", "H"
        pr = "L"
        scope = "C"

    if "require" in text and "authentication" in text:
        pr = "L"
    if "local" in text and "access" in text:
        av = "L"

    return CVSSVector(
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=scope,
        confidentiality=c,
        integrity=i,
        availability=a,
    )
