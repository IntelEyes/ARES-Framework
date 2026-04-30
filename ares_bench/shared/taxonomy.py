"""
ARES-Bench O/M/I Taxonomy.

Origin codes (O1-O8): root causes of SKC mismatches
Manifestation codes (M1-M8): how mismatches appear in agent behavior
Impact codes (I1-I7): consequences with severity levels
Cross-reference matrix: origin -> manifestation -> impact -> dimension
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Origin codes O1-O8
# ---------------------------------------------------------------------------
@dataclass
class OriginCode:
    code: str
    name: str
    definition: str
    primary_dimension: str  # S, K, C, R, or T


ORIGINS: Dict[str, OriginCode] = {
    "O1": OriginCode(
        "O1", "Missing Tool/Skill",
        "Agent lacks a required tool or analytical skill needed for the task "
        "(e.g., no YARA scanner, no packet capture capability).",
        "S",
    ),
    "O2": OriginCode(
        "O2", "Outdated Threat Intelligence",
        "Agent's threat knowledge base is stale; new TTPs, IOCs, or CVEs "
        "are absent from its knowledge context.",
        "K",
    ),
    "O3": OriginCode(
        "O3", "Incomplete Knowledge Coverage",
        "Agent has current but partial knowledge; key ATT&CK techniques or "
        "detection rules are missing from its training/context.",
        "K",
    ),
    "O4": OriginCode(
        "O4", "Blocked API/Integration",
        "Agent cannot access a required external system (SIEM, SOAR, sandbox, "
        "threat feed) due to capability restrictions.",
        "C",
    ),
    "O5": OriginCode(
        "O5", "Reasoning Degradation",
        "Agent's reasoning chain is corrupted by misleading context, prompt "
        "injection, or inherent hallucination tendencies.",
        "R",
    ),
    "O6": OriginCode(
        "O6", "Temporal Drift",
        "Time-dependent decay in agent reliability as threat landscape evolves "
        "and agent's training data ages.",
        "T",
    ),
    "O7": OriginCode(
        "O7", "Cross-Dimension Compound",
        "Multiple mismatch dimensions interact, creating emergent failures "
        "not predictable from individual dimensions.",
        "compound",
    ),
    "O8": OriginCode(
        "O8", "Cascade Propagation",
        "Mismatch in an upstream pipeline stage propagates and amplifies "
        "through downstream stages in multi-agent systems.",
        "cascade",
    ),
}

# ---------------------------------------------------------------------------
# Manifestation codes M1-M8
# ---------------------------------------------------------------------------
@dataclass
class ManifestationCode:
    code: str
    name: str
    definition: str
    observable_in: str  # where this manifests


MANIFESTATIONS: Dict[str, ManifestationCode] = {
    "M1": ManifestationCode(
        "M1", "Missed Detection",
        "Agent fails to identify a true positive threat indicator, IOC, or "
        "malicious behavior pattern present in the scenario.",
        "detection_output",
    ),
    "M2": ManifestationCode(
        "M2", "False Attribution",
        "Agent incorrectly attributes observed activity to wrong threat actor, "
        "campaign, or ATT&CK technique.",
        "attribution_output",
    ),
    "M3": ManifestationCode(
        "M3", "Hallucinated Indicator",
        "Agent fabricates IOCs, threat actors, or TTPs not present in the "
        "evidence, presenting them as real findings.",
        "enrichment_output",
    ),
    "M4": ManifestationCode(
        "M4", "Incomplete Triage",
        "Agent produces partial analysis, missing critical aspects of the "
        "incident (scope, affected systems, lateral movement).",
        "triage_output",
    ),
    "M5": ManifestationCode(
        "M5", "Wrong Severity Assessment",
        "Agent assigns incorrect severity/priority, leading to over- or "
        "under-reaction to the incident.",
        "severity_output",
    ),
    "M6": ManifestationCode(
        "M6", "Invalid Remediation",
        "Agent recommends containment/remediation actions that are ineffective, "
        "incomplete, or counterproductive.",
        "response_output",
    ),
    "M7": ManifestationCode(
        "M7", "Stale Context Application",
        "Agent applies outdated threat context, referencing deprecated IOCs "
        "or superseded attack patterns.",
        "context_output",
    ),
    "M8": ManifestationCode(
        "M8", "Cascade Amplification",
        "Error from upstream stage is amplified by downstream processing, "
        "e.g., hallucinated IOC triggers unnecessary blocking.",
        "pipeline_output",
    ),
}

# ---------------------------------------------------------------------------
# Impact codes I1-I7
# ---------------------------------------------------------------------------
@dataclass
class ImpactCode:
    code: str
    name: str
    definition: str
    severity: str  # low, medium, high, critical


IMPACTS: Dict[str, ImpactCode] = {
    "I1": ImpactCode(
        "I1", "Delayed Response",
        "Incident response is delayed but eventually correct; additional "
        "dwell time for attacker.",
        "low",
    ),
    "I2": ImpactCode(
        "I2", "Partial Blindness",
        "Some threat indicators are missed, reducing detection coverage "
        "but not completely failing.",
        "medium",
    ),
    "I3": ImpactCode(
        "I3", "Misguided Investigation",
        "Analyst time wasted pursuing false leads generated by the agent; "
        "real threat continues unaddressed.",
        "medium",
    ),
    "I4": ImpactCode(
        "I4", "Incorrect Containment",
        "Wrong assets isolated or wrong rules deployed, causing operational "
        "disruption without stopping the threat.",
        "high",
    ),
    "I5": ImpactCode(
        "I5", "Complete Miss",
        "Threat goes entirely undetected; agent provides false assurance "
        "of safety.",
        "critical",
    ),
    "I6": ImpactCode(
        "I6", "Cascading Failure",
        "Error propagates through multi-agent pipeline, compounding at "
        "each stage and producing systematically wrong output.",
        "critical",
    ),
    "I7": ImpactCode(
        "I7", "Trust Erosion",
        "Repeated inaccurate outputs erode analyst trust in the AI system, "
        "leading to manual override and reduced adoption.",
        "high",
    ),
}

# ---------------------------------------------------------------------------
# Cross-reference matrix
# ---------------------------------------------------------------------------
# Maps (origin, primary_delta_above_threshold) -> (likely_manifestations, likely_impacts)
CROSS_REFERENCE: Dict[str, Dict[str, Tuple[List[str], List[str]]]] = {
    # Origin -> { dominant_dimension -> ([manifestations], [impacts]) }
    "O1": {
        "S": (["M1", "M4"], ["I2", "I5"]),
    },
    "O2": {
        "K": (["M2", "M7"], ["I1", "I3"]),
        "T": (["M7", "M5"], ["I1", "I2"]),
    },
    "O3": {
        "K": (["M1", "M2", "M4"], ["I2", "I5"]),
    },
    "O4": {
        "C": (["M4", "M6"], ["I2", "I4"]),
    },
    "O5": {
        "R": (["M3", "M2", "M5"], ["I3", "I7"]),
    },
    "O6": {
        "T": (["M7", "M1"], ["I1", "I2"]),
    },
    "O7": {
        "compound": (["M1", "M3", "M4", "M5"], ["I4", "I5", "I7"]),
    },
    "O8": {
        "cascade": (["M8", "M3", "M6"], ["I6", "I4"]),
    },
}

# Severity ordering for selecting worst-case impact
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _dominant_dimension(delta_S: float, delta_K: float, delta_C: float,
                        delta_R: float, delta_T: float) -> str:
    """Return the dimension label with the highest mismatch."""
    dims = [
        ("S", delta_S),
        ("K", delta_K),
        ("C", delta_C),
        ("R", delta_R),
        ("T", delta_T),
    ]
    dims.sort(key=lambda x: x[1], reverse=True)
    return dims[0][0]


def _count_elevated(delta_S: float, delta_K: float, delta_C: float,
                    delta_R: float, delta_T: float,
                    threshold: float = 0.3) -> int:
    """Count how many dimensions exceed the threshold."""
    return sum(1 for d in [delta_S, delta_K, delta_C, delta_R, delta_T]
               if d > threshold)


def assign_taxonomy(
    delta_S: float,
    delta_K: float,
    delta_C: float,
    delta_R: float,
    delta_T: float,
    is_cascade: bool = False,
    agent_output: Optional[dict] = None,
    rng=None,
) -> Dict[str, str]:
    """Assign O/M/I taxonomy codes from mismatch vector and outputs.

    Uses the paper's cross-reference matrix to assign manifestations
    based on the DOMINANT mismatch dimension:

    - delta_S dominant -> M2 (Omission/False Attribution) ~71%, M5 ~18%, other ~11%
    - delta_K dominant -> M1 (Missed Detection) ~38%, M3 (Hallucinated) ~25%, M5 ~20%, other ~17%
    - delta_C dominant -> M5 (Wrong Severity/Paralysis) ~84%, M2 ~11%, other ~5%
    - delta_R dominant -> M4 (Incomplete Triage/Confabulation) ~42%, M6 (Invalid Remediation) ~16%, M3 ~22%, other ~20%

    Returns dict with keys: origin, manifestation, impact, severity,
    origin_name, manifestation_name, impact_name.
    """
    import random as _random
    _rng = rng if rng is not None else _random

    elevated = _count_elevated(delta_S, delta_K, delta_C, delta_R, delta_T)
    dominant = _dominant_dimension(delta_S, delta_K, delta_C, delta_R, delta_T)

    # Determine origin code
    if is_cascade:
        origin_code = "O8"
    elif elevated >= 3:
        origin_code = "O7"  # compound
    elif dominant == "S":
        origin_code = "O1"
    elif dominant == "K" and delta_T > 0.3:
        origin_code = "O2"  # outdated TI
    elif dominant == "K":
        origin_code = "O3"  # incomplete knowledge
    elif dominant == "C":
        origin_code = "O4"
    elif dominant == "R":
        origin_code = "O5"
    elif dominant == "T":
        origin_code = "O6"
    else:
        origin_code = "O7"

    # ---- Manifestation assignment using the paper's cross-reference matrix ----
    # Probabilistic assignment based on dominant dimension
    r_val = _rng.random() if hasattr(_rng, 'random') else _random.random()

    max_delta = max(delta_S, delta_K, delta_C, delta_R, delta_T)

    if max_delta < 0.05:
        # Near-zero mismatch: no real failure, assign benign M1 with low impact
        manifestation_code = "M1"
    elif dominant == "S":
        # delta_S dominant -> M2 (Omission) ~71%, M5 (Wrong Severity) ~18%, M1 ~8%, M4 ~3%
        if r_val < 0.71:
            manifestation_code = "M2"
        elif r_val < 0.89:
            manifestation_code = "M5"
        elif r_val < 0.97:
            manifestation_code = "M1"
        else:
            manifestation_code = "M4"
    elif dominant == "K":
        # delta_K dominant -> M1 (Missed Detection) ~38%, M3 (Hallucinated) ~25%,
        # M5 ~20%, M2 ~10%, M4 ~7%
        if r_val < 0.38:
            manifestation_code = "M1"
        elif r_val < 0.63:
            manifestation_code = "M3"
        elif r_val < 0.83:
            manifestation_code = "M5"
        elif r_val < 0.93:
            manifestation_code = "M2"
        else:
            manifestation_code = "M4"
    elif dominant == "C":
        # delta_C dominant -> M5 (Wrong Severity/Paralysis) ~84%, M2 ~11%, M6 ~5%
        if r_val < 0.84:
            manifestation_code = "M5"
        elif r_val < 0.95:
            manifestation_code = "M2"
        else:
            manifestation_code = "M6"
    elif dominant == "R":
        # delta_R dominant -> M4 (Confabulation) ~55%, M6 (Overclaiming) ~18%,
        # M3 ~15%, M2 ~8%, M5 ~4%
        if r_val < 0.55:
            manifestation_code = "M4"
        elif r_val < 0.73:
            manifestation_code = "M6"
        elif r_val < 0.88:
            manifestation_code = "M3"
        elif r_val < 0.96:
            manifestation_code = "M2"
        else:
            manifestation_code = "M5"
    elif dominant == "T":
        # Temporal drift -> M7 (Stale Context) ~60%, M1 ~25%, M2 ~15%
        if r_val < 0.60:
            manifestation_code = "M7"
        elif r_val < 0.85:
            manifestation_code = "M1"
        else:
            manifestation_code = "M2"
    else:
        # Compound / cascade
        if is_cascade:
            if r_val < 0.50:
                manifestation_code = "M8"
            elif r_val < 0.75:
                manifestation_code = "M3"
            else:
                manifestation_code = "M6"
        else:
            if r_val < 0.30:
                manifestation_code = "M1"
            elif r_val < 0.55:
                manifestation_code = "M3"
            elif r_val < 0.75:
                manifestation_code = "M4"
            else:
                manifestation_code = "M5"

    # ---- Impact assignment ----
    # Look up cross-reference for impact candidates
    origin_entry = CROSS_REFERENCE.get(origin_code, {})
    dim_key = ORIGINS[origin_code].primary_dimension
    if dim_key not in origin_entry:
        dim_key = next(iter(origin_entry)) if origin_entry else "S"

    if dim_key in origin_entry:
        _, candidate_i = origin_entry[dim_key]
    else:
        candidate_i = ["I2"]

    if max_delta > 0.8:
        impact_code = max(candidate_i,
                         key=lambda c: SEVERITY_ORDER.get(
                             IMPACTS[c].severity, 0))
    elif max_delta > 0.5:
        impact_code = candidate_i[0]
    else:
        impact_code = min(candidate_i,
                         key=lambda c: SEVERITY_ORDER.get(
                             IMPACTS[c].severity, 0))

    origin = ORIGINS[origin_code]
    manifestation = MANIFESTATIONS[manifestation_code]
    impact = IMPACTS[impact_code]

    return {
        "origin": origin_code,
        "origin_name": origin.name,
        "manifestation": manifestation_code,
        "manifestation_name": manifestation.name,
        "impact": impact_code,
        "impact_name": impact.name,
        "severity": impact.severity,
    }
