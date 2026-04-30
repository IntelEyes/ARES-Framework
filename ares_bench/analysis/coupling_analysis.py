"""
Empirical coupling (mu) analysis for the three-stage AutoGen pipeline.

Referenced in Paper 3 Section IV-G (cascade model limitations). For each
AUT-2 record in SOCAgentFailure-1K, reconstructs per-stage ARS using the
AutoGen simulator's stage mismatch decomposition, identifies the weakest
non-terminal stage, and reports the max outgoing coupling mu*_max that
appears in the Theorem 1 bound.

Coupling matrix (from services/agents/autogen_agent/main.py):
    triage -> enrich      : mu = 0.8
    triage -> recommend   : mu = 0.3
    enrich -> recommend   : mu = 0.9
    recommend             : terminal (no outgoing edge)

Theorem 1 bound: ARS_cas <= 1 - mu*_max * (1 - r*)
  r*           = min ARS across non-terminal stages
  mu*_max      = max coupling on any outgoing edge of the r*-achieving stage

Output: ares_bench/output/coupling_analysis.json
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "output" / "socagentfailure_1k.jsonl"
OUT = ROOT / "output" / "coupling_analysis.json"

# Coupling matrix baked into the AutoGen simulator. Stages:
#   0 = triage, 1 = enrich, 2 = recommend
COUPLING = {
    ("triage", "enrich"): 0.8,
    ("triage", "recommend"): 0.3,
    ("enrich", "recommend"): 0.9,
}
OUTGOING = {
    "triage": [0.8, 0.3],
    "enrich": [0.9],
    "recommend": [],
}

# Weight vectors per threat class (from shared.shared_models)
WEIGHTS = {
    "T1": {"S": 0.18, "K": 0.35, "C": 0.22, "R": 0.17, "T": 0.08},
    "T2": {"S": 0.21, "K": 0.31, "C": 0.19, "R": 0.21, "T": 0.08},
    "T3": {"S": 0.15, "K": 0.27, "C": 0.36, "R": 0.15, "T": 0.07},
    "T4": {"S": 0.32, "K": 0.21, "C": 0.28, "R": 0.12, "T": 0.07},
    "T5": {"S": 0.14, "K": 0.38, "C": 0.18, "R": 0.24, "T": 0.06},
}


def stage_ars(threat_type: str, dS: float, dK: float, dC: float, stage: str) -> float:
    """Reproduces the stage-specific mismatch weighting from autogen_agent/main.py."""
    if stage == "triage":
        m = {"S": dS, "K": dK * 0.3, "C": 0.0, "R": 0.0, "T": 0.0}
    elif stage == "enrich":
        m = {"S": 0.0, "K": dK, "C": dC * 0.3, "R": 0.0, "T": 0.0}
    elif stage == "recommend":
        m = {"S": 0.0, "K": dK * 0.3, "C": dC, "R": 0.0, "T": 0.0}
    else:
        raise ValueError(stage)
    w = WEIGHTS[threat_type]
    ars = 1.0 - sum(w[k] * m[k] for k in w)
    return max(0.0, min(1.0, ars))


def main() -> None:
    records = []
    with DATASET.open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("agent_arch") == "AUT-2":
                records.append(rec)

    if not records:
        print("No AUT-2 records found.")
        return

    weakest_stage_counts = {"triage": 0, "enrich": 0, "recommend": 0}
    mu_star_max_values = []
    r_star_values = []
    cascade_ars_values = []
    bound_values = []
    bound_violations = 0

    for rec in records:
        mv = rec["mismatch_vector"]
        tt = rec["threat_type"]
        dS, dK, dC = mv["delta_S"], mv["delta_K"], mv["delta_C"]

        ars_t = stage_ars(tt, dS, dK, dC, "triage")
        ars_e = stage_ars(tt, dS, dK, dC, "enrich")
        ars_r = stage_ars(tt, dS, dK, dC, "recommend")
        stages = {"triage": ars_t, "enrich": ars_e, "recommend": ars_r}

        # Exclude terminal stage from "weakest-with-outgoing" analysis
        non_terminal = {s: a for s, a in stages.items() if OUTGOING[s]}
        weakest = min(non_terminal, key=non_terminal.get)
        r_star = non_terminal[weakest]
        mu_star_max = max(OUTGOING[weakest])

        weakest_stage_counts[weakest] += 1
        mu_star_max_values.append(mu_star_max)
        r_star_values.append(r_star)

        cascade_ars = rec.get("cascade_ars")
        if cascade_ars is not None:
            cascade_ars_values.append(cascade_ars)
            bound = 1.0 - mu_star_max * (1.0 - r_star)
            bound_values.append(bound)
            if cascade_ars > bound + 1e-9:
                bound_violations += 1

    mu_arr = np.array(mu_star_max_values)
    r_arr = np.array(r_star_values)
    cas_arr = np.array(cascade_ars_values)
    bnd_arr = np.array(bound_values)

    out = {
        "n_aut2_records": len(records),
        "coupling_design": {
            "triage_to_enrich": 0.8,
            "triage_to_recommend": 0.3,
            "enrich_to_recommend": 0.9,
        },
        "weakest_non_terminal_stage": weakest_stage_counts,
        "mu_star_max_distribution": {
            "mean": float(mu_arr.mean()),
            "median": float(np.median(mu_arr)),
            "min": float(mu_arr.min()),
            "max": float(mu_arr.max()),
            "frac_ge_0.8": float((mu_arr >= 0.8).mean()),
        },
        "r_star_distribution": {
            "mean": float(r_arr.mean()),
            "median": float(np.median(r_arr)),
            "min": float(r_arr.min()),
            "max": float(r_arr.max()),
        },
        "cascade_vs_bound": {
            "cascade_ars_mean": float(cas_arr.mean()),
            "bound_mean": float(bnd_arr.mean()),
            "bound_violations": int(bound_violations),
            "frac_violations": float(bound_violations / max(1, len(records))),
        },
    }

    OUT.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
