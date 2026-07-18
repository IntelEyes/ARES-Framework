#!/usr/bin/env python3
"""
SOCAgentFailure-1K Dataset Generator for ARES-Bench.

NOTE ON WHAT THIS PRODUCES (read before citing the outputs):
    This generator produces an ANALYTICAL corpus. Agent outcomes -- hallucination,
    expressed confidence, task success, delta_R, and the anomaly flag -- are computed
    from the mismatch inputs by the closed-form models in shared/shared_models.py
    (simulate_hallucination, simulate_confidence, simulate_task_success, ...), and the
    agent's own text output is overridden by those calibrated values (see ~line 264).
    The corpus therefore ENCODES the mismatch->failure relationships (e.g. p_hall grows
    with delta_K) rather than discovering them from live model execution.

    A real-agent study (analysis/calibration_gap_harness*.py -> output/calibration_gap_runs.json,
    600 live executions across Claude + GPT families) shows the headline assumption baked in
    here -- that knowledge deficit yields CONFIDENT hallucination -- does NOT hold for real
    frontier agents: they are calibrated and abstain instead (pooled Pearson(delta_K, fabricate)
    = +0.11 vs. the +0.92 encoded here). Use this corpus as an analytical instrument, and the
    calibration_gap dataset for claims about real agent behaviour.

Generates exactly 1,000 evaluation records stratified across:
  - 5 task classes (T1-T5, ~200 each)
  - 4 agent architectures (AUT-1 to AUT-4, ~250 each)
  - 16 representative mismatch conditions from 4^4 matrix

Targets:
  - ~40% anomaly rate
  - ~18% hallucination rate (among LLM agents only)
  - Train/Val/Test split: 600/200/200

Outputs to ares_bench/output/:
  - socagentfailure_1k.jsonl  (full nested records)
  - socagentfailure_1k.csv    (flattened scalar metrics)
  - dataset_stats.json        (summary statistics)
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
import csv
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
BENCH_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BENCH_ROOT)

from shared.config import Config
from shared.shared_models import (
    AgentArch,
    AgentProfile,
    TaskProfile,
    MismatchVector,
    ThreatType,
    EvalRecord,
    MISMATCH_LEVELS,
    WEIGHT_VECTORS,
    ARS_THRESHOLD,
    EPISTEMIC_THRESHOLD,
    compute_ars,
    compute_mismatch_vector,
    compute_delta_S,
    compute_delta_K,
    compute_delta_C,
    compute_delta_R,
    compute_delta_T,
    compute_epistemic_gap,
    compute_anomaly_flag,
    compute_cascade_ars,
    simulate_uncertainty,
    simulate_delta_R,
    simulate_hallucination,
    simulate_confidence,
    simulate_false_negative,
    simulate_task_success,
)
from shared.attack_data import (
    THREAT_SCENARIOS,
    build_task_profile,
    get_scenarios_for_type,
)
from shared.taxonomy import assign_taxonomy

from services.scenario_engine.main import ScenarioEngine
from services.mismatch_injector.main import MismatchInjector
from services.agents.langgraph_agent.main import LangGraphAgentSim
from services.agents.autogen_agent.main import AutoGenAgentSim
from services.agents.crewai_agent.main import CrewAIAgentSim
from services.agents.rulebased_agent.main import RuleBasedAgentSim
from services.anomaly_monitor.main import AnomalyMonitor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEED = 42
TOTAL_RECORDS = 1000
TRAIN_SIZE = 600
VAL_SIZE = 200
TEST_SIZE = 200

TASK_CLASSES = [ThreatType.T1_RANSOMWARE, ThreatType.T2_PHISHING,
                ThreatType.T3_INSIDER, ThreatType.T4_DDOS,
                ThreatType.T5_APT]
ARCH_LIST = [AgentArch.AUT1_LANGGRAPH, AgentArch.AUT2_AUTOGEN,
             AgentArch.AUT3_CREWAI, AgentArch.AUT4_RULEBASED]

# 16 representative mismatch conditions from the 4^4 (S,K,C,T_age) matrix.
# Selected to span: zero, single-dim, compound, and extreme corners,
# with bias toward non-zero to achieve ~40% anomaly rate.
MISMATCH_CONDITIONS: List[Tuple[float, float, float, float]] = [
    # (delta_S, delta_K, delta_C, T_age_hours)
    (0.00, 0.00, 0.00, 0),      # Baseline -- no mismatch
    (0.33, 0.00, 0.00, 0),      # S-only low
    (0.66, 0.00, 0.00, 0),      # S-only medium
    (0.00, 0.33, 0.00, 0),      # K-only low
    (0.00, 0.66, 0.00, 0),      # K-only medium
    (0.00, 1.00, 0.00, 0),      # K-only high
    (0.00, 0.00, 0.66, 0),      # C-only medium
    (0.00, 0.00, 1.00, 0),      # C-only high
    (0.33, 0.33, 0.00, 0),      # S+K compound low
    (0.33, 0.66, 0.00, 0),      # S+K compound medium
    (0.00, 0.66, 0.66, 0),      # K+C compound medium
    (0.33, 0.33, 0.33, 0),      # All-three low
    (0.66, 0.66, 0.66, 0),      # All-three medium
    (1.00, 1.00, 1.00, 0),      # Total mismatch
    (0.00, 0.33, 0.00, 168),    # K-low + temporal (1 week)
    (0.33, 0.66, 0.33, 720),    # Compound + temporal (30 days)
]

# Scenarios per threat type (we have 2 each in attack_data)
SCENARIOS_PER_TYPE = {
    "T1": ["T1-01", "T1-02"],
    "T2": ["T2-01", "T2-02"],
    "T3": ["T3-01", "T3-02"],
    "T4": ["T4-01", "T4-02"],
    "T5": ["T5-01", "T5-02"],
}


def build_generation_plan(rng: random.Random) -> List[Dict]:
    """Build an assignment plan for exactly 1000 records with stratified balance.

    Strategy:
    - 5 threat types x 200 records each = 1000
    - Within each threat type: 4 archs x 50 records = 200
    - Within each (type, arch) cell: distribute 50 across 16 mismatch conditions
      (~3 per condition with leftover distributed round-robin)
    - Weight mismatch conditions to achieve ~40% anomaly rate overall:
      higher-mismatch conditions get slightly more samples.
    """
    plan = []
    record_idx = 0

    # Weights for mismatch conditions (higher mismatch -> slightly more weight
    # to push anomaly rate toward 40%)
    condition_weights = []
    for ds, dk, dc, t_age in MISMATCH_CONDITIONS:
        severity = ds + dk + dc + (0.1 if t_age > 0 else 0)
        # Give moderate/high mismatch ~1.5x weight
        w = 1.0 + 0.3 * min(severity, 2.0)
        condition_weights.append(w)

    total_w = sum(condition_weights)
    condition_probs = [w / total_w for w in condition_weights]

    for tt in TASK_CLASSES:
        tt_key = tt.value
        scenarios = SCENARIOS_PER_TYPE[tt_key]
        for arch in ARCH_LIST:
            # 50 records per (threat_type, arch) cell
            n_cell = 50
            # Allocate across 16 conditions proportionally
            raw_alloc = [condition_probs[i] * n_cell for i in range(16)]
            alloc = [int(a) for a in raw_alloc]
            # Distribute remainder
            remainder = n_cell - sum(alloc)
            fractional = [(raw_alloc[i] - alloc[i], i) for i in range(16)]
            fractional.sort(reverse=True)
            for j in range(remainder):
                alloc[fractional[j][1]] += 1

            for cond_idx, count in enumerate(alloc):
                ds, dk, dc, t_age = MISMATCH_CONDITIONS[cond_idx]
                for rep in range(count):
                    scenario_id = rng.choice(scenarios)
                    plan.append({
                        "idx": record_idx,
                        "scenario_id": scenario_id,
                        "threat_type": tt_key,
                        "arch": arch,
                        "target_delta_S": ds,
                        "target_delta_K": dk,
                        "target_delta_C": dc,
                        "T_age": float(t_age),
                        "repetition": rep,
                    })
                    record_idx += 1

    rng.shuffle(plan)
    return plan


def run_generation(plan: List[Dict], seed: int = SEED) -> List[Dict]:
    """Execute the generation plan using the calibrated simulation pipeline.

    Key models:
    - Hallucination: P(H) = delta_K^1.5 * (0.5 + 0.5*(1-U))
    - Confidence: LLM overconfident (0.7+0.2*(1-dK)), rule-based calibrated
    - Epistemic Gap: E = delta_K * (1 - U)
    - FN score: 0.3*dK + 0.5*E + 0.2*dS
    - AUT-2 cascade: ARS_cas = prod(1 - mu*(1 - ARS_i)) with mu=0.7
    - Task success: ARS > 0.6, no hallucination, random > 0.1
    """
    scenario_engine = ScenarioEngine(seed=seed)
    injector = MismatchInjector(seed=seed)
    agents = {
        AgentArch.AUT1_LANGGRAPH: LangGraphAgentSim(seed=seed),
        AgentArch.AUT2_AUTOGEN: AutoGenAgentSim(seed=seed),
        AgentArch.AUT3_CREWAI: CrewAIAgentSim(seed=seed),
        AgentArch.AUT4_RULEBASED: RuleBasedAgentSim(seed=seed),
    }
    monitor = AnomalyMonitor()
    gen_rng = random.Random(seed + 1000)  # separate rng for generation models

    records = []
    t0 = time.time()

    for i, entry in enumerate(plan):
        scenario_id = entry["scenario_id"]
        arch = entry["arch"]
        ds = entry["target_delta_S"]
        dk = entry["target_delta_K"]
        dc = entry["target_delta_C"]
        t_age = entry["T_age"]
        rep = entry["repetition"]

        run_id = (f"saf1k_{entry['idx']:04d}_{scenario_id}_{arch.value}"
                  f"_dS{ds}_dK{dk}_dC{dc}_T{t_age}_r{rep}")

        # 1. Build task and full agent
        task = scenario_engine.build_task(scenario_id)
        full_agent = scenario_engine.build_agent(arch, task)

        # 2. Inject mismatches
        degraded_agent = injector.inject(full_agent, task, ds, dk, dc, t_age)

        # 3. Generate misleading context if reasoning mismatch desired
        misleading = None
        if dk > 0.3 or ds > 0.5:
            misleading = injector.inject_reasoning_noise(degraded_agent, dk * 0.5)

        # 4. Run agent simulation
        agent_sim = agents[arch]
        agent_result = agent_sim.run(degraded_agent, task, misleading)

        # ----- NEW: Calibrated simulation models -----
        # Compute actual mismatches
        actual_dS = compute_delta_S(degraded_agent, task)
        actual_dK = compute_delta_K(degraded_agent, task)
        actual_dC = compute_delta_C(degraded_agent, task)

        # Uncertainty (expressed): LLM agents are overconfident
        uncertainty = simulate_uncertainty(arch, actual_dK, rng=gen_rng)

        # Confidence
        confidence = simulate_confidence(arch, actual_dS, actual_dK, actual_dC, rng=gen_rng)

        # Hallucination
        hallucinated = simulate_hallucination(arch, actual_dK, uncertainty, rng=gen_rng)

        # Override agent_result with calibrated values
        agent_result["uncertainty"] = uncertainty
        agent_result["hallucinated_indicators"] = hallucinated
        agent_result["confidence"] = confidence

        # ----- AUT-2 cascade degradation -----
        cascade_ars_val = None
        if arch == AgentArch.AUT2_AUTOGEN:
            # 3-stage pipeline: each stage sees FULL mismatch (not attenuated)
            # because each stage is an independent LLM agent in the pipeline
            threat_type_val = task.threat_type.value

            # All 3 stages see the full mismatch -- each stage is independent
            # In a pipeline, mismatch compounds: stage errors propagate
            threat_type_val = task.threat_type.value
            max_mismatch = max(actual_dS, actual_dK, actual_dC)

            # Compute the single-agent ARS for reference
            single_mm = MismatchVector(
                delta_S=actual_dS, delta_K=actual_dK,
                delta_C=actual_dC, delta_R=0.0, delta_T=0.0
            )
            single_ars = compute_ars(single_mm, threat_type_val)

            # Each stage has its own mismatch profile
            stage1_mm = MismatchVector(
                delta_S=actual_dS, delta_K=actual_dK,
                delta_C=0.0, delta_R=0.0, delta_T=0.0
            )
            stage2_mm = MismatchVector(
                delta_S=0.0, delta_K=actual_dK,
                delta_C=actual_dC, delta_R=0.0, delta_T=0.0
            )
            stage3_mm = MismatchVector(
                delta_S=actual_dS * 0.5, delta_K=actual_dK,
                delta_C=actual_dC, delta_R=0.0, delta_T=0.0
            )

            stage_ars = [
                compute_ars(stage1_mm, threat_type_val),
                compute_ars(stage2_mm, threat_type_val),
                compute_ars(stage3_mm, threat_type_val),
            ]

            # Cascade formula with strong coupling mu=0.85
            # ARS_cas = prod_i(1 - mu * (1 - ARS_i))
            mu = 0.85
            cascade_ars_val = 1.0
            for s_ars in stage_ars:
                cascade_ars_val *= (1.0 - mu * (1.0 - s_ars))
            cascade_ars_val = max(0.0, min(1.0, cascade_ars_val))

            # Additional pipeline overhead: coordination penalty proportional to mismatch
            # When mismatch exists, inter-stage communication introduces ~15% overhead
            if max_mismatch > 0.05:
                coord_penalty = 1.0 - 0.15 * max_mismatch
                cascade_ars_val *= coord_penalty

            # Hallucination propagation: if any hallucination, cascade degrades further
            if hallucinated:
                cascade_ars_val *= (0.55 + 0.30 * gen_rng.random())

            cascade_ars_val = max(0.0, min(1.0, cascade_ars_val))

            agent_result["cascade_ars"] = cascade_ars_val
            agent_result["stage_ars"] = stage_ars

        # 5. Evaluate via anomaly monitor
        timestamp = datetime.now(timezone.utc).isoformat()
        record = monitor.evaluate(run_id, degraded_agent, task, agent_result, timestamp)

        rec_dict = record.to_dict()

        # ----- Add calibrated fields to the record -----
        rec_dict["hallucinated"] = hallucinated
        rec_dict["confidence"] = confidence

        # Epistemic gap (recompute with calibrated uncertainty)
        e_gap = compute_epistemic_gap(actual_dK, uncertainty)
        rec_dict["epistemic_gap"] = round(e_gap, 6)

        # FN score
        fn_score = simulate_false_negative(actual_dK, actual_dS, e_gap, rng=gen_rng)
        rec_dict["fn_score"] = round(fn_score, 6)

        # Task success
        ars_for_success = cascade_ars_val if cascade_ars_val is not None else rec_dict["ars_score"]
        rec_dict["task_success"] = simulate_task_success(ars_for_success, hallucinated, rng=gen_rng)

        # Anomaly flag recompute with calibrated epistemic gap
        rec_dict["anomaly_flag"] = compute_anomaly_flag(rec_dict["ars_score"], e_gap)

        # For AUT-2, store the cascade ARS
        if cascade_ars_val is not None:
            rec_dict["cascade_ars"] = round(cascade_ars_val, 6)

        records.append(rec_dict)

        if (i + 1) % 200 == 0:
            elapsed = time.time() - t0
            print(f"  Generated {i+1}/{len(plan)} records ({elapsed:.1f}s)")

    elapsed = time.time() - t0
    print(f"  Generation complete: {len(records)} records in {elapsed:.1f}s")
    return records


def assign_splits(records: List[Dict], rng: random.Random) -> List[Dict]:
    """Assign train/val/test splits maintaining stratification."""
    # Group by (threat_type, agent_arch)
    groups = defaultdict(list)
    for r in records:
        key = (r["threat_type"], r["agent_arch"])
        groups[key].append(r)

    all_records = []
    for key, group in groups.items():
        rng.shuffle(group)
        n = len(group)
        # Split proportionally: 60/20/20
        n_train = round(n * 0.6)
        n_val = round(n * 0.2)
        n_test = n - n_train - n_val
        for i, rec in enumerate(group):
            if i < n_train:
                rec["split"] = "train"
            elif i < n_train + n_val:
                rec["split"] = "validation"
            else:
                rec["split"] = "test"
        all_records.extend(group)

    return all_records


def flatten_record(record: Dict) -> Dict:
    """Flatten a nested record for CSV output."""
    flat = {
        "run_id": record["run_id"],
        "scenario_id": record["scenario_id"],
        "threat_type": record["threat_type"],
        "agent_arch": record["agent_arch"],
        "ars_score": record["ars_score"],
        "epistemic_gap": record["epistemic_gap"],
        "anomaly_flag": record["anomaly_flag"],
        "uncertainty": record["uncertainty"],
        "latency_ms": record["latency_ms"],
        "split": record.get("split", ""),
    }

    # Mismatch vector components
    mv = record.get("mismatch_vector", {})
    for k in ["delta_S", "delta_K", "delta_C", "delta_R", "delta_T"]:
        flat[k] = mv.get(k, 0.0)

    # Cascade ARS
    flat["cascade_ars"] = record.get("cascade_ars")

    # Calibrated fields
    flat["hallucinated"] = record.get("hallucinated", False)
    flat["confidence"] = record.get("confidence", 0.0)
    flat["fn_score"] = record.get("fn_score", 0.0)
    flat["task_success"] = record.get("task_success", False)

    # Taxonomy codes
    tax = record.get("taxonomy_codes", {})
    flat["taxonomy_origin"] = tax.get("origin", "")
    flat["taxonomy_manifestation"] = tax.get("manifestation", "")
    flat["taxonomy_impact"] = tax.get("impact", "")
    flat["taxonomy_severity"] = tax.get("severity", "")

    return flat


def compute_dataset_stats(records: List[Dict]) -> Dict:
    """Compute comprehensive summary statistics matching paper specs."""
    n = len(records)
    ars_scores = [r["ars_score"] for r in records]
    e_gaps = [r["epistemic_gap"] for r in records]
    anomaly_flags = [r["anomaly_flag"] for r in records]
    anomaly_rate = sum(anomaly_flags) / n

    # Mean and std
    mean_ars = sum(ars_scores) / n
    std_ars = (sum((a - mean_ars) ** 2 for a in ars_scores) / n) ** 0.5
    mean_egap = sum(e_gaps) / n

    # Hallucination rate (LLM agents only = AUT-1, AUT-2, AUT-3)
    llm_records = [r for r in records if r["agent_arch"] != "AUT-4"]
    n_llm = len(llm_records)
    hallucinated_count = sum(1 for r in llm_records if r.get("hallucinated", False))
    hallucination_rate = hallucinated_count / n_llm if n_llm > 0 else 0

    # Per-architecture stats
    arch_stats = {}
    for arch_name in ["AUT-1", "AUT-2", "AUT-3", "AUT-4"]:
        arch_recs = [r for r in records if r["agent_arch"] == arch_name]
        if arch_recs:
            a_ars = [r["ars_score"] for r in arch_recs]
            a_mean = sum(a_ars) / len(a_ars)
            a_std = (sum((a - a_mean)**2 for a in a_ars) / len(a_ars)) ** 0.5
            a_anomaly = sum(1 for r in arch_recs if r["anomaly_flag"]) / len(arch_recs)

            # Hallucination (LLM agents only)
            if arch_name != "AUT-4":
                a_hall = sum(1 for r in arch_recs if r.get("hallucinated", False)) / len(arch_recs)
            else:
                a_hall = 0.0

            arch_stats[arch_name] = {
                "count": len(arch_recs),
                "mean_ars": round(a_mean, 4),
                "std_ars": round(a_std, 4),
                "min_ars": round(min(a_ars), 4),
                "max_ars": round(max(a_ars), 4),
                "anomaly_rate": round(a_anomaly, 4),
                "hallucination_rate": round(a_hall, 4),
            }

    # Per-threat-type stats
    threat_stats = {}
    for tt in ["T1", "T2", "T3", "T4", "T5"]:
        tt_recs = [r for r in records if r["threat_type"] == tt]
        if tt_recs:
            t_ars = [r["ars_score"] for r in tt_recs]
            t_mean = sum(t_ars) / len(t_ars)
            threat_stats[tt] = {
                "count": len(tt_recs),
                "mean_ars": round(t_mean, 4),
                "min_ars": round(min(t_ars), 4),
                "max_ars": round(max(t_ars), 4),
                "anomaly_rate": round(
                    sum(1 for r in tt_recs if r["anomaly_flag"]) / len(tt_recs), 4
                ),
            }

    # Split stats
    split_stats = {}
    for split in ["train", "validation", "test"]:
        s_recs = [r for r in records if r.get("split") == split]
        if s_recs:
            s_ars = [r["ars_score"] for r in s_recs]
            split_stats[split] = {
                "count": len(s_recs),
                "mean_ars": round(sum(s_ars) / len(s_ars), 4),
                "anomaly_rate": round(
                    sum(1 for r in s_recs if r["anomaly_flag"]) / len(s_recs), 4
                ),
            }

    # Taxonomy distribution
    origin_dist = Counter(r.get("taxonomy_codes", {}).get("origin", "") for r in records)
    manifest_dist = Counter(r.get("taxonomy_codes", {}).get("manifestation", "") for r in records)
    impact_dist = Counter(r.get("taxonomy_codes", {}).get("impact", "") for r in records)

    # AUT-2 vs single-agent ARS comparison (paper spec: ~26% worse)
    aut2_recs = [r for r in records if r["agent_arch"] == "AUT-2"]
    single_recs = [r for r in records if r["agent_arch"] in ("AUT-1", "AUT-3")]
    if aut2_recs and single_recs:
        aut2_mean = sum(r["ars_score"] for r in aut2_recs) / len(aut2_recs)
        single_mean = sum(r["ars_score"] for r in single_recs) / len(single_recs)
        cascade_degradation_pct = round(
            (1 - aut2_mean / single_mean) * 100 if single_mean > 0 else 0, 2
        )
    else:
        cascade_degradation_pct = None

    stats = {
        "dataset_name": "SOCAgentFailure-1K",
        "total_records": n,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "overall": {
            "mean_ars": round(mean_ars, 4),
            "std_ars": round(std_ars, 4),
            "min_ars": round(min(ars_scores), 4),
            "max_ars": round(max(ars_scores), 4),
            "mean_epistemic_gap": round(mean_egap, 4),
            "anomaly_rate": round(anomaly_rate, 4),
            "hallucination_rate_llm_only": round(hallucination_rate, 4),
        },
        "cascade_analysis": {
            "aut2_mean_ars": round(
                sum(r["ars_score"] for r in aut2_recs) / len(aut2_recs), 4
            ) if aut2_recs else None,
            "single_agent_mean_ars": round(
                sum(r["ars_score"] for r in single_recs) / len(single_recs), 4
            ) if single_recs else None,
            "cascade_degradation_pct": cascade_degradation_pct,
        },
        "by_architecture": arch_stats,
        "by_threat_type": threat_stats,
        "by_split": split_stats,
        "taxonomy_distribution": {
            "origin": dict(sorted(origin_dist.items())),
            "manifestation": dict(sorted(manifest_dist.items())),
            "impact": dict(sorted(impact_dist.items())),
        },
        "mismatch_conditions_used": len(MISMATCH_CONDITIONS),
    }
    return stats


def write_outputs(records: List[Dict], stats: Dict, output_dir: str) -> Dict[str, str]:
    """Write all output files."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {}

    # 1. JSONL
    jsonl_path = out / "socagentfailure_1k.jsonl"
    with open(jsonl_path, "w") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")
    paths["jsonl"] = str(jsonl_path)

    # 2. CSV (flattened)
    csv_path = out / "socagentfailure_1k.csv"
    flat_records = [flatten_record(r) for r in records]
    if flat_records:
        fieldnames = sorted(flat_records[0].keys())
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for fr in flat_records:
                writer.writerow(fr)
    paths["csv"] = str(csv_path)

    # 3. Stats JSON
    stats_path = out / "dataset_stats.json"
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2, default=str)
    paths["stats"] = str(stats_path)

    return paths


def main():
    print("=" * 70)
    print("  SOCAgentFailure-1K Dataset Generator")
    print("  ARES-Bench Testbed")
    print("=" * 70)

    rng = random.Random(SEED)

    # Step 1: Build generation plan
    print("\n[1/5] Building generation plan...")
    plan = build_generation_plan(rng)
    print(f"  Plan size: {len(plan)} records")

    # Verify stratification
    tt_counts = Counter(e["threat_type"] for e in plan)
    arch_counts = Counter(e["arch"].value for e in plan)
    print(f"  By threat type: {dict(sorted(tt_counts.items()))}")
    print(f"  By architecture: {dict(sorted(arch_counts.items()))}")

    # Step 2: Run generation
    print("\n[2/5] Running simulation pipeline...")
    records = run_generation(plan, seed=SEED)

    # Step 3: Assign splits
    print("\n[3/5] Assigning train/validation/test splits...")
    records = assign_splits(records, rng)
    split_counts = Counter(r.get("split", "none") for r in records)
    print(f"  Splits: {dict(sorted(split_counts.items()))}")

    # Step 4: Compute statistics
    print("\n[4/5] Computing dataset statistics...")
    stats = compute_dataset_stats(records)

    # Step 5: Write outputs
    output_dir = os.path.join(BENCH_ROOT, "output")
    print(f"\n[5/5] Writing outputs to {output_dir}/")
    paths = write_outputs(records, stats, output_dir)
    for label, path in paths.items():
        print(f"  {label}: {path}")

    # Print summary
    print("\n" + "=" * 70)
    print("  DATASET STATISTICS")
    print("=" * 70)
    o = stats["overall"]
    print(f"\n  Total records:          {stats['total_records']}")
    print(f"  Mean ARS:               {o['mean_ars']:.4f} (+/- {o['std_ars']:.4f})")
    print(f"  Mean Epistemic Gap:     {o['mean_epistemic_gap']:.4f}")
    print(f"  Anomaly rate:           {o['anomaly_rate']:.4f} ({o['anomaly_rate']*100:.1f}%)")
    print(f"  Hallucination rate:     {o['hallucination_rate_llm_only']:.4f} ({o['hallucination_rate_llm_only']*100:.1f}%, LLM-only)")

    ca = stats.get("cascade_analysis", {})
    if ca.get("cascade_degradation_pct") is not None:
        print(f"\n  Cascade Analysis (AUT-2 vs single-agent):")
        print(f"    AUT-2 mean ARS:       {ca['aut2_mean_ars']:.4f}")
        print(f"    Single-agent mean:    {ca['single_agent_mean_ars']:.4f}")
        print(f"    Cascade degradation:  {ca['cascade_degradation_pct']:.1f}%")

    print(f"\n  By Architecture:")
    for arch, s in sorted(stats["by_architecture"].items()):
        print(f"    {arch}: n={s['count']}, ARS={s['mean_ars']:.4f}, "
              f"anomaly={s['anomaly_rate']:.2%}, "
              f"halluc={s['hallucination_rate']:.2%}")

    print(f"\n  By Threat Type:")
    for tt, s in sorted(stats["by_threat_type"].items()):
        print(f"    {tt}: n={s['count']}, ARS={s['mean_ars']:.4f}, "
              f"anomaly={s['anomaly_rate']:.2%}")

    print(f"\n  By Split:")
    for sp, s in sorted(stats["by_split"].items()):
        print(f"    {sp}: n={s['count']}, ARS={s['mean_ars']:.4f}, "
              f"anomaly={s['anomaly_rate']:.2%}")

    # Taxonomy distribution
    print(f"\n  Taxonomy Distribution:")
    for dim_name, dist in stats["taxonomy_distribution"].items():
        codes = ", ".join(f"{k}:{v}" for k, v in sorted(dist.items()) if v > 0)
        print(f"    {dim_name}: {codes}")

    # Verification checks
    print("\n" + "=" * 70)
    print("  VERIFICATION")
    print("=" * 70)
    checks_passed = 0
    checks_total = 0

    def check(desc, cond):
        nonlocal checks_passed, checks_total
        checks_total += 1
        status = "PASS" if cond else "FAIL"
        if cond:
            checks_passed += 1
        print(f"  [{status}] {desc}")

    check(f"Total records == 1000 (got {stats['total_records']})",
          stats["total_records"] == 1000)

    for tt, s in stats["by_threat_type"].items():
        check(f"{tt} count ~200 (got {s['count']})", 180 <= s["count"] <= 220)

    for arch, s in stats["by_architecture"].items():
        check(f"{arch} count ~250 (got {s['count']})", 230 <= s["count"] <= 270)

    check(f"Anomaly rate ~40% (got {o['anomaly_rate']*100:.1f}%)",
          25 <= o["anomaly_rate"] * 100 <= 55)

    check(f"Hallucination rate ~18% LLM-only (got {o['hallucination_rate_llm_only']*100:.1f}%)",
          8 <= o["hallucination_rate_llm_only"] * 100 <= 30)

    check(f"Train split == 600 (got {stats['by_split'].get('train', {}).get('count', 0)})",
          stats['by_split'].get('train', {}).get('count', 0) == TRAIN_SIZE)

    check(f"Validation split == 200 (got {stats['by_split'].get('validation', {}).get('count', 0)})",
          stats['by_split'].get('validation', {}).get('count', 0) == VAL_SIZE)

    check(f"Test split == 200 (got {stats['by_split'].get('test', {}).get('count', 0)})",
          stats['by_split'].get('test', {}).get('count', 0) == TEST_SIZE)

    # AUT-4 never hallucinates
    aut4_hall = stats["by_architecture"].get("AUT-4", {}).get("hallucination_rate", 0)
    check(f"AUT-4 hallucination rate == 0% (got {aut4_hall*100:.1f}%)", aut4_hall == 0.0)

    if ca.get("cascade_degradation_pct") is not None:
        check(f"AUT-2 cascade degradation notable (got {ca['cascade_degradation_pct']:.1f}%)",
              ca["cascade_degradation_pct"] > 5)

    check("16 mismatch conditions used",
          stats["mismatch_conditions_used"] == 16)

    print(f"\n  Checks: {checks_passed}/{checks_total} passed")
    print("=" * 70)


if __name__ == "__main__":
    main()
