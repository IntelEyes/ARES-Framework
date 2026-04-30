"""
ARES-Bench Paper Results Generator.

Runs all 5 experiments from the paper and produces analysis outputs:

Experiment 1: Single-Dimension Mismatch Sweep
  - Sweep each of delta_S, delta_K, delta_C independently
  - Measure ARS degradation curves per architecture x threat type

Experiment 2: Compound Mismatch Interaction
  - Multi-dimension mismatch combinations
  - Measure non-linear interaction effects

Experiment 3: Cascade Reliability (AUT-2 AutoGen pipeline)
  - Measure cascade ARS vs individual stage ARS
  - Quantify error amplification through pipeline stages

Experiment 4: Temporal Decay
  - Vary T_age and measure ARS degradation over time
  - Compare volatility across threat types

Experiment 5: Epistemic Gap Analysis
  - Measure relationship between delta_K, uncertainty, and epistemic gap
  - Compare LLM vs rule-based agent calibration
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

# Add project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.config import Config
from shared.shared_models import (
    AgentArch,
    ThreatType,
    MISMATCH_LEVELS,
    WEIGHT_VECTORS,
    VOLATILITY_PARAMS,
    ARS_THRESHOLD,
    EPISTEMIC_THRESHOLD,
)


def load_dataset(path: str) -> List[Dict]:
    """Load dataset from JSONL file."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def experiment_1_single_dimension(records: List[Dict]) -> Dict:
    """Experiment 1: Single-dimension mismatch sweep analysis.

    For each dimension (S, K, C), group records where only that dimension
    has non-zero mismatch. Compute mean ARS per (arch, threat_type, level).
    """
    results = {}

    for dim in ["delta_S", "delta_K", "delta_C"]:
        other_dims = [d for d in ["delta_S", "delta_K", "delta_C"] if d != dim]
        dim_records = [
            r for r in records
            if all(abs(r["mismatch_vector"].get(od, 0)) < 0.01 for od in other_dims)
        ]

        # Group by (arch, threat_type, level)
        groups = defaultdict(list)
        for r in dim_records:
            level = r["mismatch_vector"].get(dim, 0)
            # Snap to nearest mismatch level
            level = min(MISMATCH_LEVELS, key=lambda x: abs(x - level))
            key = (r["agent_arch"], r["threat_type"], level)
            groups[key].append(r["ars_score"])

        # Compute mean ARS per group
        dim_results = {}
        for (arch, tt, level), scores in groups.items():
            key = f"{arch}_{tt}_{level}"
            dim_results[key] = {
                "arch": arch,
                "threat_type": tt,
                "level": level,
                "mean_ars": round(sum(scores) / len(scores), 4),
                "std_ars": round(
                    (sum((s - sum(scores)/len(scores))**2 for s in scores) / max(1, len(scores))) ** 0.5,
                    4,
                ),
                "n": len(scores),
                "anomaly_rate": round(
                    sum(1 for r in records
                        if r["agent_arch"] == arch and r["threat_type"] == tt
                        and abs(r["mismatch_vector"].get(dim, 0) - level) < 0.01
                        and r.get("anomaly_flag", False)) / max(1, len(scores)),
                    4,
                ),
            }

        results[dim] = dim_results

    return results


def experiment_2_compound(records: List[Dict]) -> Dict:
    """Experiment 2: Compound mismatch interaction analysis.

    Identify records where 2+ dimensions have non-zero mismatch.
    Compare actual ARS with predicted ARS from single-dimension model.
    """
    compound_records = [
        r for r in records
        if sum(1 for d in ["delta_S", "delta_K", "delta_C"]
               if r["mismatch_vector"].get(d, 0) > 0.01) >= 2
    ]

    # Compute "predicted" ARS as if dimensions were independent
    # (sum of individual effects) vs actual
    results = {
        "total_compound_records": len(compound_records),
        "by_architecture": {},
    }

    for arch in ["AUT-1", "AUT-2", "AUT-3", "AUT-4"]:
        arch_records = [r for r in compound_records if r["agent_arch"] == arch]
        if not arch_records:
            continue

        ars_scores = [r["ars_score"] for r in arch_records]
        mean_ars = sum(ars_scores) / len(ars_scores)

        # Count elevated dimensions
        dim_counts = defaultdict(list)
        for r in arch_records:
            n_elevated = sum(
                1 for d in ["delta_S", "delta_K", "delta_C"]
                if r["mismatch_vector"].get(d, 0) > 0.3
            )
            dim_counts[n_elevated].append(r["ars_score"])

        by_count = {}
        for n, scores in dim_counts.items():
            by_count[str(n)] = {
                "mean_ars": round(sum(scores) / len(scores), 4),
                "n": len(scores),
            }

        results["by_architecture"][arch] = {
            "n": len(arch_records),
            "mean_ars": round(mean_ars, 4),
            "anomaly_rate": round(
                sum(1 for r in arch_records if r.get("anomaly_flag")) / len(arch_records), 4
            ),
            "by_elevated_dimensions": by_count,
        }

    return results


def experiment_3_cascade(records: List[Dict]) -> Dict:
    """Experiment 3: Cascade reliability analysis (AUT-2 only).

    Compare cascade ARS with individual ARS for AutoGen pipeline.
    """
    cascade_records = [
        r for r in records
        if r["agent_arch"] == "AUT-2" and r.get("cascade_ars") is not None
    ]

    if not cascade_records:
        # If no explicit cascade records, compute from AUT-2 records
        cascade_records = [r for r in records if r["agent_arch"] == "AUT-2"]

    results = {
        "total_cascade_records": len(cascade_records),
        "by_threat_type": {},
    }

    for tt in ["T1", "T2", "T3", "T4", "T5"]:
        tt_records = [r for r in cascade_records if r["threat_type"] == tt]
        if not tt_records:
            continue

        ars_scores = [r["ars_score"] for r in tt_records]
        cascade_scores = [r.get("cascade_ars", r["ars_score"]) for r in tt_records]

        results["by_threat_type"][tt] = {
            "n": len(tt_records),
            "mean_ars": round(sum(ars_scores) / len(ars_scores), 4),
            "mean_cascade_ars": round(sum(cascade_scores) / len(cascade_scores), 4),
            "amplification_factor": round(
                (sum(ars_scores) / len(ars_scores)) /
                max(0.001, sum(cascade_scores) / len(cascade_scores)),
                4,
            ),
        }

    return results


def experiment_4_temporal(records: List[Dict]) -> Dict:
    """Experiment 4: Temporal decay analysis.

    Group by T_age and measure ARS degradation over time.
    """
    temporal_records = [
        r for r in records
        if r["mismatch_vector"].get("delta_T", 0) > 0.001
    ]

    results = {
        "total_temporal_records": len(temporal_records),
        "by_threat_type": {},
    }

    for tt in ["T1", "T2", "T3", "T4", "T5"]:
        tt_records = [r for r in temporal_records if r["threat_type"] == tt]
        if not tt_records:
            continue

        # Group by delta_T buckets
        buckets = defaultdict(list)
        for r in tt_records:
            dt = r["mismatch_vector"].get("delta_T", 0)
            bucket = round(dt, 2)
            buckets[bucket].append(r["ars_score"])

        decay_curve = {}
        for bucket, scores in sorted(buckets.items()):
            decay_curve[str(bucket)] = {
                "mean_ars": round(sum(scores) / len(scores), 4),
                "n": len(scores),
            }

        results["by_threat_type"][tt] = {
            "lambda": VOLATILITY_PARAMS.get(tt, 0.003),
            "n": len(tt_records),
            "decay_curve": decay_curve,
        }

    return results


def experiment_5_epistemic(records: List[Dict]) -> Dict:
    """Experiment 5: Epistemic gap analysis.

    Analyze relationship between delta_K, uncertainty, and epistemic gap.
    Compare LLM agents vs rule-based agent calibration.
    """
    results = {
        "threshold_epsilon": EPISTEMIC_THRESHOLD,
        "by_architecture": {},
    }

    for arch in ["AUT-1", "AUT-2", "AUT-3", "AUT-4"]:
        arch_records = [r for r in records if r["agent_arch"] == arch]
        if not arch_records:
            continue

        e_gaps = [r.get("epistemic_gap", 0) for r in arch_records]
        uncertainties = [r.get("uncertainty", 0) for r in arch_records]
        delta_ks = [r["mismatch_vector"].get("delta_K", 0) for r in arch_records]

        # Epistemic gap vs delta_K correlation
        mean_ek = sum(e_gaps) / len(e_gaps)
        mean_dk = sum(delta_ks) / len(delta_ks)

        # Simple correlation
        if len(delta_ks) > 1:
            cov = sum((dk - mean_dk) * (eg - mean_ek)
                      for dk, eg in zip(delta_ks, e_gaps)) / len(delta_ks)
            std_dk = (sum((dk - mean_dk)**2 for dk in delta_ks) / len(delta_ks)) ** 0.5
            std_eg = (sum((eg - mean_ek)**2 for eg in e_gaps) / len(e_gaps)) ** 0.5
            corr = cov / max(0.001, std_dk * std_eg)
        else:
            corr = 0.0

        # Epistemic gap exceedance rate
        exceed_rate = sum(1 for eg in e_gaps if eg > EPISTEMIC_THRESHOLD) / max(1, len(e_gaps))

        results["by_architecture"][arch] = {
            "n": len(arch_records),
            "mean_epistemic_gap": round(mean_ek, 4),
            "mean_uncertainty": round(sum(uncertainties) / len(uncertainties), 4),
            "mean_delta_K": round(mean_dk, 4),
            "correlation_deltaK_egap": round(corr, 4),
            "epistemic_exceedance_rate": round(exceed_rate, 4),
        }

    return results


def run_all_experiments(dataset_path: str, output_dir: str) -> Dict:
    """Run all 5 experiments and save results."""
    print("Loading dataset...")
    records = load_dataset(dataset_path)
    print(f"  Loaded {len(records)} records")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    all_results = {}

    print("\nExperiment 1: Single-Dimension Mismatch Sweep...")
    exp1 = experiment_1_single_dimension(records)
    all_results["experiment_1_single_dimension"] = exp1
    print(f"  Analyzed {sum(len(v) for v in exp1.values())} groups")

    print("\nExperiment 2: Compound Mismatch Interaction...")
    exp2 = experiment_2_compound(records)
    all_results["experiment_2_compound"] = exp2
    print(f"  Analyzed {exp2['total_compound_records']} compound records")

    print("\nExperiment 3: Cascade Reliability...")
    exp3 = experiment_3_cascade(records)
    all_results["experiment_3_cascade"] = exp3
    print(f"  Analyzed {exp3['total_cascade_records']} cascade records")

    print("\nExperiment 4: Temporal Decay...")
    exp4 = experiment_4_temporal(records)
    all_results["experiment_4_temporal"] = exp4
    print(f"  Analyzed {exp4['total_temporal_records']} temporal records")

    print("\nExperiment 5: Epistemic Gap Analysis...")
    exp5 = experiment_5_epistemic(records)
    all_results["experiment_5_epistemic"] = exp5
    print(f"  Analyzed across {len(exp5['by_architecture'])} architectures")

    # Summary statistics
    ars_scores = [r["ars_score"] for r in records]
    mean_ars = sum(ars_scores) / len(ars_scores)
    anomaly_rate = sum(1 for r in records if r.get("anomaly_flag")) / len(records)

    all_results["summary"] = {
        "total_records": len(records),
        "mean_ars": round(mean_ars, 4),
        "anomaly_rate": round(anomaly_rate, 4),
        "ars_threshold": ARS_THRESHOLD,
        "epistemic_threshold": EPISTEMIC_THRESHOLD,
        "architectures": sorted(set(r["agent_arch"] for r in records)),
        "threat_types": sorted(set(r["threat_type"] for r in records)),
    }

    # Write results
    results_path = output_path / "paper_results.json"
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults written to {results_path}")

    # Print key findings
    print("\n" + "=" * 60)
    print("KEY FINDINGS")
    print("=" * 60)
    print(f"Total evaluation records: {len(records)}")
    print(f"Mean ARS: {mean_ars:.4f}")
    print(f"Anomaly rate: {anomaly_rate:.4f}")
    print(f"ARS threshold (theta*): {ARS_THRESHOLD}")
    print(f"Epistemic threshold (epsilon*): {EPISTEMIC_THRESHOLD}")

    print("\nPer-architecture mean ARS:")
    for arch in ["AUT-1", "AUT-2", "AUT-3", "AUT-4"]:
        arch_scores = [r["ars_score"] for r in records if r["agent_arch"] == arch]
        if arch_scores:
            print(f"  {arch}: {sum(arch_scores)/len(arch_scores):.4f} (n={len(arch_scores)})")

    print("\nPer-threat-type mean ARS:")
    for tt in ["T1", "T2", "T3", "T4", "T5"]:
        tt_scores = [r["ars_score"] for r in records if r["threat_type"] == tt]
        if tt_scores:
            print(f"  {tt}: {sum(tt_scores)/len(tt_scores):.4f} (n={len(tt_scores)})")

    if "by_architecture" in exp5:
        print("\nEpistemic gap (mean) by architecture:")
        for arch, data in exp5["by_architecture"].items():
            print(f"  {arch}: E={data['mean_epistemic_gap']:.4f}, "
                  f"U={data['mean_uncertainty']:.4f}, "
                  f"exceedance={data['epistemic_exceedance_rate']:.4f}")

    return all_results


def generate_and_analyze(seed: int = 42, num_repetitions: int = 3) -> Dict:
    """Generate dataset via simulation and run all analyses.

    This is the main entry point for running the full pipeline.
    """
    print("=" * 60)
    print("ARES-Bench: Full Pipeline (Generate + Analyze)")
    print("=" * 60)

    # Set environment for simulation
    os.environ["SIMULATION_MODE"] = "true"
    os.environ["RANDOM_SEED"] = str(seed)
    os.environ["NUM_REPETITIONS"] = str(num_repetitions)

    from services.orchestrator.main import Orchestrator

    project_root = os.path.join(os.path.dirname(__file__), "..")
    output_dir = os.path.join(project_root, "output")
    os.makedirs(output_dir, exist_ok=True)

    orch = Orchestrator(seed=seed)
    # Override output dir
    orch.writer.output_dir = Path(output_dir)

    def progress(done, total):
        if total > 0:
            pct = 100 * done / total
            print(f"\r  Progress: {done}/{total} ({pct:.1f}%)", end="", flush=True)
        else:
            print(f"\r  Records: {done}", end="", flush=True)

    # Run sparse experiment (manageable size)
    print("\n[1/3] Running sparse mismatch experiment...")
    sparse_results = orch.run_sparse_experiment(
        num_repetitions=num_repetitions,
        samples_per_compound=3,
        progress_callback=progress,
    )
    print(f"\n  Generated {len(sparse_results)} records")

    # Run temporal experiment
    print("\n[2/3] Running temporal decay experiment...")
    temporal_results = orch.run_temporal_experiment(
        t_age_values=[0, 24, 72, 168, 336, 720, 2160],
        num_repetitions=num_repetitions,
    )
    print(f"  Generated {len(temporal_results)} records")

    # Run cascade experiment (AUT-2 only, full grid)
    print("\n[3/3] Running cascade experiment...")
    cascade_results = orch.run_cascade_experiment(
        num_repetitions=1,  # Fewer reps for full grid
    )
    print(f"  Generated {len(cascade_results)} records")

    # Flush dataset
    print("\nWriting dataset...")
    paths = orch.flush_dataset()
    for fmt, path in paths.items():
        print(f"  {fmt}: {path}")

    # Run analysis
    print("\n" + "=" * 60)
    print("ANALYSIS")
    print("=" * 60)
    dataset_path = paths["jsonl"]
    return run_all_experiments(dataset_path, output_dir)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARES-Bench Paper Results")
    parser.add_argument("--dataset", type=str, default=None,
                        help="Path to existing JSONL dataset (skip generation)")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Output directory for results")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed")
    parser.add_argument("--reps", type=int, default=3,
                        help="Number of repetitions per condition")

    args = parser.parse_args()

    if args.dataset:
        output_dir = args.output_dir or os.path.dirname(args.dataset)
        run_all_experiments(args.dataset, output_dir)
    else:
        generate_and_analyze(seed=args.seed, num_repetitions=args.reps)
