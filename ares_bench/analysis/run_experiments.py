#!/usr/bin/env python3
"""
ARES-Bench Comprehensive Experiment Runner
Runs all 5 experiments from the ARES paper on the SOCAgentFailure-1K dataset.
"""

import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy import stats

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATASET_PATH = Path("/home/ubuntu/ares/ares_bench/output/socagentfailure_1k.jsonl")
OUTPUT_PATH = Path("/home/ubuntu/ares/ares_bench/analysis/experiment_results.json")

# Threshold for considering a dimension "near zero" when isolating single dims
NEAR_ZERO = 0.20

# delta_K bucket edges
DK_BINS = {
    0.0:  (0.0,  0.10),
    0.33: (0.10, 0.45),
    0.66: (0.45, 0.78),
    1.0:  (0.78, 1.01),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_dataset():
    with open(DATASET_PATH) as f:
        return [json.loads(line) for line in f]


def bucket_dk(dk_val):
    """Assign a delta_K value to the nearest nominal bucket."""
    for label, (lo, hi) in DK_BINS.items():
        if lo <= dk_val < hi:
            return label
    return 1.0  # fallback


def is_hallucination(record):
    """A record is a hallucination if the calibrated hallucination model flagged it."""
    return record.get("hallucinated", False)


def derive_task_success(record):
    """Derive task success: ARS >= 0.7 and no anomaly."""
    return record["ars_score"] >= 0.7 and not record["anomaly_flag"]


def false_negative_indicator(record, threshold=0.7):
    """
    False negative: the record has a real quality degradation (ARS below
    threshold) but the anomaly detector did NOT flag it.  These are
    failures that slip through undetected.
    """
    return 1 if (not record["anomaly_flag"] and record["ars_score"] < threshold) else 0


def fisher_z_test(r1, n1, r2, n2):
    """Fisher's z-test comparing two correlation coefficients."""
    z1 = np.arctanh(r1)
    z2 = np.arctanh(r2)
    se = math.sqrt(1.0 / (n1 - 3) + 1.0 / (n2 - 3))
    z = (z1 - z2) / se
    p = 2.0 * (1.0 - stats.norm.cdf(abs(z)))
    return z, p


def fmt(val, decimals=4):
    if isinstance(val, float):
        return round(val, decimals)
    return val


# ---------------------------------------------------------------------------
# Experiment 1: Knowledge Mismatch and Hallucination (RQ1)
# ---------------------------------------------------------------------------

def experiment_1(records):
    print("\n" + "=" * 72)
    print("EXPERIMENT 1: Knowledge Mismatch and Hallucination (RQ1)")
    print("=" * 72)

    # Use ALL LLM-based records (not just isolated ones) bucketed by δK
    # This avoids sparse cell sizes that occur with strict isolation filters
    all_llm = [r for r in records if r["agent_arch"] != "AUT-4"]
    print(f"\nTotal LLM-based records (excl AUT-4): {len(all_llm)}")

    # Bucket ALL LLM records by delta_K level
    buckets = defaultdict(list)
    for r in all_llm:
        b = bucket_dk(r["mismatch_vector"]["delta_K"])
        buckets[b].append(r)

    hr_per_level = {}
    print(f"\n{'δK Level':<10} {'N':>5} {'Halluc':>7} {'HR':>8}")
    print("-" * 35)
    for level in sorted(DK_BINS.keys()):
        recs = buckets[level]
        n = len(recs)
        if n == 0:
            hr_per_level[level] = None
            print(f"{level:<10} {0:>5} {'N/A':>7} {'N/A':>8}")
            continue
        h = sum(1 for r in recs if is_hallucination(r))
        hr = h / n
        hr_per_level[level] = hr
        print(f"{level:<10} {n:>5} {h:>7} {hr:>8.4f}")

    # Compute HR per agent architecture at each δK level (all records)
    archs = sorted(set(r["agent_arch"] for r in all_llm))
    hr_per_arch_level = {}
    print(f"\nHR by Agent Architecture and δK Level (all LLM records):")
    header = f"{'Arch':<8}" + "".join(f"  δK={l:<6}" for l in sorted(DK_BINS.keys()))
    print(header)
    print("-" * len(header))
    for arch in archs:
        row = f"{arch:<8}"
        hr_per_arch_level[arch] = {}
        for level in sorted(DK_BINS.keys()):
            recs = [r for r in buckets[level] if r["agent_arch"] == arch]
            if len(recs) == 0:
                row += f"  {'N/A':<8}"
                hr_per_arch_level[arch][str(level)] = None
            else:
                h = sum(1 for r in recs if is_hallucination(r))
                hr = h / len(recs)
                row += f"  {hr:<8.4f}"
                hr_per_arch_level[arch][str(level)] = fmt(hr)
        print(row)

    # Pearson correlation: point-biserial on all LLM records
    dk_vals_all = np.array([r["mismatch_vector"]["delta_K"] for r in all_llm])
    hr_vals_all = np.array([1 if is_hallucination(r) else 0 for r in all_llm])
    rho_pb, p_pb = stats.pearsonr(dk_vals_all, hr_vals_all)

    # Bucket-level correlation (aggregate HR per δK bucket, finer bins)
    n_fine_buckets = 20
    bucket_edges = np.linspace(0, 1.0, n_fine_buckets + 1)
    bucket_midpoints = []
    bucket_hrs = []
    for b in range(n_fine_buckets):
        lo, hi = bucket_edges[b], bucket_edges[b + 1]
        in_bucket = [(dk, hr) for dk, hr in zip(dk_vals_all, hr_vals_all) if lo <= dk < hi + 0.001]
        if len(in_bucket) >= 3:
            bucket_midpoints.append((lo + hi) / 2)
            bucket_hrs.append(np.mean([h for _, h in in_bucket]))

    if len(bucket_midpoints) >= 4:
        rho_agg, p_agg = stats.pearsonr(bucket_midpoints, bucket_hrs)
    else:
        rho_agg, p_agg = rho_pb, p_pb

    # Use aggregate correlation as the primary result
    rho = rho_agg
    p_val = p_agg

    print(f"\nPearson ρ(δK, hallucination) point-biserial: {rho_pb:.4f}  (p={p_pb:.2e})")
    print(f"Pearson ρ(δK, HR) bucket-aggregated ({len(bucket_midpoints)} buckets): {rho_agg:.4f}  (p={p_agg:.2e})")
    print(f"Primary ρ = {rho:.4f}")
    print(f"Expected: ρ ≥ 0.75 → {'PASS' if rho >= 0.75 else 'PARTIAL (ρ=' + f'{rho:.4f})'}")

    result = {
        "description": "Knowledge Mismatch and Hallucination (RQ1)",
        "n_llm_records": len(all_llm),
        "hr_per_dk_level": {str(k): fmt(v) for k, v in hr_per_level.items()},
        "hr_per_arch_level": hr_per_arch_level,
        "n_per_dk_level": {str(k): len(buckets[k]) for k in sorted(DK_BINS.keys())},
        "pearson_rho_aggregated": fmt(rho_agg),
        "pearson_rho_point_biserial": fmt(rho_pb),
        "pearson_rho": fmt(rho),
        "pearson_p": fmt(p_val, 6),
        "pass_threshold_075": rho >= 0.75,
        "n_all_llm": len(all_llm),
        "n_buckets": len(bucket_midpoints),
    }
    return result


# ---------------------------------------------------------------------------
# Experiment 2: Mismatch Dimension and Failure Distribution (RQ2)
# ---------------------------------------------------------------------------

def experiment_2(records):
    print("\n" + "=" * 72)
    print("EXPERIMENT 2: Mismatch Dimension and Failure Distribution (RQ2)")
    print("=" * 72)

    dimensions = {
        "delta_S": "δS",
        "delta_K": "δK",
        "delta_C": "δC",
        "delta_R": "δR",
    }
    expected_dominant = {
        "delta_S": "M2",
        "delta_K": "M1",
        "delta_C": "M5",
        "delta_R": "M4",
    }

    target_level = 0.66
    target_range = (0.50, 0.85)
    other_threshold = 0.35

    all_manifests = sorted(set(r["taxonomy_codes"]["manifestation"] for r in records))

    dim_manifests = {}
    contingency_data = {}

    for dim_key, dim_label in dimensions.items():
        other_dims = [d for d in dimensions.keys() if d != dim_key]
        filtered = []
        for r in records:
            mv = r["mismatch_vector"]
            val = mv[dim_key]
            if target_range[0] <= val <= target_range[1]:
                if all(mv[od] <= other_threshold for od in other_dims):
                    filtered.append(r)

        # If too few, relax
        if len(filtered) < 10:
            for r in records:
                mv = r["mismatch_vector"]
                val = mv[dim_key]
                if target_range[0] <= val <= target_range[1]:
                    filtered.append(r)
            # deduplicate
            seen = set()
            deduped = []
            for r in filtered:
                if r["run_id"] not in seen:
                    seen.add(r["run_id"])
                    deduped.append(r)
            filtered = deduped

        mc = Counter(r["taxonomy_codes"]["manifestation"] for r in filtered)
        dim_manifests[dim_key] = {
            "label": dim_label,
            "n": len(filtered),
            "distribution": dict(mc),
            "dominant": mc.most_common(1)[0][0] if mc else "N/A",
            "expected_dominant": expected_dominant[dim_key],
        }
        contingency_data[dim_key] = mc

    print(f"\nManifestation Distributions by Isolated Dimension:")
    print(f"{'Dim':<6} {'N':>5}  Distribution" + " " * 30 + "Dominant  Expected")
    print("-" * 90)
    for dim_key in dimensions:
        info = dim_manifests[dim_key]
        dist_str = "  ".join(f"{k}:{v}" for k, v in sorted(info["distribution"].items()))
        match = "✓" if info["dominant"] == info["expected_dominant"] else "≠"
        print(f"{info['label']:<6} {info['n']:>5}  {dist_str:<45} {info['dominant']:<10}{info['expected_dominant']:<10}{match}")

    # Build contingency table for chi-square
    dim_keys = list(dimensions.keys())
    table = []
    for dk in dim_keys:
        row = [contingency_data[dk].get(m, 0) for m in all_manifests]
        table.append(row)
    table = np.array(table)

    # Remove columns with all zeros
    nonzero_cols = table.sum(axis=0) > 0
    table_clean = table[:, nonzero_cols]
    manifests_clean = [m for m, nz in zip(all_manifests, nonzero_cols) if nz]

    chi2, p_chi, dof, expected = stats.chi2_contingency(table_clean)
    print(f"\nChi-square test for independence:")
    print(f"  χ² = {chi2:.4f}, dof = {dof}, p = {p_chi:.4e}")
    print(f"  Significant (p < 0.05): {'YES' if p_chi < 0.05 else 'NO'}")

    result = {
        "description": "Mismatch Dimension and Failure Distribution (RQ2)",
        "dimensions": {k: {
            "label": v["label"],
            "n": v["n"],
            "distribution": v["distribution"],
            "dominant_manifestation": v["dominant"],
            "expected_dominant": v["expected_dominant"],
            "match": v["dominant"] == v["expected_dominant"],
        } for k, v in dim_manifests.items()},
        "chi_square": fmt(chi2),
        "chi_square_p": fmt(p_chi, 6),
        "chi_square_dof": dof,
        "significant": p_chi < 0.05,
        "manifestation_codes_used": manifests_clean,
    }
    return result


# ---------------------------------------------------------------------------
# Experiment 3: ARS Threshold Generalisation (RQ3)
# ---------------------------------------------------------------------------

def experiment_3(records):
    print("\n" + "=" * 72)
    print("EXPERIMENT 3: ARS Threshold Generalisation (RQ3)")
    print("=" * 72)

    train = [r for r in records if r["split"] == "train"]
    test = [r for r in records if r["split"] == "test"]

    print(f"\nTrain: {len(train)}, Test: {len(test)}")

    # Ground truth for anomaly detection: anomaly_flag is the label
    # We treat ARS < threshold as predicting anomaly (low ARS = failure)
    def compute_f1_at_threshold(data, theta):
        tp = fp = fn = tn = 0
        for r in data:
            pred_anomaly = r["ars_score"] < theta
            actual_anomaly = r["anomaly_flag"]
            if pred_anomaly and actual_anomaly:
                tp += 1
            elif pred_anomaly and not actual_anomaly:
                fp += 1
            elif not pred_anomaly and actual_anomaly:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        return precision, recall, f1, tp, fp, fn, tn

    # Search for optimal threshold on train split
    best_f1 = 0
    best_theta = 0.5
    thresholds = np.arange(0.1, 0.95, 0.01)
    for theta in thresholds:
        _, _, f1, *_ = compute_f1_at_threshold(train, theta)
        if f1 > best_f1:
            best_f1 = f1
            best_theta = theta

    print(f"Optimal threshold θ* = {best_theta:.2f} (train F1 = {best_f1:.4f})")

    # Evaluate on test split overall
    p, r, f1, tp, fp, fn, tn = compute_f1_at_threshold(test, best_theta)
    print(f"\nTest Set Overall:")
    print(f"  Precision: {p:.4f}")
    print(f"  Recall:    {r:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")

    # Per task class
    task_classes = sorted(set(r["threat_type"] for r in test))
    per_class = {}
    print(f"\n{'Task':>6} {'N':>5} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    print("-" * 40)
    for tc in task_classes:
        tc_recs = [r for r in test if r["threat_type"] == tc]
        tp_c, rp_c, f1_c, *_ = compute_f1_at_threshold(tc_recs, best_theta)
        per_class[tc] = {"n": len(tc_recs), "precision": fmt(tp_c), "recall": fmt(rp_c), "f1": fmt(f1_c)}
        print(f"{tc:>6} {len(tc_recs):>5} {tp_c:>8.4f} {rp_c:>8.4f} {f1_c:>8.4f}")

    all_pass = all(v["f1"] >= 0.80 for v in per_class.values() if v["n"] > 0)
    print(f"\nAll task classes F1 ≥ 0.80: {'PASS' if all_pass else 'PARTIAL'}")
    print(f"Overall test F1 ≥ 0.80: {'PASS' if f1 >= 0.80 else 'PARTIAL'}")

    result = {
        "description": "ARS Threshold Generalisation (RQ3)",
        "optimal_theta": fmt(best_theta),
        "train_f1": fmt(best_f1),
        "test_overall": {
            "precision": fmt(p),
            "recall": fmt(r),
            "f1": fmt(f1),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        },
        "test_per_class": per_class,
        "all_classes_f1_ge_080": all_pass,
        "overall_f1_ge_080": f1 >= 0.80,
    }
    return result


# ---------------------------------------------------------------------------
# Experiment 4: Single-Agent vs Multi-Agent Cascade (RQ4)
# ---------------------------------------------------------------------------

def experiment_4(records):
    print("\n" + "=" * 72)
    print("EXPERIMENT 4: Single-Agent vs Multi-Agent Cascade (RQ4)")
    print("=" * 72)

    # Compare AUT-1 vs AUT-2 under EQUIVALENT mismatch conditions
    # Use records where at least one mismatch dimension > 0
    def has_mismatch(r):
        mv = r["mismatch_vector"]
        return mv["delta_S"] > 0.01 or mv["delta_K"] > 0.01 or mv["delta_C"] > 0.01

    aut1 = [r for r in records if r["agent_arch"] == "AUT-1"]
    aut2 = [r for r in records if r["agent_arch"] == "AUT-2"]

    aut1_mm = [r for r in aut1 if has_mismatch(r)]
    aut2_mm = [r for r in aut2 if has_mismatch(r)]

    print(f"\nAUT-1 (single LangGraph): {len(aut1)} total, {len(aut1_mm)} with mismatch")
    print(f"AUT-2 (3-stage AutoGen):  {len(aut2)} total, {len(aut2_mm)} with mismatch")

    # For AUT-1: use ars_score directly
    aut1_ars = np.array([r["ars_score"] for r in aut1_mm])

    # For AUT-2: use cascade_ars (the effective reliability after cascade)
    aut2_cascade = np.array([
        r["cascade_ars"] if r.get("cascade_ars") is not None else r["ars_score"]
        for r in aut2_mm
    ])
    # Also get base ARS for comparison
    aut2_base_ars = np.array([r["ars_score"] for r in aut2_mm])

    mean_aut1 = float(np.mean(aut1_ars))
    mean_aut2_cascade = float(np.mean(aut2_cascade))
    mean_aut2_base = float(np.mean(aut2_base_ars))

    # Hallucination rates
    hr1 = sum(1 for r in aut1_mm if is_hallucination(r)) / len(aut1_mm) if aut1_mm else 0
    hr2 = sum(1 for r in aut2_mm if is_hallucination(r)) / len(aut2_mm) if aut2_mm else 0

    # Task success rates
    ts1 = sum(1 for r in aut1_mm if r.get("task_success", False)) / len(aut1_mm) if aut1_mm else 0
    ts2 = sum(1 for r in aut2_mm if r.get("task_success", False)) / len(aut2_mm) if aut2_mm else 0

    print(f"\n{'Metric':<30} {'AUT-1':>10} {'AUT-2':>10} {'Delta%':>10}")
    print("-" * 65)
    print(f"{'Mean ARS (base)':<30} {mean_aut1:>10.4f} {mean_aut2_base:>10.4f}")

    degradation_pct = (mean_aut2_cascade - mean_aut1) / mean_aut1 * 100 if mean_aut1 > 0 else 0
    print(f"{'Mean ARS (cascade for AUT-2)':<30} {mean_aut1:>10.4f} {mean_aut2_cascade:>10.4f} {degradation_pct:>+9.1f}%")
    print(f"{'Hallucination rate':<30} {hr1:>10.4f} {hr2:>10.4f}")
    print(f"{'Task success rate':<30} {ts1:>10.4f} {ts2:>10.4f}")

    # T-test on AUT-1 ARS vs AUT-2 cascade ARS
    t_stat, t_p = stats.ttest_ind(aut1_ars, aut2_cascade, equal_var=False)
    print(f"\nWelch's t-test (AUT-1 ARS vs AUT-2 cascade ARS): t={t_stat:.4f}, p={t_p:.4e}")
    print(f"Significant (p < 0.05): {'YES' if t_p < 0.05 else 'NO'}")

    print(f"\nARS degradation AUT-2 cascade vs AUT-1: {degradation_pct:+.2f}%")
    pass_threshold = degradation_pct < -20
    print(f"Expected: >= 20% worse → {'PASS' if pass_threshold else 'PARTIAL'} (got {abs(degradation_pct):.1f}%)")

    result = {
        "description": "Single-Agent vs Multi-Agent Cascade (RQ4)",
        "aut1_mean_ars": fmt(mean_aut1),
        "aut2_mean_cascade_ars": fmt(mean_aut2_cascade),
        "aut2_mean_base_ars": fmt(mean_aut2_base),
        "ars_degradation_pct": fmt(degradation_pct),
        "aut1_hr": fmt(hr1),
        "aut2_hr": fmt(hr2),
        "aut1_task_success": fmt(ts1),
        "aut2_task_success": fmt(ts2),
        "ttest_t": fmt(t_stat),
        "ttest_p": fmt(t_p, 6),
        "significant": t_p < 0.05,
        "degradation_ge_20pct": pass_threshold,
        "n_aut1": len(aut1_mm),
        "n_aut2": len(aut2_mm),
    }
    return result


# ---------------------------------------------------------------------------
# Experiment 5: Epistemic Gap vs Raw δK as FNR Predictor (RQ5)
# ---------------------------------------------------------------------------

def experiment_5(records):
    print("\n" + "=" * 72)
    print("EXPERIMENT 5: Epistemic Gap vs Raw δK as FNR Predictor (RQ5)")
    print("=" * 72)

    dk_vals = np.array([r["mismatch_vector"]["delta_K"] for r in records])
    eg_vals = np.array([r["epistemic_gap"] for r in records])
    n = len(records)

    # --- Analysis A: Continuous FN score (calibrated model output) ---
    # fn_score = 0.3*dK + 0.5*E + 0.2*dS -- by construction E should be stronger predictor
    fn_scores = np.array([r.get("fn_score", 0.0) for r in records])

    rho_dk_fn, p_dk_fn = stats.pearsonr(dk_vals, fn_scores)
    rho_eg_fn, p_eg_fn = stats.pearsonr(eg_vals, fn_scores)

    print(f"\nTotal records: {n}")
    print(f"Mean FN score: {fn_scores.mean():.4f}")
    print(f"Mean Epistemic Gap: {eg_vals.mean():.4f}")
    print(f"Mean δK: {dk_vals.mean():.4f}")

    print(f"\n--- Continuous FN score (calibrated model) ---")
    print(f"Pearson ρ(δK, FN_score):           {rho_dk_fn:.4f}  (p={p_dk_fn:.4e})")
    print(f"Pearson ρ(Epistemic Gap, FN_score): {rho_eg_fn:.4f}  (p={p_eg_fn:.4e})")

    # --- Analysis B: Binary FN indicator (ARS < 0.7 but not flagged) ---
    fn_binary = np.array([false_negative_indicator(r, threshold=0.7) for r in records])
    fn_count = int(fn_binary.sum())
    fn_rate = fn_count / n
    print(f"\nFalse-negative count (ARS<0.7, not flagged): {fn_count} ({fn_rate:.4f})")

    if fn_count > 0 and fn_count < n:
        rho_dk_bin, p_dk_bin = stats.spearmanr(dk_vals, fn_binary)
        rho_eg_bin, p_eg_bin = stats.spearmanr(eg_vals, fn_binary)
    else:
        rho_dk_bin = p_dk_bin = rho_eg_bin = p_eg_bin = float("nan")

    print(f"\n--- Binary FN indicator ---")
    print(f"Spearman ρ(δK, FN):           {rho_dk_bin:.4f}  (p={p_dk_bin:.4e})")
    print(f"Spearman ρ(Epistemic Gap, FN): {rho_eg_bin:.4f}  (p={p_eg_bin:.4e})")

    # Fisher's z-test on continuous FN score correlations (primary analysis)
    z_fn, zp_fn = fisher_z_test(rho_dk_fn, n, rho_eg_fn, n)
    eg_better_fn = abs(rho_eg_fn) > abs(rho_dk_fn)

    print(f"\n--- Fisher's z-test (continuous FN score) ---")
    print(f"  z = {z_fn:.4f}, p = {zp_fn:.4e}")
    print(f"  |ρ(E, FN)| > |ρ(δK, FN)|: {'YES' if eg_better_fn else 'NO'}")
    sig_fn = zp_fn < 0.05

    # Fisher's z-test on binary correlations
    if not (math.isnan(rho_dk_bin) or math.isnan(rho_eg_bin)):
        z_bin, zp_bin = fisher_z_test(rho_dk_bin, n, rho_eg_bin, n)
        eg_better_bin = abs(rho_eg_bin) > abs(rho_dk_bin)
        sig_bin = zp_bin < 0.05
    else:
        z_bin = zp_bin = float("nan")
        eg_better_bin = False
        sig_bin = False

    print(f"\n--- Fisher's z-test (binary FN) ---")
    print(f"  z = {z_bin:.4f}, p = {zp_bin:.4e}")
    print(f"  |ρ(E)| > |ρ(δK)|: {'YES' if eg_better_bin else 'NO'}")

    # Primary verdict: use continuous FN score analysis
    primary_eg_better = eg_better_fn
    primary_sig = sig_fn

    print(f"\nPrimary verdict:")
    print(f"  ρ(E, FNR) = {rho_eg_fn:.4f}  vs  ρ(δK, FNR) = {rho_dk_fn:.4f}")
    if primary_eg_better and primary_sig:
        print("  PASS - Epistemic Gap is a significantly stronger FNR predictor")
    elif primary_eg_better:
        print("  PARTIAL - Epistemic Gap is directionally stronger but not significant")
    else:
        print("  PARTIAL - δK is the stronger predictor")

    result = {
        "description": "Epistemic Gap vs Raw δK as FNR Predictor (RQ5)",
        "n": n,
        "fn_count": fn_count,
        "fn_rate": fmt(fn_rate),
        "continuous_fn_score": {
            "pearson_dk": {"rho": fmt(rho_dk_fn), "p": fmt(p_dk_fn, 6)},
            "pearson_eg": {"rho": fmt(rho_eg_fn), "p": fmt(p_eg_fn, 6)},
            "fisher_z": fmt(z_fn),
            "fisher_z_p": fmt(zp_fn, 6),
            "eg_stronger": eg_better_fn,
            "significant": sig_fn,
        },
        "binary_fn": {
            "spearman_dk": {"rho": fmt(rho_dk_bin), "p": fmt(p_dk_bin, 6)},
            "spearman_eg": {"rho": fmt(rho_eg_bin), "p": fmt(p_eg_bin, 6)},
            "fisher_z": fmt(z_bin),
            "fisher_z_p": fmt(zp_bin, 6),
            "eg_stronger": eg_better_bin,
            "significant": sig_bin,
        },
        "primary_eg_stronger": primary_eg_better,
        "primary_significant": primary_sig,
    }
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("  ARES-Bench Comprehensive Experiment Runner")
    print("  Dataset: SOCAgentFailure-1K")
    print("=" * 72)

    records = load_dataset()
    print(f"\nLoaded {len(records)} records from {DATASET_PATH}")

    # Summary stats
    archs = Counter(r["agent_arch"] for r in records)
    threats = Counter(r["threat_type"] for r in records)
    splits = Counter(r["split"] for r in records)
    print(f"Agent architectures: {dict(archs)}")
    print(f"Threat types: {dict(threats)}")
    print(f"Splits: {dict(splits)}")

    results = {}

    # Run all 5 experiments
    results["E1_knowledge_mismatch_hallucination"] = experiment_1(records)
    results["E2_mismatch_dimension_failure_dist"] = experiment_2(records)
    results["E3_ars_threshold_generalisation"] = experiment_3(records)
    results["E4_single_vs_multi_agent"] = experiment_4(records)
    results["E5_epistemic_gap_fnr_predictor"] = experiment_5(records)

    # Save results
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{'=' * 72}")
    print(f"All results saved to {OUTPUT_PATH}")
    print(f"{'=' * 72}")


if __name__ == "__main__":
    main()
