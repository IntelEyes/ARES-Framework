#!/usr/bin/env python3
"""Calibration / uncertainty baseline comparison for the 600-run calibration-gap study.

Answers reviewer R1-4 (IEEE S&P SPSI-2026-05-0184): compare the ARES Epistemic
Gap against the standard calibration and uncertainty-estimation baselines.

Baselines computed from output/calibration_gap_runs.json (no new API calls):
  * Expected Calibration Error (ECE) and Brier score of the agent's expressed
    confidence  [Guo et al., On Calibration of Modern Neural Networks, ICML 2017]
  * Fabrication-risk detection AUROC for three signals:
      - Epistemic Gap  E = delta_K * (1 - U) = delta_K * confidence
      - raw verbalized confidence  [Tian et al., Just Ask for Calibration, EMNLP 2023]
      - raw knowledge deficit delta_K
  * Confidence-ordered selective prediction risk-coverage
    [El-Yaniv & Wiener, JMLR 2010; Geifman & El-Yaniv, NeurIPS 2017]

Stdlib only. Usage:  python3 calibration_baseline.py [runs.json]
"""
import json
import math
import os
import sys


def is_num(x):
    return isinstance(x, (int, float)) and not (isinstance(x, float) and math.isnan(x))


def ece(rows, nbins=10):
    bins = [[] for _ in range(nbins)]
    for r in rows:
        bins[min(int(r["confidence"] * nbins), nbins - 1)].append(r)
    n, e = len(rows), 0.0
    for b in bins:
        if not b:
            continue
        acc = sum(1 for r in b if r["correct"]) / len(b)
        conf = sum(r["confidence"] for r in b) / len(b)
        e += len(b) / n * abs(acc - conf)
    return e


def brier(rows):
    return sum((r["confidence"] - (1 if r["correct"] else 0)) ** 2 for r in rows) / len(rows)


def auroc(rows, score, label):
    pos = [score(r) for r in rows if label(r)]
    neg = [score(r) for r in rows if not label(r)]
    if not pos or not neg:
        return float("nan")
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in pos for b in neg)
    return wins / (len(pos) * len(neg))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "output", "calibration_gap_runs.json")
    runs = json.load(open(path))
    if isinstance(runs, dict):
        runs = runs.get("runs") or list(runs.values())

    answered = [r for r in runs if not r["abstain"] and is_num(r.get("confidence"))]
    conf = lambda r: r["confidence"] if is_num(r.get("confidence")) else 0.0
    valid = [r for r in runs if not r["err"]]
    fab = lambda r: r["fabricate"]

    result = {
        "n_runs": len(runs),
        "n_answered": len(answered),
        "calibration": {
            "ece_pooled": round(ece(answered), 3),
            "brier_pooled": round(brier(answered), 3),
            "accuracy_answered": round(sum(1 for r in answered if r["correct"]) / len(answered), 3),
        },
        "fabrication_detector_auroc": {
            "epistemic_gap": round(auroc(valid, lambda r: r["delta_K"] * conf(r), fab), 3),
            "raw_confidence": round(auroc(valid, conf, fab), 3),
            "raw_delta_K": round(auroc(valid, lambda r: r["delta_K"], fab), 3),
        },
        "selective_prediction_risk_coverage": {},
    }
    srt = sorted(answered, key=lambda r: -r["confidence"])
    for cov in (0.25, 0.5, 0.75, 1.0):
        k = max(1, int(cov * len(srt)))
        result["selective_prediction_risk_coverage"][f"{cov:.2f}"] = round(
            sum(1 for r in srt[:k] if not r["correct"]) / k, 3
        )

    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    main()
