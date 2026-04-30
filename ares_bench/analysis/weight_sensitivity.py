"""Weight-vector sensitivity analysis for ARES (paper experiment E7).

Three analyses on the SOCAgentFailure-1K labelled subset:

  (i)   Perturbation sweep: random multiplicative noise of +/- 10/20/30%
        on the per-class weight vectors, refit theta*, report mean +- std
        test F1 over 50 trials per noise level.
  (ii)  Leave-one-dimension-out: zero each of {S, K, C, R, T} in turn,
        renormalise the remaining four, refit theta*, report test F1.
  (iii) Alternative fitting methods: refit *global* weights via OLS,
        Lasso (alpha=0.01, 0.1), ElasticNet, and Ridge; report learned
        weights and test F1 for each.

Inputs:
  ../output/socagentfailure_1k.csv  (1,000 labelled records, has a
                                     pre-existing 60/20/20 `split` column)

Outputs:
  ../output/weight_sensitivity.json  (raw numbers for E7 tables)

Run:
  python weight_sensitivity.py \
      --input ../output/socagentfailure_1k.csv \
      --output ../output/weight_sensitivity.json \
      --seed 42 \
      --n-trials 50
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import ElasticNet, Lasso, LinearRegression, Ridge
from sklearn.metrics import f1_score, precision_recall_fscore_support

# Reuse the canonical per-class weight vectors so the script and the
# bench cannot drift apart.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.shared_models import WEIGHT_VECTORS  # type: ignore  # noqa: E402

DIMS = ["delta_S", "delta_K", "delta_C", "delta_R", "delta_T"]
DIM_LABELS = ["S", "K", "C", "R", "T"]
THRESHOLD_GRID = np.arange(0.0, 1.01, 0.01)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def compute_ars(df: pd.DataFrame, weights: Dict[str, np.ndarray]) -> np.ndarray:
    """ARS = 1 - w_tau . delta, clamped to [0, 1]."""
    out = np.empty(len(df))
    deltas = df[DIMS].to_numpy()
    threats = df["threat_type"].to_numpy()
    for i in range(len(df)):
        w = weights[threats[i]]
        out[i] = 1.0 - float(np.dot(w, deltas[i]))
    return np.clip(out, 0.0, 1.0)


def best_threshold(y_true: np.ndarray, ars: np.ndarray) -> Tuple[float, float]:
    """Sweep theta in [0, 1] step 0.01 maximising F1; returns (theta*, F1)."""
    best_t, best_f1 = 0.5, -1.0
    for t in THRESHOLD_GRID:
        pred = (ars <= t).astype(int)
        f1 = f1_score(y_true, pred, zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = float(t), float(f1)
    return best_t, best_f1


def evaluate(
    df: pd.DataFrame, weights: Dict[str, np.ndarray]
) -> Tuple[float, float, float]:
    """Fit theta* on train+val, evaluate on test. Returns (theta*, train F1, test F1)."""
    ars = compute_ars(df, weights)
    is_train = df["split"].isin(["train", "validation"]).to_numpy()
    is_test = (df["split"] == "test").to_numpy()
    y = df["anomaly_flag"].astype(int).to_numpy()
    theta, train_f1 = best_threshold(y[is_train], ars[is_train])
    test_pred = (ars[is_test] <= theta).astype(int)
    test_f1 = float(f1_score(y[is_test], test_pred, zero_division=0))
    return theta, float(train_f1), test_f1


def normalise(w: np.ndarray) -> np.ndarray:
    s = float(np.abs(w).sum())
    return w / s if s > 0 else w


# ---------------------------------------------------------------------------
# (i) Perturbation sweep
# ---------------------------------------------------------------------------


def perturbation_sweep(
    df: pd.DataFrame, base_weights: Dict[str, np.ndarray], n_trials: int, seed: int
) -> Dict:
    rng = np.random.default_rng(seed)
    levels = [0.10, 0.20, 0.30]
    out: Dict[str, Dict] = {}
    for level in levels:
        f1s: List[float] = []
        for _ in range(n_trials):
            perturbed = {
                k: normalise(np.clip(w * (1 + rng.uniform(-level, level, size=w.shape)), 0.0, None))
                for k, w in base_weights.items()
            }
            _, _, test_f1 = evaluate(df, perturbed)
            f1s.append(test_f1)
        out[f"+/-{int(level*100)}%"] = {
            "n_trials": n_trials,
            "mean_test_f1": float(np.mean(f1s)),
            "std_test_f1": float(np.std(f1s)),
        }
    return out


# ---------------------------------------------------------------------------
# (ii) Leave-one-dimension-out
# ---------------------------------------------------------------------------


def leave_one_out(
    df: pd.DataFrame, base_weights: Dict[str, np.ndarray]
) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for idx, name in enumerate(DIM_LABELS):
        weights = {}
        for tk, w in base_weights.items():
            wcopy = w.copy()
            wcopy[idx] = 0.0
            weights[tk] = normalise(wcopy)
        theta, train_f1, test_f1 = evaluate(df, weights)
        out[name] = {"theta": theta, "train_f1": train_f1, "test_f1": test_f1}
    return out


# ---------------------------------------------------------------------------
# (iii) Alternative fitting methods (global weights)
# ---------------------------------------------------------------------------


def fit_global_weights(df: pd.DataFrame) -> Dict[str, Dict]:
    """Refit a single global weight vector via OLS / Lasso / ElasticNet / Ridge.

    Target: y = 1 - ars_score (so the linear model `w . delta = y` recovers
    the canonical ARS = 1 - w.delta formulation). Train on the
    train+validation rows, evaluate on test.
    """
    is_train = df["split"].isin(["train", "validation"]).to_numpy()
    X = df[DIMS].to_numpy()
    y = (1.0 - df["ars_score"].to_numpy())
    Xtr, ytr = X[is_train], y[is_train]

    fitters = {
        "OLS": LinearRegression(positive=True, fit_intercept=False),
        "Lasso α=0.01": Lasso(alpha=0.01, positive=True, fit_intercept=False, max_iter=5000),
        "Lasso α=0.1": Lasso(alpha=0.1, positive=True, fit_intercept=False, max_iter=5000),
        "ElasticNet": ElasticNet(alpha=0.1, l1_ratio=0.5, positive=True, fit_intercept=False, max_iter=5000),
        "Ridge global": Ridge(alpha=1.0, fit_intercept=False),
    }
    out: Dict[str, Dict] = {}
    for name, model in fitters.items():
        model.fit(Xtr, ytr)
        w = np.clip(model.coef_, 0.0, None)
        w = normalise(w) if w.sum() > 0 else w
        global_weights = {tk: w for tk in WEIGHT_VECTORS.keys()}
        theta, _, test_f1 = evaluate(df, global_weights)
        out[name] = {
            "weights": {DIM_LABELS[i]: float(round(w[i], 3)) for i in range(5)},
            "theta": theta,
            "test_f1": test_f1,
        }
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-trials", type=int, default=50)
    args = p.parse_args()

    df = pd.read_csv(args.input)
    df["anomaly_flag"] = df["anomaly_flag"].map({"True": True, "False": False, True: True, False: False})
    df = df.dropna(subset=DIMS + ["anomaly_flag", "split", "threat_type", "ars_score"])

    base_weights = {tk: np.array(v, dtype=float) for tk, v in WEIGHT_VECTORS.items()}

    baseline_theta, baseline_train_f1, baseline_test_f1 = evaluate(df, base_weights)
    print(
        f"Baseline (per-class Ridge from shared_models): theta*={baseline_theta:.2f}, "
        f"train F1={baseline_train_f1:.3f}, test F1={baseline_test_f1:.3f}"
    )

    payload = {
        "n_records": int(len(df)),
        "seed": args.seed,
        "baseline": {
            "theta": baseline_theta,
            "train_f1": baseline_train_f1,
            "test_f1": baseline_test_f1,
        },
        "perturbation_sweep": perturbation_sweep(df, base_weights, args.n_trials, args.seed),
        "leave_one_out": leave_one_out(df, base_weights),
        "alternative_fitters": fit_global_weights(df),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, default=str))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
