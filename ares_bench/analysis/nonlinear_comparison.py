"""
Nonlinear-vs-linear ARS weight learning comparison.

Referenced in Paper 3 Section IV-D (linear formulation justification). Fits:
  - Ridge regression (baseline, per-class and global)
  - Random Forest regressor
  - Gradient-Boosted regressor

on the 5-D mismatch vector -> anomaly_flag mapping using the released
SOCAgentFailure-1K dataset and the 60/20/20 train/val/test split. Reports
test R^2 and cross-validation fold variance.

Output: ares_bench/output/nonlinear_comparison.json
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor
from sklearn.linear_model import Ridge
from sklearn.metrics import r2_score, roc_auc_score
from sklearn.model_selection import KFold

SEED = 42
FEATURES = ["delta_S", "delta_K", "delta_C", "delta_R", "delta_T"]
TARGET = "anomaly_flag"

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "output" / "socagentfailure_1k.csv"
OUT = ROOT / "output" / "nonlinear_comparison.json"


def split_train_test(df: pd.DataFrame):
    train = df[df["split"] == "train"]
    test = df[df["split"] == "test"]
    X_train, y_train = train[FEATURES].values, train[TARGET].astype(float).values
    X_test, y_test = test[FEATURES].values, test[TARGET].astype(float).values
    return X_train, y_train, X_test, y_test


def fit_and_eval(model, X_train, y_train, X_test, y_test):
    model.fit(X_train, y_train)
    y_hat = np.clip(model.predict(X_test), 0.0, 1.0)
    r2 = r2_score(y_test, y_hat)
    auroc = roc_auc_score(y_test, y_hat) if len(set(y_test)) > 1 else float("nan")
    return r2, auroc


def cv_metrics_std(model_ctor, X, y, k: int = 5):
    kf = KFold(n_splits=k, shuffle=True, random_state=SEED)
    r2_scores, auroc_scores = [], []
    for tr, te in kf.split(X):
        m = model_ctor()
        m.fit(X[tr], y[tr])
        y_hat = np.clip(m.predict(X[te]), 0.0, 1.0)
        r2_scores.append(r2_score(y[te], y_hat))
        if len(set(y[te])) > 1:
            auroc_scores.append(roc_auc_score(y[te], y_hat))
    return (
        float(np.mean(r2_scores)),
        float(np.std(r2_scores)),
        float(np.mean(auroc_scores)) if auroc_scores else float("nan"),
        float(np.std(auroc_scores)) if auroc_scores else float("nan"),
    )


def main() -> None:
    df = pd.read_csv(DATASET)
    X_train, y_train, X_test, y_test = split_train_test(df)

    ridge_ctor = lambda: Ridge(alpha=1.0, random_state=SEED)
    rf_ctor = lambda: RandomForestRegressor(
        n_estimators=200, max_depth=None, random_state=SEED, n_jobs=-1
    )
    gbm_ctor = lambda: GradientBoostingRegressor(
        n_estimators=200, max_depth=3, learning_rate=0.05, random_state=SEED
    )

    models = {
        "Ridge (global)": ridge_ctor,
        "Random Forest": rf_ctor,
        "Gradient Boosting": gbm_ctor,
    }

    results = {}
    X_all = df[FEATURES].values
    y_all = df[TARGET].astype(float).values

    for name, ctor in models.items():
        test_r2, test_auroc = fit_and_eval(ctor(), X_train, y_train, X_test, y_test)
        cv_r2_mean, cv_r2_std, cv_auroc_mean, cv_auroc_std = cv_metrics_std(
            ctor, X_all, y_all, k=5
        )
        results[name] = {
            "test_r2": round(test_r2, 4),
            "test_auroc": round(test_auroc, 4),
            "cv5_mean_r2": round(cv_r2_mean, 4),
            "cv5_std_r2": round(cv_r2_std, 4),
            "cv5_mean_auroc": round(cv_auroc_mean, 4),
            "cv5_std_auroc": round(cv_auroc_std, 4),
        }

    out = {
        "seed": SEED,
        "target": TARGET,
        "features": FEATURES,
        "n_train": int((df["split"] == "train").sum()),
        "n_test": int((df["split"] == "test").sum()),
        "n_total": int(len(df)),
        "models": results,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
