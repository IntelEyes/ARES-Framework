"""
AUT-2 single-stage ablation: separating pipeline-depth effect from framework
identity in the cascade degradation measurement.

Referenced in Paper 3 Section VII-D (E4 cascade analysis). The released
dataset records two ARS values per AUT-2 record:

  * ars_score   -- single-agent ARS computed from the overall mismatch vector
                   (the "AUT-2 run as if it were single-stage")
  * cascade_ars -- three-stage pipeline cascade ARS

Comparing these to AUT-1's ars_score lets us disentangle two effects:

  * AUT-2 single-stage vs AUT-1 single-stage = framework-identity effect
  * AUT-2 cascade vs AUT-2 single-stage      = pure pipeline-depth effect
  * AUT-2 cascade vs AUT-1 single-stage      = combined (what the paper reports)

The comparison is done on matched mismatch conditions (common buckets) to
eliminate mismatch-distribution confound.

Output: ares_bench/output/cascade_ablation.json
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "output" / "socagentfailure_1k.jsonl"
OUT = ROOT / "output" / "cascade_ablation.json"


def bucket_key(mv: dict) -> tuple:
    """Discretise mismatch vector into comparable buckets."""
    def q(x):
        return round(float(x) * 3) / 3  # {0, 0.33, 0.66, 1.0}
    return (q(mv["delta_S"]), q(mv["delta_K"]), q(mv["delta_C"]), q(mv["delta_R"]))


def main() -> None:
    aut1_by_bucket: dict = defaultdict(list)
    aut2_single_by_bucket: dict = defaultdict(list)
    aut2_cascade_by_bucket: dict = defaultdict(list)

    with DATASET.open() as f:
        for line in f:
            rec = json.loads(line)
            arch = rec["agent_arch"]
            mv = rec["mismatch_vector"]
            key = bucket_key(mv)
            if arch == "AUT-1":
                aut1_by_bucket[key].append(rec["ars_score"])
            elif arch == "AUT-2":
                aut2_single_by_bucket[key].append(rec["ars_score"])
                cas = rec.get("cascade_ars")
                if cas is not None:
                    aut2_cascade_by_bucket[key].append(cas)

    common = (
        set(aut1_by_bucket)
        & set(aut2_single_by_bucket)
        & set(aut2_cascade_by_bucket)
    )

    aut1_means, a2s_means, a2c_means = [], [], []
    for k in common:
        aut1_means.append(np.mean(aut1_by_bucket[k]))
        a2s_means.append(np.mean(aut2_single_by_bucket[k]))
        a2c_means.append(np.mean(aut2_cascade_by_bucket[k]))

    aut1 = float(np.mean(aut1_means)) if aut1_means else float("nan")
    a2s = float(np.mean(a2s_means)) if a2s_means else float("nan")
    a2c = float(np.mean(a2c_means)) if a2c_means else float("nan")

    out = {
        "n_common_buckets": len(common),
        "aut1_ars_matched": round(aut1, 4),
        "aut2_single_stage_ars_matched": round(a2s, 4),
        "aut2_cascade_ars_matched": round(a2c, 4),
        "framework_identity_effect_pct": round(
            100.0 * (aut1 - a2s) / aut1, 2
        ) if aut1 else None,
        "pipeline_depth_effect_pct": round(
            100.0 * (a2s - a2c) / a2s, 2
        ) if a2s else None,
        "combined_effect_pct": round(
            100.0 * (aut1 - a2c) / aut1, 2
        ) if aut1 else None,
        "interpretation": (
            "framework_identity_effect: AUT-2's single-stage ARS vs AUT-1's "
            "single-stage ARS under matched mismatch; isolates framework bias. "
            "pipeline_depth_effect: AUT-2's cascade ARS vs AUT-2's single-stage "
            "ARS; isolates the pure cascade degradation. "
            "combined_effect: AUT-2 cascade vs AUT-1 single-stage; matches the "
            "5.7% headline previously reported in E4."
        ),
    }

    OUT.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
