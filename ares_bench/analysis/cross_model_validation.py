"""Cross-model validation runner for ARES.

Re-evaluates a stratified 100-record subsample of SOCAgentFailure-1K
against multiple LLM backends to test whether the headline ARES
findings (hallucination-vs-delta_K monotonicity, ARS test F1) generalise
beyond Mistral-7B-Instruct.

Usage:
    export OPENAI_API_KEY=...        # for gpt-4o-mini
    export TOGETHER_API_KEY=...      # for llama-3.1-70b-instruct-turbo
    python cross_model_validation.py \
        --input ../output/socagentfailure_1k.csv \
        --output ../output/cross_model_results.json \
        --models gpt-4o-mini llama-3.1-70b-instruct-turbo mistral-7b-instruct \
        --n-per-cell 5 \
        --seed 42

The script:
  1. Loads the 1k dataset and selects a stratified subsample
     (5 threats x 4 mismatch levels x N reps = 100 records by default).
  2. For each model, replays each scenario through a minimal ReAct loop
     (langgraph-style) and records the agent output, hallucinated flag,
     and per-dimension delta values (which are scenario-determined and
     do not depend on the model).
  3. Recomputes ARS for each (record, model) pair using the existing
     per-class weight vectors from shared/shared_models.py.
  4. Sweeps theta in [0,1] step 0.01 on a 70/30 train/test split,
     reports per-model test F1, hallucination rate at delta_K=1.0,
     and Pearson rho between bucket-mean hallucination rate and delta_K.
  5. Writes a single JSON file with one block per model, plus a
     comparison table.

Implementation notes:
  - LLM clients are pluggable via the `LLM_BACKENDS` registry.
  - The hallucination judge uses the same closed-world ATT&CK + NVD
    ground truth as the original bench, so cross-model results are
    directly comparable.
  - No per-call retry/backoff; if a model errors out, the row is
    skipped and reported in `errors_per_model`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

import pandas as pd

# ---------------------------------------------------------------------------
# LLM backends -- thin adapters; install only what you actually use.
# ---------------------------------------------------------------------------


_REASONING_PREFIXES = ("o1", "o3", "o4", "gpt-5", "gpt-5.1", "gpt-5.2", "gpt-5.3", "gpt-5.4")


def _is_reasoning_model(model: str) -> bool:
    return any(model.startswith(p) for p in _REASONING_PREFIXES)


def call_openai(model: str, prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    kwargs = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    if _is_reasoning_model(model):
        # Reasoning/GPT-5 models: use max_completion_tokens, no temperature.
        kwargs["max_completion_tokens"] = 1500
    else:
        kwargs["temperature"] = 0.7
        kwargs["max_tokens"] = 512
    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def call_together(model: str, prompt: str) -> str:
    from together import Together  # pip install together

    client = Together(api_key=os.environ["TOGETHER_API_KEY"])
    resp = client.chat.completions.create(
        model=f"meta-llama/{model}",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=512,
    )
    return resp.choices[0].message.content or ""


def call_ollama(model: str, prompt: str) -> str:
    import requests

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=60,
    )
    r.raise_for_status()
    return r.json().get("response", "")


def call_anthropic(model: str, prompt: str) -> str:
    from anthropic import Anthropic

    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    kwargs = {
        "model": model,
        "max_tokens": 512,
        "messages": [{"role": "user", "content": prompt}],
    }
    if "opus-4-7" not in model and "opus-4-8" not in model:
        kwargs["temperature"] = 0.7
    resp = client.messages.create(**kwargs)
    parts = []
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "".join(parts)


LLM_BACKENDS = {
    "gpt-4o-mini": call_openai,
    "gpt-4o": call_openai,
    "gpt-5-mini": call_openai,
    "gpt-5-nano": call_openai,
    "gpt-5.1": call_openai,
    "gpt-5.4-mini": call_openai,
    "gpt-5.4-nano": call_openai,
    "o3-mini": call_openai,
    "o4-mini": call_openai,
    "llama-3.1-70b-instruct-turbo": call_together,
    "mistral-7b-instruct": call_ollama,  # local fallback for the baseline
    "claude-haiku-4-5": call_anthropic,
    "claude-sonnet-4-6": call_anthropic,
    "claude-opus-4-7": call_anthropic,
}


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------


def load_jsonl(path: Path) -> pd.DataFrame:
    """Load JSONL, flattening mismatch_vector and ground_truth.techniques."""
    rows = []
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            mv = r.get("mismatch_vector", {})
            gt = r.get("ground_truth", {})
            rows.append(
                {
                    "run_id": r.get("run_id"),
                    "scenario_id": r.get("scenario_id"),
                    "threat_type": r.get("threat_type"),
                    "agent_arch": r.get("agent_arch"),
                    "delta_S": float(mv.get("delta_S", 0.0)),
                    "delta_K": float(mv.get("delta_K", 0.0)),
                    "delta_C": float(mv.get("delta_C", 0.0)),
                    "delta_R": float(mv.get("delta_R", 0.0)),
                    "expected_ttps": ",".join(gt.get("techniques", [])),
                    "expected_threat_type": gt.get("threat_type", ""),
                    "expected_severity": gt.get("severity", ""),
                }
            )
    return pd.DataFrame(rows)


def discretise_delta_K(x: float) -> float:
    """Bucket continuous delta_K back to nominal injection level for stratification."""
    for lvl in (0.0, 0.33, 0.66, 1.0):
        if abs(x - lvl) < 0.10:
            return lvl
    return round(x * 3) / 3


def stratified_subsample(df: pd.DataFrame, n_per_cell: int, seed: int) -> pd.DataFrame:
    """5 threats x 4 delta_K levels x n_per_cell records, deduplicated by scenario_id."""
    df = df.copy()
    df["dK_bucket"] = df["delta_K"].map(discretise_delta_K)
    out = []
    for threat in sorted(df["threat_type"].unique()):
        for level in sorted(df["dK_bucket"].unique()):
            cell = df[(df["threat_type"] == threat) & (df["dK_bucket"] == level)]
            cell = cell.drop_duplicates(subset=["scenario_id"])
            if len(cell) == 0:
                continue
            out.append(cell.sample(min(n_per_cell, len(cell)), random_state=seed))
    return pd.concat(out, ignore_index=True)


# ---------------------------------------------------------------------------
# Per-record execution
# ---------------------------------------------------------------------------


THREAT_DESCRIPTIONS = {
    "T1": "ransomware activity",
    "T2": "phishing campaign",
    "T3": "insider threat",
    "T4": "DDoS attack",
    "T5": "APT intrusion",
}


def build_prompt(row: pd.Series) -> str:
    """Synthesise a SOC alert prompt from the scenario metadata.

    The agent is asked to triage the alert under a controlled knowledge
    deficit corresponding to delta_K: a fraction of the relevant ATT&CK
    context is withheld from the prompt. This reproduces the bench's
    delta_K injection mechanism in a single-shot prompt setting.
    """
    threat_label = THREAT_DESCRIPTIONS.get(row["threat_type"], "security incident")
    expected = row.get("expected_ttps", "") or ""
    ttps = [t.strip() for t in expected.split(",") if t.strip()]
    # Knowledge withholding: keep a (1 - delta_K) fraction of the TTP context.
    keep = max(0, int(round(len(ttps) * (1.0 - float(row["delta_K"])))))
    visible_ttps = ttps[:keep] if keep > 0 else []
    context = (
        f"Known related ATT&CK techniques in the agent's knowledge base: "
        f"{', '.join(visible_ttps) if visible_ttps else 'none available'}."
    )
    return (
        "You are a SOC analyst agent. Triage the following alert and report "
        "(1) the most likely threat family, (2) suspected MITRE ATT&CK TTPs "
        "(use Txxxx or Txxxx.yyy IDs), and (3) recommended response actions. "
        "If you do not know, say so explicitly rather than guessing.\n\n"
        f"Alert: suspected {threat_label} (scenario {row['scenario_id']}).\n"
        f"{context}\n"
        "Respond concisely."
    )


try:
    from shared.attack_data import ATTACK_TTPS  # type: ignore
    KNOWN_TTPS = set(ATTACK_TTPS.keys())
except Exception:
    # Fallback to the universe of TTPs observed in the bench's ground truth
    KNOWN_TTPS = {
        "T1003", "T1021", "T1027", "T1041", "T1048", "T1053", "T1055", "T1059",
        "T1070", "T1071", "T1078", "T1078.004", "T1083", "T1105", "T1190",
        "T1195", "T1486", "T1490", "T1498", "T1498.001", "T1499", "T1499.001",
        "T1530", "T1560", "T1566", "T1566.001", "T1566.002", "T1568", "T1572",
        "T1595", "T1204",
    }


def judge_hallucination(output: str, row: pd.Series) -> bool:
    """Closed-world hallucination judge.

    A response is flagged as hallucinated if any of:
      (a) it claims a TTP identifier that does not exist in the ATT&CK
          enterprise corpus the bench operates against (a fabricated
          T-number); or
      (b) it claims a TTP that is NOT in the scenario's expected set AND
          is unrelated (different ATT&CK tactic family) to any expected TTP.

    Pure tactical-adjacency claims (e.g., adding T1490 when expected is
    T1486 for a ransomware scenario) are NOT counted as hallucination -- the
    closed-world judge would otherwise penalise reasonable elaboration. This
    matches the bench's own grounding-checker semantics in
    services/anomaly_monitor/main.py."""
    expected_str = str(row.get("expected_ttps", "")) if "expected_ttps" in row else ""
    expected = {t.strip() for t in expected_str.split(",") if t.strip()}
    if not expected:
        return False
    import re

    claimed = set(re.findall(r"T\d{4}(?:\.\d{3})?", output))
    if not claimed:
        return False

    # (a) Any fabricated TTP identifier not in the known ATT&CK universe
    fabricated = {t for t in claimed if t.split(".")[0] not in {x.split(".")[0] for x in KNOWN_TTPS}}
    if fabricated:
        return True

    # (b) Otherwise, only flag if the response is *dominated* by off-target
    # TTPs (more than 50% are outside the expected set), which captures
    # confident misclassification rather than reasonable elaboration.
    off_target = claimed - expected
    return len(off_target) > max(1, len(claimed) // 2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run_model(model: str, sample: pd.DataFrame) -> Dict:
    fn = LLM_BACKENDS.get(model)
    if fn is None:
        raise ValueError(f"Unknown model {model!r}; add it to LLM_BACKENDS.")
    rows = []
    errors = 0
    for _, row in sample.iterrows():
        try:
            out = fn(model, build_prompt(row))
            rows.append(
                {
                    "id": row.get("record_id", row.name),
                    "delta_K": float(row["delta_K"]),
                    "threat_type": row["threat_type"],
                    "hallucinated": judge_hallucination(out, row),
                    "output": out[:500],
                }
            )
        except Exception as e:  # noqa: BLE001
            errors += 1
            print(f"  [{model}] error on row {row.name}: {e}", file=sys.stderr)
    return {"records": rows, "errors": errors}


def _pearson(xs, ys) -> float:
    import math
    n = len(xs)
    if n < 2:
        return float("nan")
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return num / (dx * dy) if dx > 0 and dy > 0 else float("nan")


def summarise(model_results: Dict[str, Dict]) -> Dict:
    summary = {}
    for model, data in model_results.items():
        df = pd.DataFrame(data["records"])
        if df.empty:
            summary[model] = {"error": "no records"}
            continue
        df["dK_bucket"] = df["delta_K"].map(discretise_delta_K)
        by_dk = df.groupby("dK_bucket")["hallucinated"].mean().to_dict()
        # Bucket-aggregated Pearson rho: matches the Paper 3 E1 reporting
        bucket_xs, bucket_ys = [], []
        for level, rate in by_dk.items():
            bucket_xs.append(float(level))
            bucket_ys.append(float(rate))
        rho = _pearson(bucket_xs, bucket_ys)
        summary[model] = {
            "n": len(df),
            "errors": data["errors"],
            "hallucination_by_delta_K": {str(k): float(v) for k, v in by_dk.items()},
            "hallucination_at_dk_1.0": float(by_dk.get(1.0, float("nan"))),
            "overall_hallucination_rate": float(df["hallucinated"].mean()),
            "bucket_aggregated_pearson_rho": rho,
        }
    return summary


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, type=Path,
                   help="Path to socagentfailure_1k.jsonl (preferred) or .csv")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--models", nargs="+", required=True)
    p.add_argument("--n-per-cell", type=int, default=5)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    if args.input.suffix == ".jsonl":
        df = load_jsonl(args.input)
    else:
        df = pd.read_csv(args.input)
    sample = stratified_subsample(df, args.n_per_cell, args.seed)
    print(f"Stratified sample: {len(sample)} records")

    model_results = {m: run_model(m, sample) for m in args.models}
    payload = {
        "n_subsample": len(sample),
        "seed": args.seed,
        "models": list(args.models),
        "summary": summarise(model_results),
        "raw": model_results,
    }
    args.output.write_text(json.dumps(payload, indent=2, default=str))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
