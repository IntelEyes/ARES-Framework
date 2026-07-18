# SOCAgentFailure-1K (SAFK) Corpus

The SAFK corpus is a labelled **analytical** benchmark of **1,000 traces**
produced by the [ARES-Bench](../ares_bench/) testbed under controlled
mismatch injection.

> ⚠️ **Analytical, not live.** SAFK's *outcomes* (hallucination, expressed
> confidence, task success, taxonomy labels) are **generated from the
> mismatch inputs by closed-form models** — they exercise the ARES model's
> internal logic under exact ground truth; they are **not** measured from
> live LLM execution. For real-agent behaviour, use the **calibration-gap
> dataset** below (`calibration_gap_runs.json`): 600 live executions across
> five frontier models, which shows real agents stay calibrated and abstain
> under knowledge deficit rather than confidently hallucinate (pooled
> Pearson(δ_K, fabrication) = +0.11 live vs. +0.92 in this corpus). See the
> S&P Magazine paper's calibration-gap sections.

## Live calibration-gap data (real agents)

- `calibration_gap_runs.json` — 600 live agent executions (Claude Haiku 4.5 /
  Sonnet 4.6 / Opus 4.7; GPT-4o-mini / GPT-4o), 0 errors.
- `calibration_gap_summary.json` — per-model calibration statistics.
- `calibration_gap_scenarios.json` — 10 ATT&CK-grounded scenarios.
- Harnesses: `../ares_bench/analysis/calibration_gap_harness{,_openai}.py`.

**License: Creative Commons Attribution 4.0 International (CC BY 4.0)**, see [`../LICENSE-DATA`](../LICENSE-DATA).

## Composition

- 1,000 records total: **750 LLM-agent executions** (Mistral-7B-Instruct
  backbone) + **250 rule-based control executions**.
- 4 agent architectures × 250 records each: AUT-1 (LangGraph), AUT-2
  (AutoGen 3-stage pipeline), AUT-3 (CrewAI role-based crew), AUT-4
  (rule-based Sigma/YARA control).
- 5 threat classes × 200 records each: T1 Ransomware, T2 Phishing, T3
  Insider Threat, T4 DDoS, T5 APT Intrusion.
- Stratified split: 600 train / 200 validation / 200 held-out test.

## Per-record schema

Each record in `socagentfailure_1k.jsonl` (one JSON object per line) has:

| Field | Description |
|---|---|
| `run_id` | Unique identifier (`saf1k_<n>_<scenario>_<arch>_<deltas>_<rep>`) |
| `scenario_id`, `threat_type` | Scenario reference + threat-class code |
| `agent_arch` | One of `AUT-1` … `AUT-4` |
| `mismatch_vector` | Stringified dict `{delta_S, delta_K, delta_C, delta_R, delta_T}` |
| `ars_score`, `epistemic_gap` | Computed reliability indicators |
| `anomaly_flag` | Binary anomaly label (`ARS<θ` or `ε>τ`) |
| `taxonomy_codes` | Stringified dict `{origin, manifestation, impact}` |
| `agent_output`, `ground_truth` | Truncated agent output and ATT&CK-derived ground truth |
| `cascade_ars` | Pipeline reliability score (AUT-2 only; null elsewhere) |
| `uncertainty`, `confidence` | Stated confidence U and complement |
| `fn_score`, `task_success` | False-negative severity, binary success |
| `latency_ms`, `timestamp` | Execution metadata |
| `hallucinated` | Binary hallucination label (M1 manifestation) |
| `split` | `train` / `val` / `test` |

CSV variant (`socagentfailure_1k.csv`) carries the same columns flattened.

## Files in this directory

| File | Purpose |
|---|---|
| `socagentfailure_1k.jsonl` | The corpus in JSON Lines format (1 record/line) |
| `socagentfailure_1k.csv` | The same corpus in CSV format |
| `dataset_stats.json` | Aggregate statistics (taxonomy distribution, per-architecture counts, per-threat counts) |
| `canonical_paper_numbers.json` | All headline numbers cited in the papers (ρ, F1, anomaly rate, hallucination buckets, EG predictive lift) |
| `cascade_ablation.json` | 27-bucket controlled ablation isolating framework identity (0.13%) from pipeline depth (17.25%) |
| `cross_model_results.json` | 40-record cross-model panel (Mistral-7B + GPT-4o-mini + Claude Haiku/Sonnet) |
| `real_incident_runs_v2.json` | 30-incident CISA KEV validation × 5 LLMs |
| `real_incident_labels.csv` | Ground-truth labels for the real-incident validation set |

## Quick reproduction

Three example reproductions of paper claims:

### 1. Hallucination vs. δ_K relationship (Paper 1 §V.A, Paper 2 §6.1)

```python
import json
d = json.load(open('canonical_paper_numbers.json'))
for level, cell in d['hallucination_vs_deltaK']['buckets'].items():
    print(f"δ_K = {level}: hallucination rate = {cell['hall_rate']:.3f} (n = {cell['n']})")
# δ_K = 0.0:  0.014 (n = 210)
# δ_K = 0.33: 0.106 (n = 180)
# δ_K = 0.66: 0.220 (n = 255)
# δ_K = 1.0:  0.390 (n = 105)
```

### 2. ARS threshold F1 (Paper 1 §V.B, Paper 2 §6.3)

```python
import json
d = json.load(open('canonical_paper_numbers.json'))
print(f"θ* = {d['threshold_f1']['theta_star']}")
print(f"Test F1 = {d['threshold_f1']['test_f1']:.3f}")
for klass, perf in d['threshold_f1']['per_threat_test'].items():
    print(f"  {klass}: F1 = {perf['f1']:.3f}, recall = {perf['recall']:.3f}")
```

### 3. Cascade decomposition (Paper 1 §V.B, Paper 2 §6.4)

```python
import json
d = json.load(open('cascade_ablation.json'))
print(f"Framework identity effect: {d['framework_identity_effect_pct']}%")
print(f"Pipeline depth effect: {d['pipeline_depth_effect_pct']}%")
# Framework identity effect: 0.13%
# Pipeline depth effect: 17.25%
```

## Citing the corpus

If you use SAFK in your work, please cite the conference paper (see the
top-level [`CITATION.cff`](../CITATION.cff) or `README.md`) and credit
the dataset under CC BY 4.0.
