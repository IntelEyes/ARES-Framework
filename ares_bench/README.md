# ARES-Bench

ARES-Bench is the open-source, Docker-deployable testbed used to
generate the [SAFK corpus](../safk_corpus/) and to evaluate AI security
agents under controlled mismatch injection. The design prioritises
**reproducibility** (single-command deployment, public data sources),
**generalisability** (multiple agent architectures and threat classes),
and **controllability** (systematic mismatch injection across a
structured experimental matrix).

**License: MIT** (see [`../LICENSE`](../LICENSE)).

## Architecture

Six microservices orchestrated via Docker Compose:

| Service | Role |
|---|---|
| `scenario_engine` | Generates structured task instances from MITRE ATT&CK STIX bundles and NVD CVE data |
| `mismatch_injector` | Applies controlled capability degradation to agent profiles before task assignment |
| `agents/` | Four agent architectures under test: AUT-1 LangGraph, AUT-2 AutoGen, AUT-3 CrewAI, AUT-4 rule-based |
| `anomaly_monitor` | Computes ARS and Epistemic Gap, flags hallucinations against ATT&CK/NVD ground truth, assigns taxonomy labels |
| `dataset_writer` | Exports enriched records in JSONL + CSV |
| `orchestrator` | Coordinates the end-to-end pipeline |

## Layout

```
ares_bench/
├── README.md
├── docker-compose.yml          Service orchestration
├── .env.example                Configuration template (copy to .env)
├── generate_dataset.py         Top-level driver to produce SAFK corpus
├── services/                   6 microservices
│   ├── scenario_engine/
│   ├── mismatch_injector/
│   ├── agents/
│   │   ├── langgraph_agent/    AUT-1
│   │   ├── autogen_agent/      AUT-2
│   │   ├── crewai_agent/       AUT-3
│   │   └── rulebased_agent/    AUT-4
│   ├── anomaly_monitor/
│   ├── dataset_writer/
│   └── orchestrator/
├── shared/                     Common utilities (mismatch math, ARS, EG, taxonomy)
├── analysis/                   Reproducibility scripts
│   ├── ridge_fit.py            Per-class ARS weight learning
│   ├── cascade_ablation.py     27-bucket controlled cascade analysis
│   ├── cross_model_validation.py
│   ├── real_incident_harness.py   Live CISA KEV runner
│   └── ...
└── tests/                      Unit and integration tests
```

## Quick start

```bash
# 1. Configure
cp .env.example .env
# Edit POSTGRES_PASSWORD, OLLAMA_URL, etc. as required.

# 2. Bring up the testbed
docker compose up -d

# 3. Run the dataset generation pipeline
python generate_dataset.py
```

By default the pipeline runs in `SIMULATION_MODE=true`, producing
records via the deterministic simulator. For real LLM-driven runs,
set `SIMULATION_MODE=false` and configure `OLLAMA_URL` plus optional
`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` (the cross-model validation
harness reads these from the environment).

## Reproducibility

To reproduce the headline numbers reported in the papers, see
[`../safk_corpus/README.md`](../safk_corpus/README.md), the corpus
bundle includes `canonical_paper_numbers.json` and the per-experiment
output files needed to verify each claim without re-running the full
testbed.
