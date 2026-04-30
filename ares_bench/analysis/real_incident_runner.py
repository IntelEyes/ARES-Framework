"""Real-incident validation harness for ARES.

Ingests publicly available SOC incident reports (CISA cybersecurity
advisories and DFIR Report writeups), formats them as bench-compatible
scenarios, and runs the four reference architectures against them so a
human reviewer can manually label success/failure.

This addresses the closed-world / synthetic-data limitation of
SOCAgentFailure-1K by validating against real incident narratives.

Usage:
    # 1. Fetch advisories (writes JSON to ../output/real_incidents.json)
    python real_incident_runner.py fetch \
        --sources cisa dfir-report \
        --max-per-source 15 \
        --output ../output/real_incidents.json

    # 2. Run the four AUTs against the fetched incidents
    python real_incident_runner.py run \
        --incidents ../output/real_incidents.json \
        --output ../output/real_incident_runs.json

    # 3. Open the resulting CSV in a spreadsheet and label the
    #    `human_label` column as one of {success, partial, failure}
    python real_incident_runner.py to-csv \
        --runs ../output/real_incident_runs.json \
        --output ../output/real_incident_labelling_sheet.csv

    # 4. Compute ARS-vs-human-label confusion matrix
    python real_incident_runner.py score \
        --labelled ../output/real_incident_labelling_sheet.csv \
        --output ../output/real_incident_score.json

Networking: only the `fetch` step needs internet. All other steps run
fully offline against the saved JSON.

This file is intentionally a thin runner: per-AUT execution is
delegated to the existing services in `ares_bench/services/agents/` so
this file does not duplicate orchestration logic.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Step 1: fetch
# ---------------------------------------------------------------------------

CISA_INDEX = "https://www.cisa.gov/cybersecurity-advisories/all.json"
DFIR_REPORT_INDEX = "https://thedfirreport.com/wp-json/wp/v2/posts?per_page=20"


def fetch_cisa(max_n: int) -> List[Dict]:
    import urllib.request

    req = urllib.request.Request(CISA_INDEX, headers={"User-Agent": "ARES-bench/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    out = []
    for entry in data[:max_n]:
        out.append(
            {
                "source": "cisa",
                "id": entry.get("id") or entry.get("link"),
                "title": entry.get("title", ""),
                "url": entry.get("link", ""),
                "narrative": entry.get("description", "") or entry.get("summary", ""),
                "published": entry.get("date_published", ""),
            }
        )
    return out


def fetch_dfir_report(max_n: int) -> List[Dict]:
    import urllib.request

    req = urllib.request.Request(
        DFIR_REPORT_INDEX, headers={"User-Agent": "ARES-bench/0.1"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    out = []
    for entry in data[:max_n]:
        out.append(
            {
                "source": "dfir-report",
                "id": entry.get("id"),
                "title": entry.get("title", {}).get("rendered", ""),
                "url": entry.get("link", ""),
                "narrative": re.sub(
                    r"<[^>]+>", "", entry.get("excerpt", {}).get("rendered", "")
                ),
                "published": entry.get("date", ""),
            }
        )
    return out


SOURCES = {"cisa": fetch_cisa, "dfir-report": fetch_dfir_report}


def cmd_fetch(args: argparse.Namespace) -> None:
    incidents: List[Dict] = []
    for src in args.sources:
        fn = SOURCES.get(src)
        if fn is None:
            print(f"Unknown source {src!r}", file=sys.stderr)
            continue
        print(f"Fetching {src} ...")
        try:
            incidents.extend(fn(args.max_per_source))
        except Exception as e:  # noqa: BLE001
            print(f"  failed: {e}", file=sys.stderr)
    args.output.write_text(json.dumps({"incidents": incidents}, indent=2))
    print(f"Wrote {len(incidents)} incidents to {args.output}")


# ---------------------------------------------------------------------------
# Step 2: run incidents through the four AUTs
# ---------------------------------------------------------------------------


def to_bench_scenario(incident: Dict) -> Dict:
    """Convert a real-incident record into a synthetic bench scenario.

    The narrative is exposed as the alert text; expected_ttps and
    expected_threat_family are left blank for the human labeller to fill.
    """
    return {
        "scenario_id": f"real::{incident['source']}::{incident['id']}",
        "threat_type": "T?",  # human labels later
        "alert_text": f"{incident.get('title', '')}\n\n{incident.get('narrative', '')}",
        "expected_ttps": "",  # human labels later
        "expected_threat_family": "",
        "delta_S": 0.0,
        "delta_K": 0.0,
        "delta_C": 0.0,
        "delta_R": 0.0,
        "delta_T": 0.0,
        "source_url": incident.get("url", ""),
    }


def cmd_run(args: argparse.Namespace) -> None:
    """Run all four AUTs against the fetched incidents.

    Imports are deferred so the file remains usable for fetch/score even
    when the bench services are not available locally.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from services.agents.langgraph_agent import run as run_aut1  # type: ignore
    from services.agents.autogen_agent import run as run_aut2  # type: ignore
    from services.agents.crewai_agent import run as run_aut3  # type: ignore
    from services.agents.rulebased_agent import run as run_aut4  # type: ignore

    runners = {
        "AUT-1": run_aut1,
        "AUT-2": run_aut2,
        "AUT-3": run_aut3,
        "AUT-4": run_aut4,
    }

    incidents = json.loads(args.incidents.read_text())["incidents"]
    runs: List[Dict] = []
    for incident in incidents:
        scenario = to_bench_scenario(incident)
        for aut_name, runner in runners.items():
            try:
                result = runner(scenario)
            except Exception as e:  # noqa: BLE001
                result = {"error": str(e)}
            runs.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "agent_arch": aut_name,
                    "agent_output": result.get("output", ""),
                    "ars_score": result.get("ars_score"),
                    "human_label": "",  # to be filled in
                }
            )
    args.output.write_text(json.dumps({"runs": runs}, indent=2))
    print(f"Wrote {len(runs)} runs to {args.output}")


# ---------------------------------------------------------------------------
# Step 3: emit a labelling spreadsheet
# ---------------------------------------------------------------------------


def cmd_to_csv(args: argparse.Namespace) -> None:
    runs = json.loads(args.runs.read_text())["runs"]
    fields = ["scenario_id", "agent_arch", "ars_score", "agent_output", "human_label"]
    with args.output.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in runs:
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"Wrote labelling sheet to {args.output} ({len(runs)} rows)")


# ---------------------------------------------------------------------------
# Step 4: score against human labels
# ---------------------------------------------------------------------------


def cmd_score(args: argparse.Namespace) -> None:
    rows = list(csv.DictReader(args.labelled.open()))
    labels = [r for r in rows if r["human_label"]]
    if not labels:
        print("No human labels found", file=sys.stderr)
        sys.exit(1)
    flagged_anomaly = lambda r: float(r.get("ars_score") or 0) < 0.58  # noqa: E731
    is_failure = lambda r: r["human_label"].lower() in {"failure", "partial"}  # noqa: E731
    tp = sum(1 for r in labels if flagged_anomaly(r) and is_failure(r))
    fp = sum(1 for r in labels if flagged_anomaly(r) and not is_failure(r))
    fn = sum(1 for r in labels if not flagged_anomaly(r) and is_failure(r))
    tn = sum(1 for r in labels if not flagged_anomaly(r) and not is_failure(r))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    summary = {
        "n_labelled": len(labels),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "ars_threshold_used": 0.58,
    }
    args.output.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch")
    f.add_argument("--sources", nargs="+", default=["cisa", "dfir-report"])
    f.add_argument("--max-per-source", type=int, default=15)
    f.add_argument("--output", required=True, type=Path)
    f.set_defaults(func=cmd_fetch)

    r = sub.add_parser("run")
    r.add_argument("--incidents", required=True, type=Path)
    r.add_argument("--output", required=True, type=Path)
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("to-csv")
    c.add_argument("--runs", required=True, type=Path)
    c.add_argument("--output", required=True, type=Path)
    c.set_defaults(func=cmd_to_csv)

    s = sub.add_parser("score")
    s.add_argument("--labelled", required=True, type=Path)
    s.add_argument("--output", required=True, type=Path)
    s.set_defaults(func=cmd_score)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
