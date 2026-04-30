"""Zenodo sandbox upload helper for ARES (SOCAgentFailure-1K).

Prepares a dataset bundle, registers a new deposition against the
Zenodo Sandbox API, uploads all files, and attaches metadata.

Usage:
    export ZENODO_SANDBOX_TOKEN=<your token>
    python zenodo_upload.py --bundle-dir ../output/zenodo_bundle \\
        --title "SOCAgentFailure-1K: A labelled dataset of AI security agent executions"

On first run, pass --prepare to assemble the bundle from the bench
output directory. Pass --upload to actually push to the sandbox.

Get a sandbox API token at:
  https://sandbox.zenodo.org/account/settings/applications/tokens/new/
  (select scopes: deposit:write deposit:actions)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List


SANDBOX_BASE = "https://sandbox.zenodo.org/api"
PROD_BASE = "https://zenodo.org/api"

DEFAULT_BUNDLE_FILES = [
    # Dataset
    "socagentfailure_1k.csv",
    "socagentfailure_1k.jsonl",
    "ares_bench_dataset.csv",
    "ares_bench_dataset.jsonl",
    # Results
    "dataset_stats.json",
    "paper_results.json",
    "canonical_paper_numbers.json",
    "extra_analyses.json",
    "weight_sensitivity.json",
    "nonlinear_comparison.json",
    "coupling_analysis.json",
    "cascade_ablation.json",
    "cross_model_results.json",
    "real_incidents.json",
    "real_incident_runs.json",
    "real_incident_runs_v2.json",
    "real_incident_labels.csv",
    "advanced_threats.json",
    "advanced_threats_v2.json",
]

DEFAULT_ANALYSIS_SCRIPTS = [
    "paper_results.py",
    "weight_sensitivity.py",
    "nonlinear_comparison.py",
    "coupling_analysis.py",
    "cascade_ablation.py",
    "cross_model_validation.py",
    "real_incident_harness.py",
    "advanced_threats.py",
    "run_experiments.py",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_prepare(args: argparse.Namespace) -> None:
    bundle = args.bundle_dir
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "output").mkdir(exist_ok=True)
    (bundle / "analysis").mkdir(exist_ok=True)

    output_dir = Path(args.ares_root) / "ares_bench" / "output"
    analysis_dir = Path(args.ares_root) / "ares_bench" / "analysis"

    manifest: List[Dict] = []

    for fname in DEFAULT_BUNDLE_FILES:
        src = output_dir / fname
        if not src.exists():
            print(f"  [skip] {fname} -- not present", file=sys.stderr)
            continue
        dst = bundle / "output" / fname
        shutil.copy2(src, dst)
        manifest.append(
            {
                "path": f"output/{fname}",
                "size_bytes": dst.stat().st_size,
                "sha256": sha256(dst),
            }
        )

    for fname in DEFAULT_ANALYSIS_SCRIPTS:
        src = analysis_dir / fname
        if not src.exists():
            print(f"  [skip] {fname} -- not present", file=sys.stderr)
            continue
        dst = bundle / "analysis" / fname
        shutil.copy2(src, dst)
        manifest.append(
            {
                "path": f"analysis/{fname}",
                "size_bytes": dst.stat().st_size,
                "sha256": sha256(dst),
            }
        )

    # LICENSE
    (bundle / "LICENSE.txt").write_text(LICENSE_CC_BY_40)
    manifest.append(
        {
            "path": "LICENSE.txt",
            "size_bytes": (bundle / "LICENSE.txt").stat().st_size,
            "sha256": sha256(bundle / "LICENSE.txt"),
        }
    )

    # README
    readme = build_readme(manifest)
    (bundle / "README.md").write_text(readme)
    manifest.append(
        {
            "path": "README.md",
            "size_bytes": (bundle / "README.md").stat().st_size,
            "sha256": sha256(bundle / "README.md"),
        }
    )

    (bundle / "MANIFEST.json").write_text(json.dumps({"files": manifest}, indent=2))
    print(f"Bundle prepared at {bundle} ({len(manifest)} files)")


def build_readme(manifest: List[Dict]) -> str:
    lines = [
        "# SOCAgentFailure-1K",
        "",
        "A labelled dataset of 1,000 AI security agent execution traces under",
        "controlled mismatch conditions, released alongside the ARES framework.",
        "",
        "**Dataset version**: 1.0 (April 2026).",
        "**Licence**: CC BY 4.0.",
        "**Seed**: 42 (all results are deterministic).",
        "",
        "## Contents",
        "",
        "- `output/socagentfailure_1k.{csv,jsonl}` -- the main 1,000-record dataset.",
        "- `output/dataset_stats.json` -- summary statistics.",
        "- `output/paper_results.json`, `canonical_paper_numbers.json`,",
        "  `extra_analyses.json` -- experimental outputs underlying Paper 3 tables.",
        "- `output/weight_sensitivity.json` -- E7 weight sensitivity.",
        "- `output/nonlinear_comparison.json` -- linear vs nonlinear fit comparison.",
        "- `output/coupling_analysis.json` -- empirical mu*_max for AUT-2 cascade.",
        "- `output/cascade_ablation.json` -- framework-identity vs pipeline-depth ablation.",
        "- `output/cross_model_results.json` -- cross-model generalisation on GPT-4o-mini,",
        "  Claude Haiku 4.5, Claude Sonnet 4.6.",
        "- `output/real_incidents.json`, `real_incident_runs.json` -- CISA KEV + DFIR Report validation.",
        "- `output/advanced_threats.json` -- prompt injection, out-of-corpus,",
        "  living-off-the-land stress tests.",
        "- `analysis/*.py` -- reproduction scripts.",
        "",
        "## Reproducing paper tables",
        "",
        "Every quantitative claim in Paper 3 maps to a file in this bundle. See",
        "Paper 3 Appendix Table 11 for the full table-to-artefact mapping.",
        "",
        "## File manifest (SHA-256)",
        "",
        "| File | Size | SHA-256 |",
        "|---|---|---|",
    ]
    for m in manifest:
        lines.append(f"| `{m['path']}` | {m['size_bytes']:,} | `{m['sha256']}` |")
    lines.append("")
    lines.append("## Citation")
    lines.append("")
    lines.append("If you use this dataset, please cite the ARES framework paper:")
    lines.append("> Alam, M. M., Jurcut, A. D., Anik, M. R. Z., El Bodour, S. S.")
    lines.append("> *ARES: A Formal Reliability Framework for Detecting Anomalous")
    lines.append("> Behaviour in Agentic AI Systems for Cyber Threat Detection.* IEEE")
    lines.append("> Transactions on Dependable and Secure Computing, 2026.")
    return "\n".join(lines)


LICENSE_CC_BY_40 = """\
Creative Commons Attribution 4.0 International (CC BY 4.0)

You are free to:
  Share -- copy and redistribute the material in any medium or format
  Adapt -- remix, transform, and build upon the material for any purpose,
           even commercially.

Under the following terms:
  Attribution -- You must give appropriate credit, provide a link to the
                 license, and indicate if changes were made. You may do so
                 in any reasonable manner, but not in any way that suggests
                 the licensor endorses you or your use.

No additional restrictions -- You may not apply legal terms or technological
measures that legally restrict others from doing anything the license permits.

Full legal code: https://creativecommons.org/licenses/by/4.0/legalcode
"""


def _api(args: argparse.Namespace) -> str:
    return PROD_BASE if args.prod else SANDBOX_BASE


def _token() -> str:
    t = os.environ.get("ZENODO_SANDBOX_TOKEN") or os.environ.get("ZENODO_TOKEN")
    if not t:
        sys.exit("Set ZENODO_SANDBOX_TOKEN (or ZENODO_TOKEN for production).")
    return t


def _request(method: str, url: str, data: bytes = b"", token: str = "", content_type: str = "application/json"):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
            return r.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        raise


def cmd_upload(args: argparse.Namespace) -> None:
    token = _token()
    api = _api(args)
    bundle = args.bundle_dir
    if not (bundle / "MANIFEST.json").exists():
        sys.exit(f"No MANIFEST.json in {bundle}; run `prepare` first.")

    metadata = {
        "metadata": {
            "title": args.title,
            "upload_type": "dataset",
            "description": (
                "<p>SOCAgentFailure-1K: a labelled dataset of 1,000 AI security "
                "agent execution traces under controlled SKC mismatch conditions, "
                "released alongside the ARES reliability framework. Contains full "
                "mismatch vectors, ARS scores, Epistemic Gap values, failure "
                "taxonomy labels, and execution metadata for four agent "
                "architectures across five threat scenario classes. Generated "
                "deterministically with seed 42. Includes reproduction scripts "
                "that regenerate every table in the companion TDSC paper.</p>"
            ),
            "creators": [
                {"name": "Alam, Mohammad Makchudul", "affiliation": "University College Dublin"},
                {"name": "Jurcut, Anca Delia", "affiliation": "University College Dublin"},
                {"name": "Anik, Md. Redowan Zaman", "affiliation": "BGD e-GOV CIRT"},
                {"name": "El Bodour, Sabrein Serag El Din", "affiliation": "BGD e-GOV CIRT"},
            ],
            "keywords": [
                "AI agent reliability",
                "cybersecurity",
                "SOC automation",
                "LLM hallucination",
                "failure taxonomy",
                "MITRE ATT&CK",
                "epistemic gap",
                "agentic AI",
            ],
            "access_right": "open",
            "license": "CC-BY-4.0",
            "version": "1.0.0",
        }
    }

    print("Creating deposition ...", file=sys.stderr)
    _, dep = _request(
        "POST",
        f"{api}/deposit/depositions",
        data=json.dumps({}).encode(),
        token=token,
    )
    dep_id = dep["id"]
    bucket_url = dep["links"]["bucket"]
    print(f"  deposition id: {dep_id}", file=sys.stderr)

    print("Uploading files via bucket API ...", file=sys.stderr)
    for path in sorted(bundle.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(bundle).as_posix()
        with path.open("rb") as f:
            data = f.read()
        upload_url = f"{bucket_url}/{urllib.parse.quote(rel)}"
        req = urllib.request.Request(upload_url, data=data, method="PUT")
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=300) as r:
            r.read()
        print(f"  uploaded: {rel} ({len(data):,} bytes)", file=sys.stderr)

    print("Attaching metadata ...", file=sys.stderr)
    _request(
        "PUT",
        f"{api}/deposit/depositions/{dep_id}",
        data=json.dumps(metadata).encode(),
        token=token,
    )

    if args.publish:
        print("Publishing ...", file=sys.stderr)
        _, pub = _request(
            "POST",
            f"{api}/deposit/depositions/{dep_id}/actions/publish",
            token=token,
        )
        print(json.dumps(pub.get("links", {}), indent=2))
    else:
        print("Skipped publishing (pass --publish to finalise).", file=sys.stderr)
        print(f"Draft deposition: {api.replace('/api', '')}/deposit/{dep_id}")


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("prepare")
    pr.add_argument("--bundle-dir", required=True, type=Path)
    pr.add_argument("--ares-root", default=str(Path(__file__).resolve().parents[2]))
    pr.set_defaults(func=cmd_prepare)

    up = sub.add_parser("upload")
    up.add_argument("--bundle-dir", required=True, type=Path)
    up.add_argument(
        "--title",
        default="SOCAgentFailure-1K: A Labelled Dataset of AI Security Agent Execution Traces",
    )
    up.add_argument("--prod", action="store_true", help="Use Zenodo production (default: sandbox)")
    up.add_argument("--publish", action="store_true", help="Finalise deposition (default: draft)")
    up.set_defaults(func=cmd_upload)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
