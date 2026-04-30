"""Real-incident validation harness for ARES, v2.

CISA retired its advisories RSS in May 2025, so this harness uses two
still-available real-world sources:

  1. CISA Known Exploited Vulnerabilities (KEV) catalog JSON -- live feed
     of CVEs confirmed exploited in the wild.
  2. The DFIR Report WordPress REST API -- incident writeups with TTPs.

For each incident, the harness:
  (a) Synthesises a SOC-alert prompt from the narrative.
  (b) Runs three LLM backends (Mistral-7B baseline not used here because
      real incidents may reference post-training CVEs; we use frontier
      LLMs with knowledge cutoffs that cover recent incidents).
  (c) Auto-scores each response on three criteria (CVE identification,
      vendor/product identification, action appropriateness), producing
      an ARS-proxy in [0,1] per (incident, model).
  (d) Emits a labelling CSV so a human reviewer can override the
      auto-score.

Usage:
    export ANTHROPIC_API_KEY=...
    export OPENAI_API_KEY=...
    python real_incident_harness.py fetch --output ../output/real_incidents.json
    python real_incident_harness.py run \
        --incidents ../output/real_incidents.json \
        --output ../output/real_incident_runs.json \
        --models gpt-4o-mini claude-sonnet-4-6
    python real_incident_harness.py label-sheet \
        --runs ../output/real_incident_runs.json \
        --output ../output/real_incident_labels.csv
    python real_incident_harness.py score \
        --runs ../output/real_incident_runs.json \
        --labels ../output/real_incident_labels.csv \
        --output ../output/real_incident_score.json
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DFIR_REPORT = "https://thedfirreport.com/wp-json/wp/v2/posts?per_page=30"


# ---------------------------------------------------------------------------
# Step 1: fetch
# ---------------------------------------------------------------------------


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def fetch_cisa_kev(max_n: int) -> List[Dict]:
    raw = json.loads(_http_get(CISA_KEV))
    # KEV is sorted oldest-first in the feed; take the most recent entries
    entries = raw.get("vulnerabilities", [])
    entries = sorted(entries, key=lambda e: e.get("dateAdded", ""), reverse=True)
    out = []
    for v in entries[:max_n]:
        narrative = (
            f"Vendor: {v.get('vendorProject','?')}. "
            f"Product: {v.get('product','?')}. "
            f"Vulnerability: {v.get('vulnerabilityName','?')}. "
            f"Description: {v.get('shortDescription','')}. "
            f"Required action: {v.get('requiredAction','')}. "
            f"Known ransomware campaign use: {v.get('knownRansomwareCampaignUse','?')}. "
            f"Date added to KEV: {v.get('dateAdded','?')}."
        )
        out.append(
            {
                "source": "cisa_kev",
                "id": v.get("cveID"),
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "vuln_name": v.get("vulnerabilityName"),
                "title": f"{v.get('cveID')}: {v.get('vulnerabilityName')}",
                "narrative": narrative,
                "date_added": v.get("dateAdded"),
                "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
            }
        )
    return out


def fetch_dfir_report(max_n: int) -> List[Dict]:
    try:
        raw = json.loads(_http_get(DFIR_REPORT))
    except Exception as e:  # noqa: BLE001
        print(f"  DFIR Report unavailable: {e}", file=sys.stderr)
        return []
    out = []
    for p in raw[:max_n]:
        excerpt = p.get("excerpt", {}).get("rendered", "")
        narrative = re.sub(r"<[^>]+>", "", excerpt).strip()
        out.append(
            {
                "source": "dfir_report",
                "id": str(p.get("id")),
                "title": p.get("title", {}).get("rendered", ""),
                "url": p.get("link", ""),
                "narrative": narrative,
                "date_added": p.get("date", ""),
            }
        )
    return out


def cmd_fetch(args: argparse.Namespace) -> None:
    incidents: List[Dict] = []
    incidents.extend(fetch_cisa_kev(args.n_kev))
    incidents.extend(fetch_dfir_report(args.n_dfir))
    args.output.write_text(json.dumps({"incidents": incidents}, indent=2))
    print(f"Wrote {len(incidents)} incidents to {args.output}")


# ---------------------------------------------------------------------------
# Step 2: run through LLM backends
# ---------------------------------------------------------------------------


_REASONING_PREFIXES = ("o1", "o3", "o4", "gpt-5")


def _is_reasoning_model(m: str) -> bool:
    return any(m.startswith(p) for p in _REASONING_PREFIXES)


def call_openai(model: str, prompt: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    kwargs = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    if _is_reasoning_model(model):
        kwargs["max_completion_tokens"] = 1800
    else:
        kwargs["temperature"] = 0.3
        kwargs["max_tokens"] = 600
    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def call_anthropic(model: str, prompt: str) -> str:
    from anthropic import Anthropic

    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    kwargs = {
        "model": model,
        "max_tokens": 600,
        "messages": [{"role": "user", "content": prompt}],
    }
    if "opus-4-7" not in model and "opus-4-8" not in model:
        kwargs["temperature"] = 0.3
    resp = client.messages.create(**kwargs)
    parts = [b.text for b in resp.content if getattr(b, "type", None) == "text"]
    return "".join(parts)


LLM_BACKENDS = {
    "gpt-4o-mini": call_openai,
    "gpt-4o": call_openai,
    "gpt-5-mini": call_openai,
    "gpt-5.4-mini": call_openai,
    "o3-mini": call_openai,
    "o4-mini": call_openai,
    "claude-haiku-4-5": call_anthropic,
    "claude-sonnet-4-6": call_anthropic,
    "claude-opus-4-7": call_anthropic,
}


def build_prompt(incident: Dict) -> str:
    return (
        "You are a SOC analyst agent triaging a real security advisory. "
        "Read the advisory below and respond with:\n"
        "1. CVE identifier (if present)\n"
        "2. Affected vendor and product\n"
        "3. Most likely ATT&CK TTPs (Txxxx or Txxxx.yyy)\n"
        "4. Recommended containment actions\n"
        "5. Your confidence (0.0 to 1.0) as a single number on its own line prefixed with 'CONFIDENCE:'\n"
        "If you are not sure about any field, say 'unknown' rather than guessing.\n\n"
        f"Advisory:\n{incident['narrative']}\n"
    )


CONF_RE = re.compile(r"CONFIDENCE:\s*([0-9]*\.?[0-9]+)", re.IGNORECASE)
TTP_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def extract_confidence(text: str) -> Optional[float]:
    m = CONF_RE.search(text)
    if not m:
        return None
    try:
        return max(0.0, min(1.0, float(m.group(1))))
    except ValueError:
        return None


def auto_score(incident: Dict, output: str) -> Dict:
    """Deterministic auto-scoring against ground truth drawn from the KEV
    entry itself.

    Returns a 3-criterion rubric; final score is the mean.
    """
    text = output.lower()
    cve_match = False
    vendor_match = False
    product_match = False

    if incident.get("cve_id"):
        cve_match = incident["cve_id"].lower() in text
    if incident.get("vendor"):
        vendor_tokens = [t for t in re.split(r"[\s,/]+", incident["vendor"].lower()) if len(t) > 2]
        vendor_match = any(t in text for t in vendor_tokens)
    if incident.get("product"):
        product_tokens = [t for t in re.split(r"[\s,/]+", incident["product"].lower()) if len(t) > 2]
        product_match = any(t in text for t in product_tokens)

    ttps = list(set(TTP_RE.findall(output)))
    confidence = extract_confidence(output)

    # Auto ARS proxy: fraction of identifiable criteria correctly matched,
    # plus partial credit for non-empty TTP claim.
    weights = {"cve": 0.4, "vendor": 0.25, "product": 0.25, "ttp_any": 0.10}
    ars_proxy = (
        weights["cve"] * (1.0 if cve_match else 0.0)
        + weights["vendor"] * (1.0 if vendor_match else 0.0)
        + weights["product"] * (1.0 if product_match else 0.0)
        + weights["ttp_any"] * (1.0 if ttps else 0.0)
    )

    return {
        "cve_match": cve_match,
        "vendor_match": vendor_match,
        "product_match": product_match,
        "ttps_claimed": ttps,
        "confidence_stated": confidence,
        "ars_proxy": round(ars_proxy, 3),
    }


def cmd_run(args: argparse.Namespace) -> None:
    incidents = json.loads(args.incidents.read_text())["incidents"]
    runs = []
    for model in args.models:
        fn = LLM_BACKENDS.get(model)
        if fn is None:
            print(f"Unknown model {model!r}, skipping.", file=sys.stderr)
            continue
        print(f"Running {len(incidents)} incidents through {model} ...", file=sys.stderr)
        for inc in incidents:
            try:
                output = fn(model, build_prompt(inc))
            except Exception as e:  # noqa: BLE001
                runs.append(
                    {
                        "incident_id": inc["id"],
                        "source": inc["source"],
                        "model": model,
                        "error": str(e),
                    }
                )
                continue
            score = auto_score(inc, output)
            runs.append(
                {
                    "incident_id": inc["id"],
                    "source": inc["source"],
                    "cve_id": inc.get("cve_id"),
                    "title": inc.get("title"),
                    "model": model,
                    "output": output,
                    "auto_score": score,
                    "human_label": "",  # filled in step 3
                }
            )
    args.output.write_text(json.dumps({"runs": runs}, indent=2))
    print(f"Wrote {len(runs)} runs to {args.output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 3: emit labelling sheet
# ---------------------------------------------------------------------------


def cmd_label_sheet(args: argparse.Namespace) -> None:
    runs = json.loads(args.runs.read_text())["runs"]
    fields = [
        "incident_id",
        "source",
        "cve_id",
        "title",
        "model",
        "ars_proxy",
        "cve_match",
        "vendor_match",
        "product_match",
        "ttps_claimed",
        "confidence_stated",
        "output_first_200",
        "human_label",
        "human_notes",
    ]
    with args.output.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in runs:
            if "error" in r:
                continue
            s = r["auto_score"]
            w.writerow(
                {
                    "incident_id": r["incident_id"],
                    "source": r["source"],
                    "cve_id": r.get("cve_id", ""),
                    "title": r.get("title", ""),
                    "model": r["model"],
                    "ars_proxy": s["ars_proxy"],
                    "cve_match": s["cve_match"],
                    "vendor_match": s["vendor_match"],
                    "product_match": s["product_match"],
                    "ttps_claimed": ";".join(s.get("ttps_claimed", [])),
                    "confidence_stated": s.get("confidence_stated", ""),
                    "output_first_200": (r.get("output", "") or "").replace("\n", " ")[:200],
                    "human_label": "",
                    "human_notes": "",
                }
            )
    print(f"Wrote labelling sheet: {args.output}")


# ---------------------------------------------------------------------------
# Step 4: score (after human labelling)
# ---------------------------------------------------------------------------


def cmd_score(args: argparse.Namespace) -> None:
    with args.labels.open() as f:
        rows = list(csv.DictReader(f))
    labelled = [r for r in rows if r["human_label"].strip()]

    by_model: Dict[str, Dict] = {}
    for r in rows:
        m = r["model"]
        s = by_model.setdefault(
            m,
            {"n": 0, "mean_ars_proxy": 0.0, "cve_match_rate": 0, "n_labelled": 0, "human_success": 0},
        )
        s["n"] += 1
        s["mean_ars_proxy"] += float(r["ars_proxy"])
        if r["cve_match"].lower() == "true":
            s["cve_match_rate"] += 1
        if r["human_label"].strip():
            s["n_labelled"] += 1
            if r["human_label"].strip().lower() in {"success", "partial"}:
                s["human_success"] += 1

    for m, s in by_model.items():
        if s["n"]:
            s["mean_ars_proxy"] = round(s["mean_ars_proxy"] / s["n"], 3)
            s["cve_match_rate"] = round(s["cve_match_rate"] / s["n"], 3)
        if s["n_labelled"]:
            s["human_success_rate"] = round(s["human_success"] / s["n_labelled"], 3)

    # Auto-proxy vs human-label confusion (threshold 0.58 matching ARS theta*)
    theta = 0.58
    tp = fp = fn = tn = 0
    for r in labelled:
        flag_anom = float(r["ars_proxy"]) < theta
        is_fail = r["human_label"].strip().lower() in {"failure", "partial"}
        if flag_anom and is_fail:
            tp += 1
        elif flag_anom and not is_fail:
            fp += 1
        elif (not flag_anom) and is_fail:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    out = {
        "theta": theta,
        "n_total": len(rows),
        "n_labelled": len(labelled),
        "per_model": by_model,
        "confusion_labelled": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision_labelled": round(precision, 3),
        "recall_labelled": round(recall, 3),
        "f1_labelled": round(f1, 3),
    }
    args.output.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch")
    f.add_argument("--output", required=True, type=Path)
    f.add_argument("--n-kev", type=int, default=20)
    f.add_argument("--n-dfir", type=int, default=10)
    f.set_defaults(func=cmd_fetch)

    r = sub.add_parser("run")
    r.add_argument("--incidents", required=True, type=Path)
    r.add_argument("--output", required=True, type=Path)
    r.add_argument(
        "--models",
        nargs="+",
        default=["gpt-4o-mini", "claude-sonnet-4-6"],
    )
    r.set_defaults(func=cmd_run)

    ls = sub.add_parser("label-sheet")
    ls.add_argument("--runs", required=True, type=Path)
    ls.add_argument("--output", required=True, type=Path)
    ls.set_defaults(func=cmd_label_sheet)

    s = sub.add_parser("score")
    s.add_argument("--runs", required=True, type=Path)
    s.add_argument("--labels", required=True, type=Path)
    s.add_argument("--output", required=True, type=Path)
    s.set_defaults(func=cmd_score)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
