#!/usr/bin/env python3
"""Live multi-agent cascade experiment (reviewer R2-e).

Tests the ARES cascade claim on real frontier agents instead of the analytical
model: does tightly-coupled pipeline DEPTH degrade end-to-end reliability, and
is the degradation bounded by the weakest stage? Reports sampling, variance,
and confidence intervals with controlled budgets.

Design (same task, two depths):
  * depth-1 (single agent): one call names the primary ATT&CK technique.
  * depth-3 (pipeline): triage tactic -> enrich technique -> confirm, each stage
    conditioned only on the prior stage's output + the original alert (tight
    coupling, so an upstream error propagates).
Controlled budgets: identical model, max_tokens, and temperature across depths;
the ONLY manipulated variable is pipeline depth. Reps at temperature>0 give the
sampling variance the reviewer asked for.

Keys from env: ANTHROPIC_API_KEY, OPENAI_API_KEY. Stdlib only (urllib).
Usage: python3 cascade_live_harness.py [scenarios.json] [out.json]
"""
import json
import os
import random
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")

MODELS = ["claude-haiku-4-5", "claude-sonnet-4-6", "gpt-4o-mini"]
REPS = 4
TEMPERATURE = 0.7
MAX_TOKENS = 300
THREAT_NAME = {
    "T1": "ransomware intrusion", "T2": "phishing campaign",
    "T3": "insider-threat incident", "T4": "DDoS attack", "T5": "APT intrusion",
}
TID = re.compile(r"T\d{4}")


def call(model, prompt):
    """Single chat turn. Returns text or raises."""
    for attempt in range(4):
        try:
            if model.startswith("claude"):
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=json.dumps({
                        "model": model, "max_tokens": MAX_TOKENS, "temperature": TEMPERATURE,
                        "messages": [{"role": "user", "content": prompt}],
                    }).encode(),
                    headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                             "content-type": "application/json"})
                d = json.load(urllib.request.urlopen(req, timeout=60))
                return d["content"][0]["text"]
            else:
                req = urllib.request.Request(
                    "https://api.openai.com/v1/chat/completions",
                    data=json.dumps({
                        "model": model, "max_tokens": MAX_TOKENS, "temperature": TEMPERATURE,
                        "messages": [{"role": "user", "content": prompt}],
                    }).encode(),
                    headers={"Authorization": f"Bearer {OPENAI_KEY}", "content-type": "application/json"})
                d = json.load(urllib.request.urlopen(req, timeout=60))
                return d["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 529) and attempt < 3:
                time.sleep(2 * (attempt + 1)); continue
            raise
        except Exception:
            if attempt < 3:
                time.sleep(2 * (attempt + 1)); continue
            raise


def incident(sc, shuffled):
    subtype = (sc.get("subtype") or "unspecified").replace("_", " ")
    sev = sc.get("severity") or "high"
    return (f"SOC incident: a {sev}-severity {THREAT_NAME[sc['threat_type']]} "
            f"({subtype}). Observed ATT&CK techniques in the "
            f"telemetry (unordered): {', '.join(shuffled)}. They form one kill chain.")


def last_tid(text):
    m = TID.findall(text or "")
    return m[-1] if m else None


def run_single(model, sc, shuffled):
    p = (incident(sc, shuffled) + "\n\nIdentify the PRIMARY (kill-chain-initiating) "
         "ATT&CK technique ID. Answer with ONLY the technique ID (e.g., T1566).")
    out = call(model, p)
    return {"final": last_tid(out), "stages": {"single": last_tid(out)}}


def run_pipeline(model, sc, shuffled):
    inc = incident(sc, shuffled)
    s1 = call(model, inc + "\n\nWhich single ATT&CK TACTIC does this incident BEGIN with? "
              "Answer with only the tactic name (e.g., Initial Access).")
    s1t = (s1 or "").strip().splitlines()[0][:60] if s1 else "?"
    s2 = call(model, inc + f"\n\nA triage step determined the incident begins with tactic "
              f"'{s1t}'. From the observed techniques, which ONE is the primary initiator "
              f"under that tactic? Answer with ONLY the technique ID.")
    s2t = last_tid(s2)
    s3 = call(model, inc + f"\n\nA prior stage identified '{s2t}' as the primary technique. "
              f"Confirm the single primary kill-chain-initiating ATT&CK technique ID. "
              f"Answer with ONLY the technique ID.")
    return {"final": last_tid(s3), "stages": {"triage_tactic": s1t, "enrich": s2t, "confirm": last_tid(s3)}}


def one(model, sc, sid, rep):
    rng = random.Random(f"{sid}-{rep}")
    shuffled = sc["techniques"][:]; rng.shuffle(shuffled)
    gt = sc["techniques"][0]              # primary = first (kill-chain-initiating)
    gt_base = gt.split(".")[0]            # score on base technique (ignore sub-technique)
    base = lambda x: x.split(".")[0] if x else None
    rec = {"model": model, "sid": sid, "rep": rep, "gt_primary": gt, "err": False}
    try:
        s = run_single(model, sc, shuffled)
        p = run_pipeline(model, sc, shuffled)
        rec["single_final"] = s["final"]; rec["single_correct"] = (base(s["final"]) == gt_base)
        rec["pipe_final"] = p["final"]; rec["pipe_correct"] = (base(p["final"]) == gt_base)
        rec["pipe_stages"] = p["stages"]
    except Exception as e:
        rec["err"] = True; rec["msg"] = str(e)[:200]
    return rec


def main():
    spath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "output", "calibration_gap_scenarios.json")
    opath = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "output", "cascade_live_runs.json")
    raw = json.load(open(spath))
    if isinstance(raw, dict) and "scenarios" in raw:
        raw = raw["scenarios"]
    # normalise to list of (sid, scenario)
    if isinstance(raw, dict):
        items = sorted(raw.items())
    else:
        items = [(f"S{i:02d}", sc) for i, sc in enumerate(raw)]
    jobs = []
    for model in MODELS:
        for sid, sc in items:
            for rep in range(REPS):
                jobs.append((model, sc, sid, rep))
    print(f"running {len(jobs)} cells x (1 single + 3 pipeline) calls ...", flush=True)
    out = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for rec in ex.map(lambda a: one(*a), jobs):
            out.append(rec)
            if len(out) % 20 == 0:
                print(f"  {len(out)}/{len(jobs)} (errs={sum(r['err'] for r in out)})", flush=True)
    json.dump(out, open(opath, "w"), indent=1)
    print(f"wrote {opath}: {len(out)} records, {sum(r['err'] for r in out)} errors")


if __name__ == "__main__":
    main()
