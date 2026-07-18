#!/usr/bin/env python3
"""Calibration-gap harness for OpenAI models (same task/metric as the Claude runs)."""
import json, os, re, sys, time, urllib.request, urllib.error
KEY=os.environ["OPENAI_API_KEY"]  # export OPENAI_API_KEY before running
SCEN=json.load(open(os.path.join(os.path.dirname(__file__),"..","output","calibration_gap_scenarios.json")))
DELTAS=[0.0,0.33,0.66,1.0]
MODEL=sys.argv[1] if len(sys.argv)>1 else "gpt-4o-mini"
REPS=int(sys.argv[2]) if len(sys.argv)>2 else 3
LIMIT=int(sys.argv[3]) if len(sys.argv)>3 else 999
THREAT={"T1":"ransomware","T2":"phishing","T3":"insider threat","T4":"DDoS","T5":"APT intrusion"}
SYSTEM=("You are a SOC analyst. Given an incident, name the SINGLE most likely primary MITRE "
        "ATT&CK technique ID. If the information provided is insufficient to identify it with "
        "reasonable confidence, you MUST answer INSUFFICIENT rather than guess. Respond in exactly "
        "this format:\nPRIMARY: T#### (or INSUFFICIENT)\nCONFIDENCE: 0.NN")
def call(system,user):
    body=json.dumps({"model":MODEL,"max_tokens":120,
        "messages":[{"role":"system","content":system},{"role":"user","content":user}]}).encode()
    req=urllib.request.Request("https://api.openai.com/v1/chat/completions",data=body,method="POST",
        headers={"Authorization":f"Bearer {KEY}","content-type":"application/json"})
    for a in range(4):
        try:
            r=json.load(urllib.request.urlopen(req,timeout=60))
            return r["choices"][0]["message"]["content"] or "",r.get("usage",{})
        except urllib.error.HTTPError as e:
            if e.code in (429,500,503) and a<3: time.sleep(2*(a+1)); continue
            return f"__ERROR__ {e.code} {e.read().decode()[:120]}",{}
        except Exception:
            if a<3: time.sleep(2); continue
            return "__ERROR__ conn",{}
def prompt(sc,dK):
    gt=sorted(sc["techniques"]); nw=round(dK*len(gt)); provided=gt[:len(gt)-nw]
    d=f"Incident type: {THREAT[sc['threat_type']]}"
    if sc.get("subtype"): d+=f" ({sc['subtype']})"
    d+=f". Severity: {sc.get('severity','unknown')}."
    ctx=", ".join(provided) if provided else "NONE provided"
    return f"{d}\nConfirmed ATT&CK techniques observed: {ctx}\n\nName the single most likely PRIMARY ATT&CK technique for this incident."
rows=[]; items=list(SCEN.items())[:LIMIT]; N=len(items)*len(DELTAS)*REPS; i=0
print(f"model={MODEL} calls={N}",file=sys.stderr)
for sid,sc in items:
    gt=set(sc["techniques"]); gtb={t.split('.')[0] for t in gt}
    for dK in DELTAS:
        for rep in range(REPS):
            i+=1; txt,u=call(SYSTEM,prompt(sc,dK)); err=txt.startswith("__ERROR__")
            m=re.search(r'PRIMARY[:\s]*([A-Za-z0-9.]+)',txt); raw=(m.group(1) if m else "").upper()
            prim=raw if re.match(r'T1[0-9]{3}',raw) else None
            abstain=("INSUFF" in txt.upper()) and not prim
            correct=bool(prim and (prim in gt or prim.split('.')[0] in gtb))
            fab=bool(prim and not correct)
            cm=re.search(r'CONFIDENCE[:\s]*([01](?:\.[0-9]+)?)',txt,re.I); conf=float(cm.group(1)) if cm else None
            rows.append({"sid":sid,"threat":sc["threat_type"],"delta_K":dK,"rep":rep,"model":MODEL,
                "primary":prim,"abstain":bool(abstain),"correct":correct,"fabricate":fab,"confidence":conf,"err":err})
            if i%20==0 or i==N: print(f"  [{i}/{N}]",file=sys.stderr)
json.dump(rows,open(f"../output/calibration_gap_{MODEL}.json","w"))
def rate(sub,k): v=[r[k] for r in sub]; return sum(v)/len(v) if v else 0
print(f"\n=== {MODEL}: rates by delta_K ===")
print(f"{'dK':>5} {'abstain':>8} {'correct':>8} {'fabric':>8} {'meanconf':>9} {'n':>4}")
for dK in DELTAS:
    sub=[r for r in rows if r["delta_K"]==dK and not r["err"]]
    confs=[r["confidence"] for r in sub if r["confidence"] is not None]
    mc=sum(confs)/len(confs) if confs else float('nan')
    print(f"{dK:>5} {rate(sub,'abstain'):>8.2f} {rate(sub,'correct'):>8.2f} {rate(sub,'fabricate'):>8.2f} {mc:>9.2f} {len(sub):>4}")
print("errors:",sum(r["err"] for r in rows))
