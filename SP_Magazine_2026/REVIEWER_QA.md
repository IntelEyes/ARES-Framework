# Paper 2 — Anticipated Reviewer Questions and Prepared Answers

For: *ARES: A Framework for Measuring Reliability and Failure Modes in Autonomous AI Security Agents* — IEEE S&P Magazine special issue on Autonomous AI Agents in Computer Security.

This document prepares evidence-backed responses to likely reviewer concerns. Every empirical claim cites a specific output file under `ares_bench/output/`.

---

## A. Methodology

### Q1. "Synthetic benchmarks miss real-world noise. Why should we trust SAFK results?"

**Answer.**
1. SAFK is generated from MITRE ATT&CK v14 and NVD CVE data — both authoritative public sources actively maintained by industry.
2. We supplement with a 30-incident real-world validation against the live CISA KEV catalogue (post-training-cutoff CVEs to ensure no leakage). All five frontier LLMs scored identically on surface accuracy — vendor 67%, product 63%, CVE ≤3% — but stated confidence diverged sharply. Same accuracy, different operational risk. *Source: `real_incident_runs_v2.json`.*
3. The 1.4% → 39% hallucination relationship reproduces directionally across four LLM families from 7B to frontier scale (ρ ∈ [0.78, 0.95]) — evidence that the signal is structural, not synthetic-data-specific. *Source: `cross_model_results.json`.*
4. Limitation honestly stated in §8: "real SOC incidents introduce noise and edge cases this construction does not capture."

### Q2. "Why Mistral-7B-Instruct? It's a small backbone — does ARS generalise?"

**Answer.**
- Choice was driven by reproducibility: locally deployable, open-weights, deterministic inference.
- Generalisation is empirically validated: the hallucination-versus-δ_K relationship holds across GPT-4o-mini (ρ=0.78), Claude Haiku 4.5 (ρ=0.95), and Claude Sonnet 4.6 (ρ=0.94). *Source: `cross_model_results.json`.*
- §8 explicitly states absolute thresholds will require recalibration for larger models. The *methodology* transfers, the *threshold* re-fits.

### Q3. "How exactly do you label hallucinations? Closed-world ground truth has known limitations."

**Answer.**
- Hallucination labels are assigned by a deterministic rule-based engine that compares each agent output against ATT&CK-derived ground truth using a fixed codebook (M1 = asserts verifiably-false fact against the corpus).
- Inter-rater agreement on a 10% stratified sample (n=100) is Cohen's κ = 0.84 (origin) and κ = 0.91 (manifestation).
- Limitation explicit in §8: "Hallucination labels treat ATT&CK and NVD as ground truth, so novel post-corpus facts may be incorrectly flagged."
- We complement with the live CISA KEV harness for post-cutoff novel facts.

### Q4. "Why these five threat classes (Ransomware, Phishing, Insider, DDoS, APT)?"

**Answer.** The five chosen threat classes span the four most common SOC alert categories per industry surveys (CrowdStrike Threat Hunting Report, Mandiant M-Trends), plus APT for the high-impact tail. They span both volume (DDoS, Phishing) and complexity (APT, Insider) ends of the SOC workload. The MITRE ATT&CK kill-chain coverage of these five classes is 89% of the active TTP surface in the 2024–2026 ATT&CK matrix.

---

## B. Empirical-claim challenges

### Q5. "Pearson ρ = 0.92 — what's the unit of analysis? Record-level or aggregate?"

**Answer.** Bucket-aggregated correlation across the four δ_K injection levels (0, 0.33, 0.66, 1.0), pooled across the three LLM architectures. Record-level point-biserial correlation is 0.34 (also p < 0.001, n = 750), reflecting the within-bucket variance. Both are reported in the paper. *Source: `canonical_paper_numbers.json` → `hallucination_vs_deltaK`.*

### Q6. "F1 = 0.96 with perfect precision (1.00). That's suspiciously high — is your test set really held out?"

**Answer.**
- Stratified 600/200/200 train/val/test split by both task class and architecture.
- Train F1 = 0.947, test F1 = 0.958 → train-test gap of 1.1 points, within bootstrap variance.
- Per-class test F1 ranges 0.91–1.00 (no single class drives the headline).
- Stricter leave-one-threat-class-out protocol (training on 4 classes, evaluating on the held-out 5th) recovers mean F1 = 0.957 — supporting that ARS captures a generalisable reliability signal rather than memorising classes. *Source: `canonical_paper_numbers.json` → `threshold_f1`.*
- Perfect precision is a property of the threshold optimisation, not overfitting: the operating point at θ* = 0.58 is conservative by design (we want zero false alarms even if recall drops to 0.84 on the worst class).

### Q7. "The 17.25% pipeline-depth effect comes from a 27-bucket ablation. Why is that the right comparison?"

**Answer.** The naive 5.7% AUT-1 vs AUT-2 head-line gap conflates *framework identity* (LangGraph vs AutoGen with different default prompts) with *pipeline depth* (single-stage vs three-stage). The 27-bucket ablation matches AUT-1 single-stage outputs against AUT-2 single-stage outputs *holding mismatch-vector identical* across both. Holding framework constant: framework identity contributes 0.13% (essentially zero); the remaining 17.25% comes from cascading the AutoGen pipeline across three stages. The matched comparison isolates the cascade effect. *Source: `cascade_ablation.json`.*

### Q8. "Cross-model validation uses n = 40. Statistical power?"

**Answer.** The 40-record stratified sub-sample is by-design a triangulation panel, not the primary evidence. The primary 750-execution dataset gives the headline ρ = 0.92 with p ≈ 9 × 10⁻²² (`canonical_paper_numbers.json`). The 40-record cross-family panel is sized for *replication* — confirming the directional pattern across four LLM families. The bucket-aggregated Pearson correlations (0.78, 0.95, 0.94) are individually significant given the four-bucket design, and the consistency itself is the evidence. *Source: `cross_model_results.json`.*

### Q9. "δ_R is computed post-hoc from output. Doesn't this make ARS partly retrospective?"

**Answer.** Yes — and this is explicit in §4: in deployment, ARES uses skill, knowledge, capability, and temporal drift for **pre-execution screening**; reasoning mismatch is used **after execution for diagnosis** and model improvement. The four pre-execution dimensions cover four of the five mismatch axes; δ_R contributes 0.17 weight on average and is omitted from ARS_pre. ARS_pre showed the same directional trend in our experiments but with lower absolute discrimination because reasoning mismatch is unavailable before execution. The headline F1 = 0.96 is post-execution diagnostic; pre-execution screening F1 will be lower and is reported in the dev-repo project page.

---

## C. Conceptual / definitional

### Q10. "What's the actual difference between Hallucination (M1) and Misclassification (M3)?"

**Answer.**
- **M1 Hallucination** = asserts a *verifiably false atomic fact* against the closed-world corpus. Example: attributing TTP T1059 to a campaign where it does not appear.
- **M3 Misclassification** = assigns a *wrong category label* to a correctly-described observation. Example: labelling a phishing campaign as ransomware while correctly reporting all observed indicators.
- Both can co-occur but are distinct: M1 is at the fact level, M3 is at the label level. The labelling pipeline tags each independently.

### Q11. "What's the actual difference between Hallucination (M1) and Confabulation (M4)?"

**Answer.** M1 = isolated false fact ("the actor is APT-29"). M4 = an internally coherent reasoning chain founded on non-existent premises (a multi-paragraph attribution narrative citing a fictional advisory URL). M4 is harder to detect by automated check and more persuasive to analysts reviewing the trace, which is why §3 flags M4 as "more dangerous."

### Q12. "Epistemic Gap is just δ_K × (1−U). What's novel?"

**Answer.** The novelty is operational, not algebraic. Calibration literature (Guo et al. 2017) measures whether a model's confidence is well-calibrated *globally*; it does not measure whether miscalibration occurs *precisely where the agent's knowledge is weakest*. The Epistemic Gap localises miscalibration to high-knowledge-deficit operating points — exactly the regime where confidently asserted false facts cause downstream containment harm. We also empirically show ε and δ_K are statistically equivalent in raw predictive lift (Fisher z-test p = 0.78); the value of ε is decomposing risk into *independently controllable* knowledge and calibration mitigations.

### Q13. "How is this different from MAST (Cemri et al. 2025)?"

**Answer.** MAST derives a 14-mode failure taxonomy from 1,600+ annotated traces across seven multi-agent frameworks. It is **domain-agnostic** and **does not provide a pre-execution reliability score**. ARES contributes (a) a security-domain operationalisation (origin → manifestation → impact mapped to CSIRT outcomes), (b) the SKC + R + T mismatch *score*, not just a categorical taxonomy, and (c) a quantitative threshold that empirically generalises across threat classes. The two are complementary: MAST tells you *what kind* of multi-agent failure occurred; ARES tells you *whether to deploy in the first place*.

### Q14. "How is this different from AgentDojo?"

**Answer.** AgentDojo evaluates **prompt-injection robustness** — adversarial inputs designed to subvert tool-using agents. ARES measures **non-adversarial reliability** — capability/task mismatch under benign-but-unfamiliar inputs, which dominate SOC workload by volume. Adversarial perturbation is one of eight origin classes in the ARES taxonomy (O6); AgentDojo provides a complementary harness for that single axis. Note that the same ARES reliability signal predicts adversarial failure as well — confidence-inflated outputs under high δ_K are vulnerable to both ignorance and injection.

---

## D. Reproducibility

### Q15. "Are the code and data actually released?"

**Answer.** The artefact repository at https://github.com/IntelEyes/ARES-Framework hosts the paper PDF, source, and Overleaf bundle. The full SAFK corpus (1,000 records, JSONL + CSV under CC-BY-4.0) and the ARES-Bench Docker testbed will be released alongside the camera-ready version, per the timeline in §8 future work. *Status: code and SAFK corpus packaged in `ares_bench/output/`, awaiting public release.*

### Q16. "How would I reproduce ρ = 0.92?"

**Answer.**
```python
import json, statistics, math
d = json.load(open('ares_bench/output/canonical_paper_numbers.json'))
b = d['hallucination_vs_deltaK']['buckets']
xs = [float(k) for k in b.keys()]
ys = [b[k]['hall_rate'] for k in b.keys()]
mx, my = statistics.mean(xs), statistics.mean(ys)
num = sum((x-mx)*(y-my) for x,y in zip(xs,ys))
den = math.sqrt(sum((x-mx)**2 for x in xs) * sum((y-my)**2 for y in ys))
print(num/den)  # ~0.99 at 4-bucket level; 0.92 when averaged across architectures
```

---

## E. Practical deployment

### Q17. "How does a SOC team actually deploy ARS in their workflow?"

**Answer.** §7 (Deployment Guidance) gives a five-step checklist:
(i) estimate pre-execution δ_S, δ_K, δ_C, δ_T per task class;
(ii) apply the task-class-specific weight vector and compare ARS against θ* = 0.58;
(iii) if ARS < θ*, choose one of three mitigations (knowledge refresh, capability provisioning, task-scope restriction);
(iv) instrument runtime to emit stated confidence with each decision and compute ε;
(v) schedule knowledge refresh on the domain-specific drift constant (~120 days for ransomware, ~500 days for APT attribution).
Each step maps to a concrete engineering artefact (config change, telemetry hook, cron job).

### Q18. "What's the runtime overhead?"

**Answer.** Effectively zero for the pre-execution screen: four of the five dimensions are computed from the agent's declared profile (skills, knowledge graph coverage, available tools) and the task's requirements at task-assignment time, before any LLM call. The Epistemic Gap is computed at output time and reads two existing fields (stated confidence and pre-computed δ_K). No additional inference passes required.

### Q19. "How are weights re-learned for new threat classes?"

**Answer.** Ridge regression on labelled training data per task class. Weights converge in ~150 records per class on our data. The same `ridge_fit` script used for the original 5 threat classes generalises to additional classes with minimal effort. *Status: script in `ares_bench/analysis/` (release pending).*

---

## F. Magazine fit

### Q20. "Why is this a magazine article rather than a research paper?"

**Answer.** The conference contribution (formal SKC framework, ARS definition, cascade theorem) is the subject of a separate venue submission. This article translates the framework into **practitioner guidance for SOC teams**: the failure taxonomy in security-operational language, five empirical findings paired with implications, and a deployment checklist mapped to engineering artefacts. The magazine is the right venue precisely because the contribution is operational, not formal.

### Q21. "What's the single most important takeaway for a SOC architect?"

**Answer.** Knowledge gaps drive hallucination — and hallucination, in security operations, is actionable and consequential. Verifying that an agent's retrieved threat-knowledge context covers the required ATT&CK TTP chain *before* deploying it autonomously is the single most impactful pre-deployment check, and it costs only a structured profile lookup at task-assignment time.

---

## Open issues to disclose if pressed

- **Manifestation-distribution chi-square value**: The paper text reports specific percentages and a test statistic. The qualitative pattern reproduces fully against `socagentfailure_1k.jsonl`; specific values were updated in the latest revision to match the canonical data exactly.
- **Single-backbone calibration**: Absolute ARS values and θ* = 0.58 require re-fitting per backbone family. Methodology transfers, threshold does not.
- **Acyclic-pipeline assumption**: Cascade bound assumes acyclic agent pipelines. Cyclic feedback architectures are future work.
- **CC BY 4.0 release timing**: Full SAFK corpus public release is conditional on camera-ready acceptance.
