# Response to Reviewer: IEEE ISAIA 2026, Paper 93

**Title:** ARES: A Formal Reliability Framework for Detecting Anomalous Behaviour
in Agentic AI Systems
**Authors:** Mohammad Makchudul Alam, Md. Redowan Zaman Anik,
Sabrein Serag El Din el Bodour, Anca Delia Jurcut
**Decision:** Accept (Reviewer 1, score 2, "recommend acceptance in its current
format")

---

We thank the reviewer for the positive assessment and for recommending
acceptance. We are grateful for the constructive suggestions, and we have
incorporated all three into the camera-ready version. Because the reviewer
recommended acceptance in the current format, the changes are enhancements that
strengthen the paper without altering its claims. Each point is addressed below,
with a pointer to the relevant text.

---

### Comment 1: Clarify how the benchmark data was generated / collected, and the annotation process (for reproducibility)

We agree that reproducibility rests on this being explicit, and Section V now
documents both the generation and the annotation pipeline in full.

**Data generation** (Section V, *Dataset construction*): scenarios are templated
from MITRE ATT&CK v14 kill-chains and NVD CVE records, each fixing a ground-truth
threat class, TTP chain, and required capability profile against which the
agent's output is scored. Mismatch is injected through deliberately realistic
mechanisms rather than random corruption: δ_S disables skill/tool nodes in the
execution graph; δ_K filters ATT&CK TTP context from retrieval to a controlled
fraction; δ_C intercepts tool calls via a permission-denying middleware proxy;
δ_R inserts misleading content into the system prompt at a controlled
probability; and δ_T is set through the agent's knowledge-age attribute.
Generation is deterministic (fixed seed), and the full generator, injection
harness, and per-record provenance are released with the testbed so every trace
is reproducible from source.

**Annotation** (Section V, *Labelling protocol*): failure modes are first
assigned by a deterministic rule-based engine that compares each agent output
against the ATT&CK-derived ground truth using a fixed codebook of five
manifestations. A 10% stratified sample (n = 100) is then independently reviewed
by two annotators; inter-rater agreement is Cohen's κ = 0.84 for origin code and
κ = 0.91 for manifestation code, with disagreements resolved by adjudication and
rule-based labels revised to match human judgement in 4.3% of reviewed cases.

To support reproducibility beyond the description, the SOCAgentFailure-1K corpus,
the generator, and the evaluation testbed are released publicly
(https://github.com/IntelEyes/ARES-Framework).

### Comment 2: Discuss how the framework performs across other leading LLMs beyond the Mistral backbone

Section V includes a *Cross-model-family generalisation* result addressing this
directly. Beyond the Mistral-7B-Instruct backbone used for the main corpus, we
evaluate the knowledge-mismatch-versus-hallucination relationship across four LLM
families spanning 7B to frontier scale, Mistral-7B-Instruct, GPT-4o-mini,
Claude Haiku 4.5, and Claude Sonnet 4.6. The relationship replicates directionally
(bucket-aggregated ρ ∈ [0.78, 0.95]), with absolute thresholds requiring
per-model recalibration. The *shape* of the signal therefore transfers across
backbones even though the operating threshold must be re-fit per model, which we
also note in the Discussion (*LLM specificity*).

### Comment 3: Additional discussion on future directions

We have expanded the future-work discussion in Section VII. It now leads with the
most consequential direction, moving from controlled injection to live
measurement, recovering the mismatch dimensions from real agents in a production
SOC where δ_K and expressed uncertainty are read from telemetry rather than set by
construction, and notes that companion work has begun on the knowledge and
calibration terms, with early results suggesting that agent calibration, not
knowledge coverage alone, governs whether a mismatch becomes a dangerous failure.
Cyclic multi-agent architectures and adversarial mismatch injection are stated as
further open directions.

---

We thank the reviewer again for the careful reading and the helpful suggestions,
which have improved the clarity and reproducibility of the final version.
