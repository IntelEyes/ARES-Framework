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
documents both the generation and the labelling pipeline in full.

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

**Annotation** (Section V, *Labelling protocol*): failure modes are assigned by
a deterministic rule-based engine that compares each agent output against the
ATT&CK-derived ground truth using a fixed codebook of five manifestations.
Because the corpus is analytical — each scenario fixes the ground truth by
construction — labels are assigned programmatically rather than estimated from
human annotation, so they are exact rather than inter-annotator estimates. The
full codebook and labelling engine are released with the testbed, and external
validity is assessed separately on real, post-cutoff incidents (the 30-incident
CISA KEV validation) rather than by re-annotating the analytically generated
corpus.

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

## Camera-ready formatting compliance (Organizing Committee, final proceedings review)

Separately from the reviewer's technical comments above, the IEEE ISAIA 2026
Organizing Committee's final-review of the proceedings identified one IEEE
formatting-policy issue, which we have corrected in the camera-ready.

### Committee comment: Remove labels "1st Author," "2nd Author," etc. — these are in the IEEE template for illustration purposes only.

Addressed. The `\IEEEauthorblockN{}` entries in `main.tex` retained the
illustration-only ordinal prefixes from the IEEEtran template
("1st", "2nd", "3rd", "4th"). These have been removed so each entry now
carries only the author's name; affiliations and contact details are
unchanged. The PDF was rebuilt (still 6 pages, no reflow) and the bundled
`ISAIA_2026_LaTeX.zip` source package regenerated from the corrected source.
The revised PDF will be re-validated through IEEE PDF eXpress prior to final
submission.

---

## Additional camera-ready corrections (authors' final consistency pass)

While preparing the camera-ready we ran a consistency pass of Section V against
the released benchmark code and corpus, and corrected the following for
accuracy and reproducibility. None alter the paper's claims or conclusions.

1. **Result count (Section V-B).** The summary sentence said "four additional
   framework-level results" while five labeled results are presented; the
   cross-model-family result added in response to Comment 2 was not reflected
   in the count. Corrected to "five."

2. **Labelling protocol (Section V).** The description of a two-annotator
   inter-rater study (Cohen's κ, revision rate) was removed, as it did not
   correspond to the released artifacts: the SOCAgentFailure-1K corpus is
   analytical, with taxonomy labels assigned programmatically from
   ground-truth-by-construction rather than by human annotation. The paragraph
   now states this accurately, and external validity is attributed to the
   real-incident (CISA KEV) validation set.

3. **Failure-signature labels (Section V-B).** Reconciled the manifestation
   names with the released O/M/I taxonomy. The knowledge-deficit signature was
   corrected — the 32% bucket is *Missed Detection* (code M1), not
   *Hallucination*; the *Hallucinated* share (M3) is 26% — and an unmatched
   "Misclassification (21%)" figure was removed. A mapping from the paper's
   five manifestation names to the released codes (M3, M2, M5, M4, M6) was
   added so the prose and the public corpus labels agree.

All corrections were verified against `ares_bench/shared/taxonomy.py` and the
`safk_corpus/` data, and the camera-ready PDF remains 6 pages.

---

We thank the reviewer again for the careful reading and the helpful suggestions,
which have improved the clarity and reproducibility of the final version.
