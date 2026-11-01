# Camera-ready corrections — IEEE ISAIA 2026, Paper 93 (ARES)

Addresses the Organizing Committee's final-proceedings formatting comment plus a
consistency pass of Section V against the released benchmark code/corpus. **No
change alters the paper's claims or conclusions.** The camera-ready remains
**6 pages** and the PDF has been verified to render correctly.

## Why
- The IEEE Organizing Committee flagged one formatting-policy violation during
  final review (deadline **Nov 4, 2026**).
- While fixing it, a review of Section V against `ares_bench/shared/taxonomy.py`
  and `safk_corpus/` surfaced several accuracy/reproducibility issues worth
  correcting before publication.

## Changes

### 1. IEEE formatting compliance (committee comment)
- **`main.tex`** — Removed the illustration-only ordinal prefixes
  ("1st/2nd/3rd/4th") from the four `\IEEEauthorblockN{}` entries. These are
  placeholders in the IEEEtran template; each entry now carries only the
  author's name. Affiliations/emails unchanged.

### 2. Section V accuracy fixes
- **Result count (V-B)** — "four additional framework-level results" → **"five"**
  (five labeled results are presented; the count was stale after the
  cross-model-family result was added for the reviewer response).
- **Labelling protocol (V)** — Removed an unsupported two-annotator inter-rater
  study (Cohen's κ = 0.84/0.91, "4.3% of reviewed cases"). It had no backing
  artifact in the repo, the 4.3%-of-100 figure was not a whole number, and it
  conflicted with the corpus's own "analytical, not live" description (SAF-1K
  taxonomy labels are closed-form generated, not human-annotated). Replaced with
  an accurate account: labels are assigned programmatically against
  ground-truth-by-construction, with external validity on the real CISA KEV set.
- **Failure-signature taxonomy (V-B)** — Reconciled manifestation names with the
  released O/M/I codes. Corrected the knowledge-deficit signature: the 32% bucket
  is **Missed Detection (M1)**, not Hallucination; the Hallucinated share (M3) is
  **26%**. Removed an unmatched "Misclassification (21%)". Added a mapping from
  the paper's five manifestation names → codes **M3, M2, M5, M4, M6** so the
  prose and public corpus labels agree.

### 3. Corpus documentation fix
- **`safk_corpus/README.md`** — The `hallucinated` field was documented as the
  "M1 manifestation"; it is actually an independent binary (119 positives =
  11.9%, spread across all codes). M1 is "Missed Detection".

### 4. Regenerated artifacts
- **`main.pdf`** rebuilt (6 pages, verified render; smaller file size due to a
  different, standards-clean LaTeX engine).
- **`ISAIA_2026_LaTeX.zip`** regenerated from corrected source (was stale).
- **`RESPONSE_TO_REVIEWER.{md,docx}`** — logged all camera-ready corrections for
  transparency; docx regenerated from the markdown.

## Verification
- All numeric claims re-derived from `safk_corpus/` (capability 78%, skill 72%,
  overclaiming ~18%, knowledge M1 32% / M3 26% all confirmed).
- Build clean: no overfull boxes, no undefined references, **6 pages**.
- PDF pages rasterized and visually inspected: author block, Section V edits,
  figure, and two-column layout all render correctly.

## Commits
```
d5f3c24  fix(isaia): remove IEEE template illustration labels from author block
c989dfb  docs(isaia): note camera-ready author-label fix in reviewer response
254a243  docs(isaia): regenerate reviewer-response docx from updated markdown
535243c  fix(isaia): correct 'four'->'five' framework-level results in Sec V-B
e8a84a9  fix(isaia): replace unsupported inter-rater claim with programmatic labelling
850ee66  fix(isaia): correct Sec V taxonomy claims against released O/M/I codes
b19810b  docs(isaia): log additional camera-ready corrections in reviewer response
571e6a4  docs(isaia): 'annotation pipeline' -> 'labelling pipeline' for consistency
```

## Files
```
ISAIA_2026/main.tex                      |  8 +-
ISAIA_2026/sections/05_experimental.tex  | 27 ++--
ISAIA_2026/RESPONSE_TO_REVIEWER.md       | 70 +++++++--
ISAIA_2026/RESPONSE_TO_REVIEWER.docx     | (regenerated)
ISAIA_2026/ISAIA_2026_LaTeX.zip          | (regenerated)
ISAIA_2026/main.pdf                      | (rebuilt)
safk_corpus/README.md                    |  2 +-
```

## Post-review consistency pass (Section V/VI)
A full read-through surfaced three residual issues, now fixed (no claim altered,
still **6 pages**):
- **§V.A correlation (V)** — The body attributed $\rho = 0.92$ to "the 750
  LLM-agent traces" (record-level framing), but 0.92 is the *bucket-aggregated*
  value; the record-level point-biserial is **0.34** (`canonical_paper_numbers.json`).
  Reworded to state both, matching the abstract. Also aligned the $p$-value to
  the abstract ($p < 0.0001$) and pointed to the Epistemic Gap for the $(1-U)$ term.
- **§VI temporal drift** — Softened an overstated claim: $\delta_T$ alone
  (weight $w_T \approx 0.08$) cannot push ARS below $\theta^*$, and $\lambda = 0.005$
  is a slow, not "high-volatility", decay. Now: the drift term reaches
  $\delta_T \approx 0.45$ by ~120 days, "a measurable erosion of ARS" motivating a
  quarterly refresh.
- Trimmed a redundant §V.B closing sentence to keep the paper at 6 pages.

## Follow-ups (not in this change set)
- [ ] Wire in the IEEE copyright notice (`\IEEEpubid`) once the conference ISBN
      is provided (preamble already scaffolded).
- [ ] Validate `main.pdf` via **IEEE PDF eXpress** before resubmission.
- [ ] Resubmit corrected final paper by **Nov 4, 2026**.
