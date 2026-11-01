# Camera-ready diff summary — IEEE ISAIA 2026, Paper 93 (ARES)

Changes from the accepted paper to the camera-ready, i.e. commit `64877c1`
("Add ISAIA 2026 point-by-point response to reviewer (Paper 93, accepted)")
→ `754f7a4`.

**No change alters any claim or conclusion. The paper remains 6 pages.**

## File-level diffstat

```
 ISAIA_2026/main.tex                     |   8 +--   author block
 ISAIA_2026/sections/05_experimental.tex |  50 ++--   Section V (largest change)
 ISAIA_2026/sections/06_discussion.tex   |   6 +-    Section VI temporal drift
 safk_corpus/README.md                   |   2 +-    corpus schema note
 ISAIA_2026/RESPONSE_TO_REVIEWER.md      |  70 ++++   reviewer-response log
 ISAIA_2026/RESPONSE_TO_REVIEWER.docx    | Bin        regenerated from .md
 ISAIA_2026/CAMERA_READY_CHANGES.md      | 102 +++    changelog
 ISAIA_2026/ISAIA_2026_LaTeX.zip         | Bin        regenerated source package
 ISAIA_2026/main.pdf                     | Bin        rebuilt (345 KB -> 120 KB)
```

10 commits · 197 insertions / 41 deletions.

## Changes by theme

### 1. IEEE formatting compliance (the committee's comment) — `main.tex`
- Removed the illustration-only ordinal prefixes `1st / 2nd / 3rd / 4th` from all
  four `\IEEEauthorblockN{}` entries. Names, affiliations, and emails otherwise
  unchanged.

### 2. Section V accuracy — corrected against the released benchmark — `sections/05_experimental.tex`
- **Result count:** "four additional framework-level results" → **"five"** (the
  count was stale after the cross-model-family result was added for the reviewer
  response).
- **Labelling protocol:** removed an **unsupported human inter-rater study**
  (Cohen's κ = 0.84 / 0.91, "4.3% of reviewed cases"). It had no backing artifact
  in the repo, the 4.3%-of-100 figure was not a whole number, and it conflicted
  with the corpus's own "analytical, not live" description (SAF-1K taxonomy labels
  are closed-form generated, not human-annotated). Replaced with an accurate
  account: labels assigned **programmatically** against ground-truth-by-construction,
  mapped to the released **O/M/I codes (M3, M2, M5, M4, M6)**, with external
  validity assessed on the real CISA KEV set.
- **Failure-signature taxonomy:** corrected the knowledge-deficit signature — the
  32% bucket is **Missed Detection (M1)**, not Hallucination; the Hallucinated
  share **(M3) is 26%**; removed an unmatched "Misclassification (21%)".
- **Correlation framing:** ρ = 0.92 is now stated as **bucket-aggregated**, with the
  **record-level point-biserial 0.34** reported alongside (matches the abstract and
  `safk_corpus/canonical_paper_numbers.json`); the *p*-value was aligned to
  `p < 0.0001`; a pointer to the Epistemic Gap decomposition was added for the
  (1 − U) interaction term.
- Trimmed a redundant §V.B closing sentence to keep the paper at 6 pages.

### 3. Section VI — softened an overstated claim — `sections/06_discussion.tex`
- Temporal drift: dropped "ARS degrades below θ* in roughly 120 days" (δ_T alone,
  at weight w_T ≈ 0.08, cannot cross θ*) and the backwards "high-volatility" label
  for the slow decay λ = 0.005. Now reads: "the drift term reaches δ_T ≈ 0.45 by
  roughly 120 days, a measurable erosion of ARS that motivates a quarterly refresh."

### 4. Corpus documentation — `safk_corpus/README.md`
- `hallucinated` field: corrected from "M1 manifestation" to an independent binary
  (119 positives = 11.9% overall, distributed across all manifestation codes).

### 5. Transparency artifacts (not paper content)
- `CAMERA_READY_CHANGES.md` — full changelog.
- `RESPONSE_TO_REVIEWER.{md,docx}` — logged all camera-ready corrections; docx
  regenerated from the markdown.
- `main.pdf` and `ISAIA_2026_LaTeX.zip` rebuilt from the corrected source.

## Net effect

Every substantive edit either (a) satisfies the committee's formatting comment, or
(b) fixes a statement that disagreed with the project's own released code/corpus.
Nothing alters the framework, the results, or the conclusions. The single
scientific claim touched (temporal drift) was *softened*, not changed in direction.

## Outstanding
- [ ] Wire in the IEEE copyright notice (`\IEEEpubid`) once the conference ISBN is
      provided (preamble already scaffolded).
- [ ] Validate `main.pdf` via **IEEE PDF eXpress** before resubmission.
- [ ] Resubmit the corrected final paper by **Nov 4, 2026**.
