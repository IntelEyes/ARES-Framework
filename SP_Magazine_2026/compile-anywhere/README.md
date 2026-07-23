# Compile-anywhere variants

The canonical source is the parent directory (`main.tex` + `sections/` +
`references.bib`), which needs pdfLaTeX and a BibTeX pass. These two variants
exist for environments that cannot handle that structure.

| File | Use when |
|---|---|
| `singlefile.tex` | An editor compiles only a single root file, or `\input{sections/...}` cannot resolve (e.g. an Overleaf project where the upload landed in a subfolder). All 10 sections and the resolved bibliography are inlined; no BibTeX pass needed. |
| `minimal-deps.tex` + `fig1_skc_pipeline.pdf` | A restricted or sandboxed LaTeX service rejects the source. Identical to `singlefile.tex` but with TikZ removed entirely: Fig. 1 is pre-rendered and included via `\includegraphics`. Loads only TeX Live core packages. Pure ASCII. |

Both compile with `pdflatex` alone (run twice for cross-references) and produce
the same 8-page manuscript as the canonical source.
