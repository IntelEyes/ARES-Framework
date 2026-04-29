# ARES: A Formal Reliability Framework for Agentic AI Security Systems

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Project page for the **ARES** (Agentic Reliability Evaluation for Security
systems) framework — a formal reliability and anomaly-detection model for
autonomous AI agents deployed in Security Operations Centres (SOCs).

## What is ARES?

ARES quantifies the gap between what a security task demands and what an
agent can deliver across five dimensions — **Skill, Knowledge, Capability,
Reasoning, and Temporal drift (SKC + R + T)** — and uses that gap to predict
agent failures *before and during* execution.

The framework introduces:

- A **five-dimensional SKC mismatch vector** with a learnable, task-class
  specific **Agent Reliability Score (ARS)** for pre-execution screening.
- An **Epistemic Gap** metric that formalises the hallucination
  precondition as *confident ignorance*: the interaction between knowledge
  deficit and miscalibrated confidence.
- A **cascade reliability bound** for tightly-coupled multi-agent
  pipelines, and a **temporal-drift model** for knowledge ageing.

## Contents

```
ARES-Framework/
├── README.md
├── LICENSE                      MIT
├── CITATION.cff                 Cite this repository
└── Paper1_ISAIA_2026/           IEEE ISAIA 2026 conference paper
    ├── main.pdf                   Camera-ready PDF
    ├── main.tex                   LaTeX source (IEEEtran)
    ├── references.bib
    ├── sections/                  Per-section .tex files
    └── Paper1_ISAIA_2026_Overleaf.zip   Direct upload to Overleaf
```

The conference paper is self-contained: all definitions, the
five-dimensional SKC mismatch model, the Agent Reliability Score, the
Epistemic Gap, the cascade reliability bound, and the experimental
findings on 1,000 labelled execution traces are reported inside the
PDF. This page is the project home where future outputs of the ARES
research line will be published as they become available.

## Citation

If you use this work, please cite:

```bibtex
@inproceedings{alam2026ares,
  title     = {ARES: A Formal Reliability Framework for Detecting
               Anomalous Behaviour in Agentic AI Systems},
  author    = {Alam, Mohammad Makchudul and Anik, Md.~Redowan Z. and
               el Bodour, Sabrein S.~E. and Jurcut, Anca Delia},
  booktitle = {Proc.\ IEEE Int.\ Symp.\ on Artificial Intelligence
               Applications (ISAIA)},
  year      = {2026}
}
```

A `CITATION.cff` is also provided so GitHub renders a "Cite this
repository" widget in the sidebar.

## Authors

- **Mohammad Makchudul Alam** — BGD e-GOV CIRT, ICT Division;
  DNS Research Lab, UCD ([engrarifcce@gmail.com](mailto:engrarifcce@gmail.com),
  ORCID: [0009-0007-1823-2386](https://orcid.org/0009-0007-1823-2386))
- **Md.~Redowan Z. Anik** — BGD e-GOV CIRT, ICT Division
- **Sabrein S.~E. el Bodour** — BGD e-GOV CIRT, ICT Division
- **Anca Delia Jurcut** — School of Computer Science, University College
  Dublin

## License

Released under the [MIT License](LICENSE).
