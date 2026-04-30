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
├── LICENSE                  MIT
├── CITATION.cff             Cite this repository
├── ISAIA_2026/              IEEE ISAIA 2026 conference paper
│   ├── main.pdf               PDF
│   ├── main.tex               LaTeX source (IEEEtran)
│   ├── references.bib
│   ├── sections/              Per-section .tex files
│   └── ISAIA_2026_Overleaf.zip   Direct upload to Overleaf
└── SP_Magazine_2026/        IEEE Security & Privacy Magazine article
    ├── main.pdf               PDF
    ├── main.tex               LaTeX source (IEEEtran journal/compsoc)
    ├── references.bib
    ├── sections/              Per-section .tex files
    └── SP_Magazine_2026_Overleaf.zip   Direct upload to Overleaf
```

Both papers are self-contained: all definitions, the five-dimensional
SKC mismatch model, the Agent Reliability Score, the Epistemic Gap,
the cascade reliability bound, and the experimental findings on 1,000
labelled execution traces are reported inside the respective PDFs.
The conference paper (ISAIA 2026) gives the formal contribution; the
magazine article (S&P Magazine 2026) translates it into deployment
guidance for SOC teams. This page is the project home where future
outputs of the ARES research line will be published as they become
available.

## Citation

If you use this work, please cite the conference paper:

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

For the magazine article:

```bibtex
@article{alam2026aresmag,
  title   = {ARES: A Framework for Measuring Reliability and Failure
             Modes in Autonomous AI Security Agents},
  author  = {Alam, Mohammad Makchudul and Jurcut, Anca Delia and
             Anik, Md.~Redowan Z. and el Bodour, Sabrein S.~E. and
             Islam, Moshiul},
  journal = {IEEE Security \& Privacy},
  year    = {2026},
  note    = {Special issue on Autonomous AI Agents in Computer Security}
}
```

A `CITATION.cff` is also provided so GitHub renders a "Cite this
repository" widget in the sidebar.

## Authors

- **Mohammad Makchudul Alam** — CTI, BGD e-GOV CIRT;
  [DNS Research Lab](https://www.dnsresearchlabs.ucd.ie),
  Dhaka, Bangladesh
  ([engrarifcce@gmail.com](mailto:engrarifcce@gmail.com))
- **Md. Redowan Z. Anik** — Cyber Threat Intelligence, BGD e-GOV CIRT,
  Dhaka, Bangladesh
  ([redowanzanik@gmail.com](mailto:redowanzanik@gmail.com))
- **Sabrein S. E. el Bodour** — Cyber Threat Intelligence, BGD e-GOV CIRT,
  Dhaka, Bangladesh
  ([sabreinserag@gmail.com](mailto:sabreinserag@gmail.com))
- **Anca Delia Jurcut** — School of Computer Science, University College
  Dublin, Dublin, Ireland
  ([anca.jurcut@ucd.ie](mailto:anca.jurcut@ucd.ie))
- **Moshiul Islam** — EIC Limited, Dhaka, Bangladesh
  *(IEEE S&P Magazine article only)*
  ([moshiul@eicsecure.com](mailto:moshiul@eicsecure.com))

## License

Released under the [MIT License](LICENSE).
