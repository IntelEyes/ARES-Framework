# Supplementary Analysis

Auxiliary analyses that are not part of the conference paper but
support the broader ARES research line.

## advanced_threats_panel.tex

Stress-test of six production LLMs against eight categories of advanced
security scenarios (75 scenarios total): prompt injection embedded in
threat artefacts, out-of-corpus novel attacks, living-off-the-land
binaries, APT campaigns, modern ransomware families, supply-chain and
zero-day incidents, AI-specific attacks, and BEC / social engineering
lures. Includes a per-model success-rate heatmap rendered as a TikZ
figure.

The panel reproduces the central ARES argument, that the same
reliability signal predicts benign and adversarial failure, at the
adversarial-stress end of the spectrum. It is published here as a
supplementary artefact because it does not fit within the IEEE S&P
Magazine word budget.

Source artefact: `ares_bench/output/advanced_threats_v2.json` (in the
forthcoming SAFK release).
