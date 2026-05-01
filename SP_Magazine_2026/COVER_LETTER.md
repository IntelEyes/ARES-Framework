# Cover Letter — IEEE Security & Privacy Magazine

**To:** The Editors
**Special Issue:** Autonomous AI Agents in Computer Security
**Date:** 30 April 2026

**Submission title.**
*ARES: A Framework for Measuring Reliability and Failure Modes in Autonomous AI Security Agents*

**Authors.**
Mohammad Makchudul Alam¹·², Md. Redowan Zaman Anik², Sabrein Serag El Din el Bodour², Moshiul Islam Mishu³, and Anca Delia Jurcut⁴.
*¹DNS Research Lab, University College Dublin · ²BGD e-GOV CIRT, Dhaka, Bangladesh · ³EIC Limited, Dhaka, Bangladesh · ⁴School of Computer Science, University College Dublin, Ireland.*

**Corresponding author.** Mohammad Makchudul Alam, engrarifcce@gmail.com.

---

Dear Editors,

We are pleased to submit our manuscript for your consideration in the special issue on *Autonomous AI Agents in Computer Security*.

**Why this article fits the special issue.** Autonomous AI agents are now triaging alerts, enriching incidents, and recommending containment actions in production Security Operations Centres. Yet the conditions under which they fail — and the operational consequences of those failures — remain poorly characterised. This article provides a practical reliability framework, **ARES**, that translates failures into measurable risk: a five-dimensional Skill–Knowledge–Capability mismatch model, an Agent Reliability Score, and an Epistemic Gap metric that captures *confident ignorance*. The framing is squarely operational and aimed at SOC practitioners as well as researchers, matching the special issue's emphasis on the security implications of agent autonomy.

**Empirical contribution.** Using the ARES-Bench testbed and the SOCAgentFailure-1K labelled corpus (1,000 traces across four agent architectures and five threat classes), we report five practitioner-actionable findings: knowledge gaps drive hallucination; mismatch dimensions produce diagnostically distinct failure signatures; ARS works as a generalisable pre-execution reliability gate (test F1 = 0.96 across all five threat classes); multi-agent pipelines amplify rather than mitigate component failures (a 17.25 % pipeline-depth penalty isolated under controlled ablation); and the Epistemic Gap separates knowledge risk from confidence risk as independently controllable mitigations. Each finding is paired with a deployment implication for SOC architects.

**Self-contained article.** The manuscript stands alone: definitions, the SKC model, the empirical findings, and the deployment guidance are all reported inside the PDF. The artefact repository at `https://github.com/IntelEyes/ARES-Framework` hosts the testbed code, the labelled corpus (CC BY 4.0), and the canonical-numbers JSON file that supports every headline statistic in the article.

**Originality declaration.** This work is original, has not been previously published, and is not under concurrent review by any other journal or conference. A formal companion paper covering the theorem proofs and full experimental tables has been prepared for a separate venue; the present submission is a self-contained magazine article. Author contributions span agent architecture and benchmark engineering (Alam), incident-handling-grounded scenario design (Anik, el Bodour), industry validation against operational PCI-DSS / SOC / GRC contexts (Islam Mishu), and supervisory direction in network security and trustworthy AI (Jurcut).

**Anonymisation.** The submission is single-anonymous per the special-issue policy: author names and affiliations appear on the title page. No double-anonymous redaction was applied.

We hope this article will be of interest to your readership and look forward to the reviewers' feedback.

Sincerely,

Mohammad Makchudul Alam, on behalf of all authors
DNS Research Lab, University College Dublin
engrarifcce@gmail.com
