"""
ARES-Bench Realistic Cybersecurity Data Source Catalog.

Catalogues publicly available cybersecurity datasets that can feed into
the ARES testbed and benchmark pipeline.  Each entry records provenance,
licensing, format, which ARES threat types (T1-T5) and which ARES
component (scenario_engine, mismatch_injector, agents, anomaly_monitor,
dataset_writer, orchestrator) it supports.

Sources already integrated into ARES are marked with ``integrated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class DataSourceCatalog:
    """Metadata for a single realistic cybersecurity dataset."""

    name: str
    url: str
    description: str
    license: str
    format: str
    threat_types: List[str] = field(default_factory=list)
    ares_component: str = ""
    actively_maintained: bool = True
    integrated: bool = False


# ---------------------------------------------------------------------------
# Catalog  (keys are short snake_case identifiers)
# ---------------------------------------------------------------------------
REALISTIC_DATA_SOURCES: Dict[str, DataSourceCatalog] = {
    # =======================================================================
    # Splunk / SOC Training
    # =======================================================================
    "splunk_bots_v1": DataSourceCatalog(
        name="Splunk BOTS v1 (Boss of the SOC)",
        url="https://github.com/splunk/botsv1",
        description=(
            "Captured-the-flag style SOC dataset from Splunk's 2016 Boss of "
            "the SOC competition.  Contains web-server compromise, ransomware "
            "execution, and data exfiltration across Windows, Suricata, and "
            "stream logs."
        ),
        license="CC-BY-SA-4.0",
        format="Splunk index (exported as compressed tgz/csv)",
        threat_types=["T1", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "splunk_bots_v2": DataSourceCatalog(
        name="Splunk BOTS v2 (Boss of the SOC)",
        url="https://github.com/splunk/botsv2",
        description=(
            "Second iteration of Splunk BOTS featuring APT-style attack "
            "chains, cryptocurrency mining, and cloud-service abuse across "
            "AWS and on-prem infrastructure."
        ),
        license="CC-BY-SA-4.0",
        format="Splunk index (exported as compressed tgz/csv)",
        threat_types=["T1", "T3", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "splunk_bots_v3": DataSourceCatalog(
        name="Splunk BOTS v3 (Boss of the SOC)",
        url="https://github.com/splunk/botsv3",
        description=(
            "Third BOTS dataset with realistic multi-stage attack data "
            "spanning cloud, endpoint, and network telemetry including "
            "Office 365 and AWS CloudTrail logs."
        ),
        license="CC-BY-SA-4.0",
        format="Splunk index (exported as compressed tgz/csv)",
        threat_types=["T2", "T3", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "splunk_attack_data": DataSourceCatalog(
        name="Splunk Attack Data",
        url="https://github.com/splunk/attack_data",
        description=(
            "Repository of attack simulation datasets produced by the Splunk "
            "Threat Research Team.  Each dataset is tagged with MITRE ATT&CK "
            "technique IDs and comes as raw log files suitable for replay."
        ),
        license="Apache-2.0",
        format="JSON/raw log files",
        threat_types=["T1", "T2", "T3", "T4", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "splunk_security_content": DataSourceCatalog(
        name="Splunk Security Content",
        url="https://github.com/splunk/security_content",
        description=(
            "Curated repository of Splunk detection analytics (SPL searches), "
            "stories, and response playbooks mapped to MITRE ATT&CK.  Useful "
            "for generating ground-truth detection labels and expected "
            "analyst workflows."
        ),
        license="Apache-2.0",
        format="YAML/TOML detection rules + SPL",
        threat_types=["T1", "T2", "T3", "T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=True,
    ),

    # =======================================================================
    # MITRE Ecosystem
    # =======================================================================
    "mitre_attack_stix": DataSourceCatalog(
        name="MITRE ATT&CK STIX v14+",
        url="https://github.com/mitre-attack/attack-stix-data",
        description=(
            "Official STIX 2.1 representation of the MITRE ATT&CK knowledge "
            "base (Enterprise, Mobile, ICS).  Used in ARES to define K* "
            "knowledge requirements for each threat scenario."
        ),
        license="Apache-2.0",
        format="STIX 2.1 JSON bundles",
        threat_types=["T1", "T2", "T3", "T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=True,
        integrated=True,
    ),
    "mitre_caldera": DataSourceCatalog(
        name="MITRE CALDERA Adversary Emulation Logs",
        url="https://github.com/mitre/caldera",
        description=(
            "Automated adversary-emulation platform.  CALDERA operation logs "
            "capture sequences of ATT&CK techniques executed against target "
            "hosts, providing realistic multi-step attack telemetry."
        ),
        license="Apache-2.0",
        format="JSON operation reports + raw agent logs",
        threat_types=["T1", "T3", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "atomic_red_team": DataSourceCatalog(
        name="Atomic Red Team Execution Logs",
        url="https://github.com/redcanaryco/atomic-red-team",
        description=(
            "Library of small, portable tests mapped one-to-one to MITRE "
            "ATT&CK techniques.  Execution logs from Invoke-AtomicRedTeam "
            "provide per-technique ground-truth telemetry for Windows, Linux, "
            "and macOS."
        ),
        license="MIT",
        format="YAML test definitions + execution log output (JSON/CSV)",
        threat_types=["T1", "T2", "T3", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "mitre_engenuity_evaluations": DataSourceCatalog(
        name="MITRE Engenuity ATT&CK Evaluations",
        url="https://attackevals.mitre-engenuity.org/",
        description=(
            "Published results from MITRE Engenuity's ATT&CK Evaluations of "
            "commercial EDR/XDR products.  Includes step-by-step detection "
            "results for emulated APT campaigns (APT3, APT29, Carbanak/FIN7, "
            "Wizard Spider/Sandworm, Turla)."
        ),
        license="Publicly available (no explicit OSS license)",
        format="JSON evaluation results + HTML reports",
        threat_types=["T1", "T5"],
        ares_component="scenario_engine",
        actively_maintained=True,
    ),

    # =======================================================================
    # Endpoint / SIEM Data
    # =======================================================================
    "otrf_security_datasets": DataSourceCatalog(
        name="OTRF Security Datasets (Mordor)",
        url="https://github.com/OTRF/Security-Datasets",
        description=(
            "Pre-recorded security event logs from adversary simulation "
            "exercises, organised by ATT&CK tactics.  Covers Windows "
            "Security, Sysmon, and AWS CloudTrail events.  Already used in "
            "ARES for endpoint-telemetry scenario generation."
        ),
        license="MIT",
        format="JSON (Elasticsearch-ingestible) / Jupyter notebooks",
        threat_types=["T1", "T2", "T3", "T5"],
        ares_component="scenario_engine",
        actively_maintained=True,
        integrated=True,
    ),
    "evtx_attack_samples": DataSourceCatalog(
        name="EVTX-ATTACK-SAMPLES",
        url="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        description=(
            "Collection of Windows Event Log (.evtx) files generated during "
            "red-team exercises, mapped to MITRE ATT&CK.  Provides realistic "
            "raw endpoint artefacts for detection engineering."
        ),
        license="Unlicense",
        format="Windows EVTX files",
        threat_types=["T1", "T3", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=False,
    ),
    "cert_insider_threat": DataSourceCatalog(
        name="CERT Insider Threat Dataset (CMU)",
        url="https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247",
        description=(
            "Synthetic but realistic insider-threat dataset from CMU/CERT "
            "containing logon, device, email, HTTP, and file-access events "
            "for ~1000 employees over 18 months with injected malicious "
            "insider scenarios."
        ),
        license="CC-BY-4.0",
        format="CSV (logon.csv, device.csv, email.csv, http.csv, file.csv)",
        threat_types=["T3"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "lanl_unified": DataSourceCatalog(
        name="LANL Unified Host and Network Dataset",
        url="https://csr.lanl.gov/data/2017/",
        description=(
            "58 consecutive days of de-identified host and network events "
            "from Los Alamos National Laboratory's enterprise network.  "
            "Includes authentication, process, DNS, and network-flow data "
            "with known red-team compromise events."
        ),
        license="Publicly available for research",
        format="CSV/TSV compressed files",
        threat_types=["T3", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "sigma_rules": DataSourceCatalog(
        name="Sigma Rules",
        url="https://github.com/SigmaHQ/sigma",
        description=(
            "Community-driven repository of generic SIEM detection rules in "
            "the Sigma format.  Rules are mapped to ATT&CK techniques and "
            "can be compiled to Splunk SPL, Elastic Query DSL, and other "
            "SIEM query languages."
        ),
        license="LGPL-2.1 (detection rules) / MIT (tooling)",
        format="YAML Sigma rules",
        threat_types=["T1", "T2", "T3", "T4", "T5"],
        ares_component="anomaly_monitor",
        actively_maintained=True,
    ),

    # =======================================================================
    # Network Traffic
    # =======================================================================
    "cicids2017": DataSourceCatalog(
        name="CICIDS2017",
        url="https://www.unb.ca/cic/datasets/ids-2017.html",
        description=(
            "Full pcap and extracted feature CSVs for benign traffic and "
            "common attack types (brute-force, DoS/DDoS, web attacks, "
            "infiltration, botnet, port-scan).  Already integrated as a "
            "network-traffic source in ARES."
        ),
        license="Publicly available for research",
        format="PCAP + CSV (CICFlowMeter features)",
        threat_types=["T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
        integrated=True,
    ),
    "unsw_nb15": DataSourceCatalog(
        name="UNSW-NB15",
        url="https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        description=(
            "Hybrid real-normal and synthetic-attack network dataset from "
            "UNSW Canberra.  Contains 49 features extracted from pcap data "
            "covering nine attack families.  Already used in ARES for "
            "network anomaly baseline."
        ),
        license="Publicly available for research",
        format="CSV / PCAP",
        threat_types=["T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
        integrated=True,
    ),
    "cse_cic_ids2018": DataSourceCatalog(
        name="CSE-CIC-IDS2018",
        url="https://www.unb.ca/cic/datasets/ids-2018.html",
        description=(
            "Collaborative project between CSE and CIC generating realistic "
            "network intrusion data.  Includes brute-force, heartbleed, "
            "botnet, DoS, DDoS, web-attack, and infiltration traffic "
            "profiles with labelled flows."
        ),
        license="Publicly available for research",
        format="PCAP + CSV (CICFlowMeter features)",
        threat_types=["T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "cic_ddos2019": DataSourceCatalog(
        name="CIC-DDoS2019",
        url="https://www.unb.ca/cic/datasets/ddos-2019.html",
        description=(
            "Dedicated DDoS evaluation dataset from CIC with reflection- "
            "and exploitation-based DDoS attack types including LDAP, MSSQL, "
            "NetBIOS, SNMP, DNS, NTP, TFTP, SYN, and UDP floods."
        ),
        license="Publicly available for research",
        format="PCAP + CSV (CICFlowMeter features)",
        threat_types=["T4"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),
    "ctu13_botnet": DataSourceCatalog(
        name="CTU-13 Botnet Dataset",
        url="https://www.stratosphereips.org/datasets-ctu13",
        description=(
            "Thirteen captures of real botnet traffic mixed with normal and "
            "background traffic from CTU University, Prague.  Each scenario "
            "uses a different malware sample (Neris, Rbot, Virut, NSIS, "
            "Murlo, Sogou)."
        ),
        license="Publicly available for research",
        format="PCAP + NetFlow (bidirectional)",
        threat_types=["T4", "T5"],
        ares_component="scenario_engine",
        actively_maintained=False,
    ),

    # =======================================================================
    # Threat Intelligence
    # =======================================================================
    "abusech_malwarebazaar": DataSourceCatalog(
        name="abuse.ch MalwareBazaar",
        url="https://bazaar.abuse.ch/",
        description=(
            "Community-driven malware sample sharing platform.  Provides "
            "downloadable samples, YARA rules, and rich metadata (tags, "
            "delivery method, MITRE ATT&CK mapping) via REST API."
        ),
        license="CC0-1.0",
        format="REST API (JSON) + downloadable samples (ZIP)",
        threat_types=["T1", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "abusech_urlhaus": DataSourceCatalog(
        name="abuse.ch URLhaus",
        url="https://urlhaus.abuse.ch/",
        description=(
            "Database of malware distribution URLs.  Tracks active and "
            "historical URLs used to distribute malware, with payload tags "
            "and hosting information."
        ),
        license="CC0-1.0",
        format="REST API (JSON) + CSV bulk exports",
        threat_types=["T1", "T2"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "abusech_threatfox": DataSourceCatalog(
        name="abuse.ch ThreatFox",
        url="https://threatfox.abuse.ch/",
        description=(
            "Platform for sharing indicators of compromise (IOCs) associated "
            "with malware families.  Covers hashes, URLs, domains, and IP "
            "addresses with MITRE ATT&CK tagging."
        ),
        license="CC0-1.0",
        format="REST API (JSON) + CSV bulk exports",
        threat_types=["T1", "T2", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "abusech_feodo_tracker": DataSourceCatalog(
        name="abuse.ch Feodo Tracker",
        url="https://feodotracker.abuse.ch/",
        description=(
            "Tracks command-and-control infrastructure for banking trojans "
            "and botnet families (Dridex, Emotet, TrickBot, QakBot).  "
            "Provides blocklists of active C2 servers."
        ),
        license="CC0-1.0",
        format="CSV blocklists + REST API (JSON)",
        threat_types=["T1", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "phishtank": DataSourceCatalog(
        name="PhishTank",
        url="https://phishtank.org/",
        description=(
            "Community-curated database of verified phishing URLs.  "
            "Provides a downloadable feed and API for real-time lookup of "
            "suspected phishing sites."
        ),
        license="CC-BY-SA-2.5 (data feed)",
        format="XML / CSV / JSON API",
        threat_types=["T2"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),
    "alienvault_otx": DataSourceCatalog(
        name="AlienVault OTX (Open Threat Exchange)",
        url="https://otx.alienvault.com/",
        description=(
            "Open threat-intelligence community platform.  Pulses contain "
            "curated IOC collections with context (CVEs, ATT&CK techniques, "
            "targeted industries) and are accessible via a free REST API."
        ),
        license="Free (API key required)",
        format="REST API (JSON) + STIX/TAXII",
        threat_types=["T1", "T2", "T3", "T4", "T5"],
        ares_component="mismatch_injector",
        actively_maintained=True,
    ),

    # =======================================================================
    # Malware Analysis
    # =======================================================================
    "ember": DataSourceCatalog(
        name="EMBER (Elastic Malware Benchmark for Empowering Researchers)",
        url="https://github.com/elastic/ember",
        description=(
            "Labelled feature dataset of 1.1 million PE files (2017 + 2018 "
            "corpora) extracted by the LIEF library.  Designed for training "
            "and benchmarking static malware classifiers."
        ),
        license="Elastic License 2.0",
        format="JSONL features + LightGBM baseline model",
        threat_types=["T1", "T5"],
        ares_component="agents",
        actively_maintained=True,
    ),
    "sorel_20m": DataSourceCatalog(
        name="SOREL-20M (Sophos/ReversingLabs 20 Million)",
        url="https://github.com/sophos/SOREL-20M",
        description=(
            "20 million PE sample metadata with features and labels jointly "
            "produced by Sophos AI and ReversingLabs.  Includes pre-trained "
            "LightGBM and PyTorch models for malware detection."
        ),
        license="Apache-2.0 (metadata + code); samples not redistributed",
        format="LMDB + JSONL features + pre-trained models",
        threat_types=["T1", "T5"],
        ares_component="agents",
        actively_maintained=False,
    ),
    "virusshare": DataSourceCatalog(
        name="VirusShare",
        url="https://virusshare.com/",
        description=(
            "Large-scale repository of malware samples (48M+ files).  "
            "Provides hash sets and downloadable sample archives.  Already "
            "used in ARES for malware-knowledge calibration."
        ),
        license="Restricted (registration required)",
        format="Downloadable sample ZIPs + MD5/SHA256 hash lists",
        threat_types=["T1", "T5"],
        ares_component="agents",
        actively_maintained=True,
        integrated=True,
    ),

    # =======================================================================
    # Cloud / Container
    # =======================================================================
    "stratus_red_team": DataSourceCatalog(
        name="Stratus Red Team (Datadog)",
        url="https://github.com/DataDog/stratus-red-team",
        description=(
            "Granular, actionable adversary-emulation tool for cloud "
            "environments (AWS, Azure, GCP, Kubernetes).  Attack techniques "
            "are mapped to MITRE ATT&CK and produce cloud-native audit "
            "trail logs (CloudTrail, Azure Activity, GCP Audit)."
        ),
        license="Apache-2.0",
        format="Go CLI tool + JSON CloudTrail/audit logs",
        threat_types=["T3", "T5"],
        ares_component="scenario_engine",
        actively_maintained=True,
    ),
    "falco_event_generator": DataSourceCatalog(
        name="Falco Event Generator",
        url="https://github.com/falcosecurity/event-generator",
        description=(
            "Generates sample suspicious activity inside Linux containers "
            "and Kubernetes pods to trigger Falco runtime-security rules.  "
            "Covers file-system tampering, shell spawning, sensitive mount "
            "access, and network anomalies."
        ),
        license="Apache-2.0",
        format="Go CLI tool + Falco JSON alert output",
        threat_types=["T3", "T5"],
        ares_component="anomaly_monitor",
        actively_maintained=True,
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def get_sources_for_threat_type(threat_type: str) -> List[DataSourceCatalog]:
    """Return all data sources relevant to a given threat type (e.g. 'T1').

    Parameters
    ----------
    threat_type:
        One of ``T1`` (Ransomware), ``T2`` (Phishing), ``T3`` (Insider
        Threat), ``T4`` (DDoS), or ``T5`` (APT Intrusion).
    """
    return [
        src
        for src in REALISTIC_DATA_SOURCES.values()
        if threat_type in src.threat_types
    ]


def get_sources_for_component(component: str) -> List[DataSourceCatalog]:
    """Return all data sources that feed a specific ARES component.

    Parameters
    ----------
    component:
        An ARES service name such as ``scenario_engine``,
        ``mismatch_injector``, ``agents``, ``anomaly_monitor``,
        ``dataset_writer``, or ``orchestrator``.
    """
    return [
        src
        for src in REALISTIC_DATA_SOURCES.values()
        if src.ares_component == component
    ]


def get_new_sources() -> List[DataSourceCatalog]:
    """Return data sources *not yet* integrated into ARES."""
    return [
        src
        for src in REALISTIC_DATA_SOURCES.values()
        if not src.integrated
    ]


def get_existing_sources() -> List[DataSourceCatalog]:
    """Return data sources already integrated into ARES."""
    return [
        src
        for src in REALISTIC_DATA_SOURCES.values()
        if src.integrated
    ]
