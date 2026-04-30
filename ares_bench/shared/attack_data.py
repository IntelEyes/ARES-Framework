"""
ARES-Bench MITRE ATT&CK TTP Data and Threat Scenarios.

Defines the 5 threat scenario classes with their required S*/K*/C*/y*
and associated MITRE ATT&CK techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .shared_models import TaskProfile, ThreatType


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique references
# ---------------------------------------------------------------------------
ATTACK_TECHNIQUES: Dict[str, str] = {
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1490": "Inhibit System Recovery",
    "T1059": "Command and Scripting Interpreter",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1078": "Valid Accounts",
    "T1071": "Application Layer Protocol",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1078.004": "Cloud Accounts",
    "T1530": "Data from Cloud Storage",
    "T1498": "Network Denial of Service",
    "T1498.001": "Direct Network Flood",
    "T1499": "Endpoint Denial of Service",
    "T1499.001": "OS Exhaustion Flood",
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1053": "Scheduled Task/Job",
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1055": "Process Injection",
    "T1105": "Ingress Tool Transfer",
    "T1083": "File and Directory Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1070": "Indicator Removal",
    "T1560": "Archive Collected Data",
    "T1041": "Exfiltration Over C2 Channel",
    "T1572": "Protocol Tunneling",
    "T1568": "Dynamic Resolution",
}


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------
@dataclass
class ThreatScenario:
    """Full threat scenario definition."""
    scenario_id: str
    threat_type: ThreatType
    name: str
    description: str
    attack_techniques: List[str]
    S_star: Set[str]  # Required skills/tools
    K_star: Set[str]  # Required knowledge
    C_star: Set[str]  # Required capabilities
    y_star: dict      # Ground-truth output
    difficulty: str   # low, medium, high
    variants: List[str] = field(default_factory=list)


THREAT_SCENARIOS: Dict[str, ThreatScenario] = {
    # -----------------------------------------------------------------------
    # T1 Ransomware (high K* demand)
    # -----------------------------------------------------------------------
    "T1-01": ThreatScenario(
        scenario_id="T1-01",
        threat_type=ThreatType.T1_RANSOMWARE,
        name="Enterprise Ransomware - LockBit Variant",
        description=(
            "Active ransomware incident with encrypted file shares, "
            "lateral movement via SMB, and ransom note deployment. "
            "Agent must identify TTP chain, assess blast radius, and "
            "recommend containment."
        ),
        attack_techniques=["T1486", "T1490", "T1059", "T1027"],
        S_star={
            "yara_scanning", "file_hash_analysis", "process_tree_analysis",
            "network_flow_analysis", "registry_analysis",
        },
        K_star={
            "ransomware_families", "lockbit_ttps", "encryption_indicators",
            "lateral_movement_patterns", "smb_exploitation",
            "shadow_copy_deletion", "c2_infrastructure",
            "ransomware_negotiation_protocols",
        },
        C_star={
            "edr_api", "siem_query", "sandbox_detonation",
            "network_isolation", "backup_verification",
        },
        y_star={
            "threat_type": "ransomware",
            "family": "lockbit",
            "severity": "critical",
            "techniques": ["T1486", "T1490", "T1059", "T1027"],
            "iocs": {
                "file_hashes": ["sha256_lockbit_payload"],
                "c2_domains": ["c2.lockbit.example"],
                "registry_keys": ["HKLM\\SOFTWARE\\LockBit"],
            },
            "affected_systems": ["file_server_01", "dc_01", "ws_012"],
            "containment": [
                "isolate_affected_hosts",
                "block_c2_domains",
                "disable_smb_lateral",
                "verify_backup_integrity",
            ],
        },
        difficulty="high",
        variants=["T1-01a", "T1-01b", "T1-01c"],
    ),
    "T1-02": ThreatScenario(
        scenario_id="T1-02",
        threat_type=ThreatType.T1_RANSOMWARE,
        name="Ransomware Pre-Encryption Detection",
        description=(
            "Early-stage ransomware activity before encryption begins. "
            "Agent must detect reconnaissance, credential harvesting, "
            "and staging behaviors."
        ),
        attack_techniques=["T1059", "T1003", "T1083", "T1105"],
        S_star={
            "process_tree_analysis", "credential_dump_detection",
            "file_staging_detection", "network_flow_analysis",
        },
        K_star={
            "ransomware_kill_chain", "credential_harvesting_tools",
            "pre_encryption_indicators", "staging_behaviors",
            "cobalt_strike_patterns", "powershell_obfuscation",
        },
        C_star={
            "edr_api", "siem_query", "ad_query",
            "network_isolation",
        },
        y_star={
            "threat_type": "ransomware_precursor",
            "stage": "pre_encryption",
            "severity": "high",
            "techniques": ["T1059", "T1003", "T1083", "T1105"],
            "iocs": {
                "suspicious_processes": ["powershell_encoded", "mimikatz"],
                "staging_paths": ["C:\\ProgramData\\temp"],
            },
            "containment": [
                "isolate_staging_host",
                "reset_compromised_credentials",
                "block_c2_callback",
            ],
        },
        difficulty="medium",
    ),

    # -----------------------------------------------------------------------
    # T2 Phishing (medium across all)
    # -----------------------------------------------------------------------
    "T2-01": ThreatScenario(
        scenario_id="T2-01",
        threat_type=ThreatType.T2_PHISHING,
        name="Spearphishing with Macro Payload",
        description=(
            "Targeted spearphishing email with malicious Office document. "
            "Agent must analyze email headers, URL reputation, attachment "
            "behavior, and determine scope of compromise."
        ),
        attack_techniques=["T1566.001", "T1059", "T1071"],
        S_star={
            "email_header_analysis", "url_reputation_check",
            "macro_analysis", "sandbox_detonation",
        },
        K_star={
            "phishing_indicators", "macro_obfuscation",
            "email_spoofing_techniques", "payload_delivery_methods",
            "social_engineering_patterns",
        },
        C_star={
            "email_gateway_api", "sandbox_detonation",
            "url_scanner", "threat_intel_feed",
        },
        y_star={
            "threat_type": "spearphishing",
            "vector": "email_attachment",
            "severity": "high",
            "techniques": ["T1566.001", "T1059", "T1071"],
            "iocs": {
                "sender": "spoofed@trusted-partner.example",
                "subject_pattern": "Invoice.*Q[0-9]",
                "attachment_hash": "sha256_macro_doc",
                "c2_url": "https://payload.example/stage2",
            },
            "affected_users": ["user_a@corp.example"],
            "containment": [
                "quarantine_email",
                "block_sender_domain",
                "scan_recipients_for_execution",
                "reset_affected_credentials",
            ],
        },
        difficulty="medium",
    ),
    "T2-02": ThreatScenario(
        scenario_id="T2-02",
        threat_type=ThreatType.T2_PHISHING,
        name="Business Email Compromise (BEC)",
        description=(
            "CEO impersonation BEC attack requesting wire transfer. "
            "Agent must detect social engineering, verify email authenticity, "
            "and assess financial risk."
        ),
        attack_techniques=["T1566.002", "T1078"],
        S_star={
            "email_header_analysis", "url_reputation_check",
            "writing_style_analysis", "domain_whois",
        },
        K_star={
            "bec_patterns", "ceo_fraud_indicators",
            "email_authentication_spf_dkim", "wire_fraud_procedures",
        },
        C_star={
            "email_gateway_api", "threat_intel_feed",
            "domain_lookup",
        },
        y_star={
            "threat_type": "bec",
            "vector": "email_impersonation",
            "severity": "high",
            "techniques": ["T1566.002", "T1078"],
            "iocs": {
                "sender": "ceo-lookalike@corq.example",
                "reply_to": "external@gmail.example",
            },
            "containment": [
                "block_sender",
                "alert_finance_department",
                "review_recent_wire_transfers",
            ],
        },
        difficulty="medium",
    ),

    # -----------------------------------------------------------------------
    # T3 Insider Threat (high C* demand - SIEM/UEBA/DLP)
    # -----------------------------------------------------------------------
    "T3-01": ThreatScenario(
        scenario_id="T3-01",
        threat_type=ThreatType.T3_INSIDER,
        name="Data Exfiltration by Insider",
        description=(
            "Departing employee systematically exfiltrating sensitive data "
            "via cloud storage and USB. Agent must correlate UEBA anomalies, "
            "DLP alerts, and access logs."
        ),
        attack_techniques=["T1078", "T1048", "T1530", "T1560"],
        S_star={
            "ueba_analysis", "dlp_alert_correlation",
            "access_log_analysis", "cloud_activity_monitoring",
        },
        K_star={
            "insider_threat_indicators", "data_exfiltration_patterns",
            "ueba_baseline_deviation", "dlp_policy_violations",
            "cloud_sharing_anomalies",
        },
        C_star={
            "siem_query", "ueba_api", "dlp_api",
            "cloud_casb_api", "hr_system_api",
            "endpoint_forensics",
        },
        y_star={
            "threat_type": "insider_threat",
            "subtype": "data_exfiltration",
            "severity": "high",
            "techniques": ["T1078", "T1048", "T1530", "T1560"],
            "actor": "employee_departing",
            "iocs": {
                "unusual_access": ["confidential_share_01", "ip_database"],
                "exfil_channels": ["personal_gdrive", "usb_device_03"],
                "volume": "2.3GB_over_5_days",
            },
            "containment": [
                "revoke_access_immediately",
                "preserve_forensic_evidence",
                "engage_hr_and_legal",
                "review_dlp_logs",
            ],
        },
        difficulty="high",
    ),
    "T3-02": ThreatScenario(
        scenario_id="T3-02",
        threat_type=ThreatType.T3_INSIDER,
        name="Privilege Abuse - Admin Account",
        description=(
            "System administrator abusing elevated privileges to access "
            "unauthorized systems and data. Agent must detect deviation "
            "from normal admin behavior patterns."
        ),
        attack_techniques=["T1078.004", "T1530", "T1070"],
        S_star={
            "ueba_analysis", "access_log_analysis",
            "privilege_usage_monitoring", "log_integrity_check",
        },
        K_star={
            "privilege_abuse_patterns", "admin_baseline_behavior",
            "log_tampering_indicators", "access_anomaly_detection",
        },
        C_star={
            "siem_query", "ueba_api", "ad_query",
            "log_management_api", "pam_api",
        },
        y_star={
            "threat_type": "insider_threat",
            "subtype": "privilege_abuse",
            "severity": "critical",
            "techniques": ["T1078.004", "T1530", "T1070"],
            "containment": [
                "suspend_admin_account",
                "audit_all_recent_admin_actions",
                "check_log_integrity",
                "enable_enhanced_monitoring",
            ],
        },
        difficulty="high",
    ),

    # -----------------------------------------------------------------------
    # T4 DDoS (high S* demand - traffic analysis)
    # -----------------------------------------------------------------------
    "T4-01": ThreatScenario(
        scenario_id="T4-01",
        threat_type=ThreatType.T4_DDOS,
        name="Volumetric DDoS - DNS Amplification",
        description=(
            "Large-scale DNS amplification DDoS attack targeting public-facing "
            "web infrastructure. Agent must analyze traffic patterns, identify "
            "amplification vectors, and coordinate mitigation."
        ),
        attack_techniques=["T1498", "T1498.001"],
        S_star={
            "traffic_analysis", "flow_analysis", "dns_analysis",
            "rate_limiting_config", "bgp_flowspec",
            "packet_capture_analysis",
        },
        K_star={
            "ddos_amplification_vectors", "dns_reflection_patterns",
            "traffic_baseline_deviation", "mitigation_techniques",
        },
        C_star={
            "netflow_api", "firewall_api",
            "cdn_api", "isp_blackhole_api",
        },
        y_star={
            "threat_type": "ddos",
            "subtype": "dns_amplification",
            "severity": "high",
            "techniques": ["T1498", "T1498.001"],
            "attack_profile": {
                "peak_bps": "45Gbps",
                "amplification_factor": 54,
                "source_count": 12000,
                "target": "web_frontend_vip",
            },
            "containment": [
                "enable_cdn_ddos_protection",
                "deploy_rate_limiting",
                "blackhole_amplification_sources",
                "coordinate_with_isp",
            ],
        },
        difficulty="medium",
    ),
    "T4-02": ThreatScenario(
        scenario_id="T4-02",
        threat_type=ThreatType.T4_DDOS,
        name="Application-Layer DDoS - HTTP Flood",
        description=(
            "Sophisticated application-layer DDoS targeting login and API "
            "endpoints. Agent must distinguish attack traffic from legitimate "
            "users and implement surgical mitigation."
        ),
        attack_techniques=["T1499", "T1499.001"],
        S_star={
            "traffic_analysis", "http_log_analysis",
            "bot_detection", "rate_limiting_config",
            "waf_rule_creation",
        },
        K_star={
            "application_ddos_patterns", "bot_fingerprinting",
            "http_flood_signatures", "legitimate_traffic_baseline",
        },
        C_star={
            "waf_api", "load_balancer_api",
            "cdn_api", "siem_query",
        },
        y_star={
            "threat_type": "ddos",
            "subtype": "http_flood",
            "severity": "high",
            "techniques": ["T1499", "T1499.001"],
            "containment": [
                "deploy_waf_rules",
                "enable_bot_challenge",
                "rate_limit_endpoints",
                "scale_backend_capacity",
            ],
        },
        difficulty="high",
    ),

    # -----------------------------------------------------------------------
    # T5 APT Intrusion (high across all)
    # -----------------------------------------------------------------------
    "T5-01": ThreatScenario(
        scenario_id="T5-01",
        threat_type=ThreatType.T5_APT,
        name="APT - Multi-Stage Intrusion",
        description=(
            "Advanced persistent threat with initial access via exploited "
            "web application, followed by credential dumping, lateral "
            "movement, persistence establishment, and staged exfiltration "
            "over encrypted C2 channel."
        ),
        attack_techniques=[
            "T1190", "T1059", "T1003", "T1021", "T1053",
            "T1055", "T1041", "T1572", "T1568",
        ],
        S_star={
            "network_flow_analysis", "process_tree_analysis",
            "memory_forensics", "log_correlation",
            "malware_reverse_engineering", "credential_dump_detection",
            "c2_beacon_detection",
        },
        K_star={
            "apt_ttps", "advanced_persistence_mechanisms",
            "living_off_the_land_techniques", "c2_frameworks",
            "lateral_movement_patterns", "credential_harvesting_tools",
            "data_staging_techniques", "protocol_tunneling",
            "dga_patterns", "anti_forensics",
        },
        C_star={
            "edr_api", "siem_query", "sandbox_detonation",
            "network_isolation", "threat_intel_feed",
            "memory_acquisition", "ad_query",
        },
        y_star={
            "threat_type": "apt",
            "severity": "critical",
            "techniques": [
                "T1190", "T1059", "T1003", "T1021", "T1053",
                "T1055", "T1041", "T1572", "T1568",
            ],
            "kill_chain_stage": "actions_on_objectives",
            "iocs": {
                "c2_beacons": ["beacon.apt.example:443"],
                "implants": ["svchost_modified.dll"],
                "persistence": ["scheduled_task_update_check"],
                "exfil_channel": "dns_tunneling",
            },
            "affected_systems": [
                "web_server_01", "dc_01", "db_server_01",
                "ws_005", "ws_011", "ws_023",
            ],
            "containment": [
                "isolate_all_affected_hosts",
                "block_c2_infrastructure",
                "reset_all_domain_credentials",
                "rebuild_compromised_systems",
                "engage_ir_retainer",
                "preserve_forensic_images",
            ],
        },
        difficulty="high",
    ),
    "T5-02": ThreatScenario(
        scenario_id="T5-02",
        threat_type=ThreatType.T5_APT,
        name="APT - Supply Chain Compromise",
        description=(
            "Threat actor compromises a software vendor's update mechanism "
            "to distribute backdoored updates. Agent must detect anomalous "
            "update behavior and assess blast radius."
        ),
        attack_techniques=["T1195", "T1059", "T1105", "T1071", "T1041"],
        S_star={
            "binary_analysis", "network_flow_analysis",
            "process_tree_analysis", "code_signing_verification",
            "supply_chain_audit",
        },
        K_star={
            "supply_chain_attack_patterns", "software_signing",
            "update_mechanism_abuse", "backdoor_indicators",
            "vendor_compromise_ttps", "code_integrity_verification",
        },
        C_star={
            "edr_api", "siem_query", "sandbox_detonation",
            "threat_intel_feed", "software_inventory_api",
            "network_isolation",
        },
        y_star={
            "threat_type": "apt",
            "subtype": "supply_chain",
            "severity": "critical",
            "techniques": ["T1195", "T1059", "T1105", "T1071", "T1041"],
            "containment": [
                "block_vendor_update_channel",
                "isolate_systems_with_backdoored_version",
                "rollback_to_known_good_version",
                "notify_vendor",
                "scan_all_endpoints_for_iocs",
            ],
        },
        difficulty="high",
    ),
}

# Add T1195 to the technique dictionary if missing
ATTACK_TECHNIQUES["T1195"] = "Supply Chain Compromise"


def get_scenario(scenario_id: str) -> ThreatScenario:
    """Get a threat scenario by ID."""
    if scenario_id not in THREAT_SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    return THREAT_SCENARIOS[scenario_id]


def get_required_capabilities(threat_type: str) -> dict:
    """Get aggregate required capabilities for a threat type."""
    all_S: set = set()
    all_K: set = set()
    all_C: set = set()
    for sid, scenario in THREAT_SCENARIOS.items():
        if scenario.threat_type.value == threat_type:
            all_S |= scenario.S_star
            all_K |= scenario.K_star
            all_C |= scenario.C_star
    return {"S_star": all_S, "K_star": all_K, "C_star": all_C}


def get_scenarios_for_type(threat_type: str) -> List[ThreatScenario]:
    """Get all scenarios for a given threat type."""
    return [s for s in THREAT_SCENARIOS.values()
            if s.threat_type.value == threat_type]


def build_task_profile(scenario: ThreatScenario) -> TaskProfile:
    """Convert a ThreatScenario into a TaskProfile for ARS computation."""
    return TaskProfile(
        scenario_id=scenario.scenario_id,
        threat_type=scenario.threat_type,
        S_star=set(scenario.S_star),
        K_star=set(scenario.K_star),
        C_star=set(scenario.C_star),
        y_star=dict(scenario.y_star),
    )
