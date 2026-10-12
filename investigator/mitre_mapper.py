"""
Maps QRadar offense categories and descriptions to MITRE ATT&CK techniques.
"""

from typing import List

# Map QRadar offense category keywords → ATT&CK techniques
CATEGORY_MAPPING = [
    {
        "keywords": ["brute force", "multiple login fail", "authentication fail", "credential"],
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        ],
    },
    {
        "keywords": ["port scan", "network scan", "reconnaissance", "probing"],
        "techniques": [
            {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
            {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        ],
    },
    {
        "keywords": ["malware", "trojan", "ransomware", "virus", "backdoor", "rat"],
        "techniques": [
            {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        ],
    },
    {
        "keywords": ["exfiltration", "data transfer", "large upload", "dns tunnel"],
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        ],
    },
    {
        "keywords": ["privilege escalation", "escalation", "admin", "sudo", "elevation"],
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
        ],
    },
    {
        "keywords": ["lateral movement", "pass the hash", "pass the ticket", "wmi", "psexec", "smb"],
        "techniques": [
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
        ],
    },
    {
        "keywords": ["phishing", "spear phishing", "email", "attachment", "malicious link"],
        "techniques": [
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        ],
    },
    {
        "keywords": ["persistence", "registry", "scheduled task", "cron", "startup"],
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"},
        ],
    },
    {
        "keywords": ["command and control", "c2", "beacon", "c&c", "botnet"],
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
            {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
        ],
    },
    {
        "keywords": ["defense evasion", "log clear", "log deletion", "disable security"],
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
            {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
        ],
    },
]

RECOMMENDATIONS = {
    "T1110": "Block source IP. Enforce account lockout policy. Enable MFA.",
    "T1046": "Investigate scanning host. Check for unauthorized devices. Review firewall rules.",
    "T1566": "Quarantine affected mailboxes. Block sender domain. User awareness training.",
    "T1041": "Block destination IP/domain. Analyze network flows. Inspect endpoint.",
    "T1068": "Patch vulnerable software. Review privilege assignments. Enable EDR alerting.",
    "T1021": "Restrict lateral movement paths. Enforce least privilege. Monitor SMB/WMI.",
    "T1547": "Review autostart entries. Run full AV scan. Check registry run keys.",
    "T1071": "Block C2 domains/IPs. Inspect process network connections. Isolate host.",
    "default": "Investigate source and destination hosts. Preserve evidence. Escalate to Tier 2.",
}


def map_to_mitre(offense: dict) -> List[dict]:
    """Return a deduplicated list of MITRE ATT&CK technique dicts for this offense."""
    text = (
        (offense.get("description") or "") + " " +
        (offense.get("offense_type_str") or "") + " " +
        (offense.get("category") or "")
    ).lower()

    seen_ids = set()
    techniques = []
    for mapping in CATEGORY_MAPPING:
        if any(kw in text for kw in mapping["keywords"]):
            for t in mapping["techniques"]:
                if t["id"] not in seen_ids:
                    techniques.append(t)
                    seen_ids.add(t["id"])
    return techniques


def get_recommendation(techniques: List[dict]) -> str:
    for t in techniques:
        rec = RECOMMENDATIONS.get(t["id"])
        if rec:
            return rec
    return RECOMMENDATIONS["default"]
