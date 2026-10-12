# Automated SIEM Alert Investigator

An automated investigation bot that polls IBM QRadar offenses, enriches IOCs via threat intelligence APIs, maps adversary activity to MITRE ATT&CK, and produces structured incident triage cards.

## Features
- Poll IBM QRadar REST API for open offenses
- Extract IOCs (IPs, domains, hashes) from offense events
- Enrich IOCs via VirusTotal, AbuseIPDB, and OTX AlienVault
- Map offense categories to MITRE ATT&CK techniques
- Generate structured JSON triage cards per offense
- Continuous polling mode with configurable interval

## Architecture
```
IBM QRadar Offenses API
        │
  [ QRadar Client ]     ← fetch offenses + raw events
        │
  [ IOC Extractor ]     ← parse IPs, domains, file hashes
        │
  [ Threat Intel ]      ← enrich IOCs via VT / AbuseIPDB / OTX
        │
  [ MITRE Mapper ]      ← map offense categories → ATT&CK
        │
  [ Triage Card Gen ]   ← produce structured JSON triage cards
        │
  [ Output ]            ← JSON files / stdout
```

## Quick Start

### Install
```bash
pip install -r requirements.txt
```

### Configure
Edit `config.yaml` with your QRadar host and API token, plus any threat intel API keys.

### Run (single pass)
```bash
python main.py
```

### Run (continuous polling every 5 minutes)
```bash
python main.py --poll --interval 300
```

### Run against mock data (no real QRadar needed)
```bash
python main.py --mock
```

## Configuration
```yaml
qradar:
  host: https://your-qradar-host
  api_token: YOUR_QRADAR_API_TOKEN
  verify_ssl: false
  offense_limit: 50

threat_intel:
  virustotal_api_key: YOUR_VT_KEY       # optional
  abuseipdb_api_key: YOUR_ABUSEIPDB_KEY # optional
  otx_api_key: YOUR_OTX_KEY             # optional

output:
  directory: triage_cards/
  format: json
```

## Triage Card Output
```json
{
  "triage_id": "TRG-20241115-001",
  "offense_id": 42,
  "offense_description": "Multiple Login Failures Followed by Success",
  "severity": 8,
  "status": "open",
  "mitre_techniques": [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
  ],
  "iocs": {
    "ips": ["203.0.113.42"],
    "domains": [],
    "hashes": []
  },
  "enrichment": {
    "203.0.113.42": {
      "abuseipdb_score": 95,
      "virustotal_malicious": 12,
      "country": "CN"
    }
  },
  "recommendation": "Block source IP. Investigate compromised account. Reset credentials.",
  "generated_at": "2024-11-15T10:30:00Z"
}
```

## Project Structure
```
Automated-SIEM-Alert-Investigator/
├── main.py
├── requirements.txt
├── config.yaml
├── investigator/
│   ├── __init__.py
│   ├── qradar_client.py     # QRadar REST API client
│   ├── ioc_extractor.py     # Extract IOCs from offense events
│   ├── threat_intel.py      # VirusTotal / AbuseIPDB / OTX enrichment
│   ├── mitre_mapper.py      # Map offense categories to ATT&CK
│   └── triage_card.py       # Build structured triage cards
├── mock_data/
│   └── sample_offenses.json
└── tests/
    └── test_ioc_extractor.py
```
