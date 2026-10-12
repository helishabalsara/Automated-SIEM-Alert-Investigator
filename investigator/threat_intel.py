"""
IOC enrichment via VirusTotal, AbuseIPDB, and OTX AlienVault.
All API calls degrade gracefully — missing keys = empty enrichment.
"""

import logging
from typing import Dict, List

import requests

logger = logging.getLogger(__name__)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SIEM-Investigator/1.0"})
TIMEOUT = 10


def enrich_iocs(iocs: Dict[str, List[str]], config: dict) -> Dict[str, dict]:
    """
    Enrich all IOCs and return a flat dict keyed by IOC value.
    Each value has available enrichment fields merged.
    """
    results = {}
    vt_key = config.get("virustotal_api_key", "")
    abuse_key = config.get("abuseipdb_api_key", "")
    otx_key = config.get("otx_api_key", "")

    for ip in iocs.get("ips", []):
        enrichment = {}
        if abuse_key:
            enrichment.update(_abuseipdb(ip, abuse_key))
        if vt_key:
            enrichment.update(_virustotal_ip(ip, vt_key))
        if otx_key:
            enrichment.update(_otx_ip(ip, otx_key))
        results[ip] = enrichment

    for domain in iocs.get("domains", []):
        enrichment = {}
        if vt_key:
            enrichment.update(_virustotal_domain(domain, vt_key))
        if otx_key:
            enrichment.update(_otx_domain(domain, otx_key))
        results[domain] = enrichment

    for h in iocs.get("hashes", []):
        enrichment = {}
        if vt_key:
            enrichment.update(_virustotal_hash(h, vt_key))
        results[h] = enrichment

    return results


def _abuseipdb(ip: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuseipdb_score": data.get("abuseConfidenceScore", 0),
            "abuseipdb_total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "is_tor": data.get("isTor", False),
        }
    except Exception as e:
        logger.debug(f"AbuseIPDB failed for {ip}: {e}")
        return {}


def _virustotal_ip(ip: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "virustotal_malicious": stats.get("malicious", 0),
            "virustotal_suspicious": stats.get("suspicious", 0),
        }
    except Exception as e:
        logger.debug(f"VirusTotal IP failed for {ip}: {e}")
        return {}


def _virustotal_domain(domain: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "virustotal_malicious": stats.get("malicious", 0),
            "virustotal_suspicious": stats.get("suspicious", 0),
        }
    except Exception as e:
        logger.debug(f"VirusTotal domain failed for {domain}: {e}")
        return {}


def _virustotal_hash(h: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "virustotal_malicious": stats.get("malicious", 0),
            "file_name": attrs.get("meaningful_name", ""),
            "file_type": attrs.get("type_description", ""),
        }
    except Exception as e:
        logger.debug(f"VirusTotal hash failed for {h}: {e}")
        return {}


def _otx_ip(ip: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "otx_pulse_count": data.get("pulse_info", {}).get("count", 0),
            "otx_tags": data.get("pulse_info", {}).get("tags", [])[:5],
        }
    except Exception as e:
        logger.debug(f"OTX failed for {ip}: {e}")
        return {}


def _otx_domain(domain: str, key: str) -> dict:
    try:
        resp = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "otx_pulse_count": data.get("pulse_info", {}).get("count", 0),
        }
    except Exception as e:
        logger.debug(f"OTX domain failed for {domain}: {e}")
        return {}
