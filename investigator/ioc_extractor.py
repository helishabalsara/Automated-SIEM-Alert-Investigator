"""
Extract IOCs (IPs, domains, file hashes) from QRadar offense data and raw events.
"""

import re
from typing import Dict, List, Set

# Regex patterns
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# IPs to exclude (RFC 1918, loopback, link-local)
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "169.254.", "0.")

KNOWN_SAFE_DOMAINS = {"amazonaws.com", "microsoft.com", "windows.com",
                      "google.com", "cloudflare.com"}


def extract_iocs(offense: dict, events: List[dict]) -> Dict[str, List[str]]:
    """Return deduplicated IOCs extracted from an offense + its events."""
    ips: Set[str] = set()
    domains: Set[str] = set()
    hashes: Set[str] = set()

    # From offense source addresses
    for ip in offense.get("_resolved_source_ips", []):
        if _is_public_ip(ip):
            ips.add(ip)

    # From raw events
    text_corpus = " ".join(_event_to_text(e) for e in events)
    text_corpus += f" {offense.get('offense_source', '')} {offense.get('description', '')}"

    for ip in RE_IPV4.findall(text_corpus):
        if _is_public_ip(ip):
            ips.add(ip)

    for domain in RE_DOMAIN.findall(text_corpus):
        domain = domain.lower().rstrip(".")
        if _is_valid_domain(domain):
            domains.add(domain)

    for h in RE_SHA256.findall(text_corpus):
        hashes.add(h.lower())
    for h in RE_SHA1.findall(text_corpus):
        if h.lower() not in hashes:
            hashes.add(h.lower())
    for h in RE_MD5.findall(text_corpus):
        if h.lower() not in hashes:
            hashes.add(h.lower())

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": sorted(hashes),
    }


def _event_to_text(event: dict) -> str:
    parts = [
        str(event.get("sourceip", "")),
        str(event.get("destinationip", "")),
        str(event.get("username", "")),
        str(event.get("payload", "")),
    ]
    return " ".join(parts)


def _is_public_ip(ip: str) -> bool:
    return ip and not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _is_valid_domain(domain: str) -> bool:
    if len(domain) < 4 or "." not in domain:
        return False
    tld = domain.split(".")[-1]
    if len(tld) < 2 or tld.isdigit():
        return False
    for safe in KNOWN_SAFE_DOMAINS:
        if domain.endswith(safe):
            return False
    return True
