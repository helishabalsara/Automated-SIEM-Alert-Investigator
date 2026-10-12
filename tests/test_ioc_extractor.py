import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from investigator.ioc_extractor import extract_iocs


def test_extracts_public_ip():
    offense = {"offense_source": "203.0.113.42", "description": "Login from 203.0.113.42", "_resolved_source_ips": ["203.0.113.42"]}
    iocs = extract_iocs(offense, [])
    assert "203.0.113.42" in iocs["ips"]


def test_filters_private_ip():
    offense = {"offense_source": "192.168.1.1", "description": "Internal scan", "_resolved_source_ips": []}
    iocs = extract_iocs(offense, [{"sourceip": "192.168.1.1", "destinationip": "10.0.0.1", "username": "", "payload": ""}])
    assert "192.168.1.1" not in iocs["ips"]
    assert "10.0.0.1" not in iocs["ips"]


def test_extracts_hash_from_event():
    offense = {"offense_source": "", "description": "", "_resolved_source_ips": []}
    payload = "File hash: d41d8cd98f00b204e9800998ecf8427e detected"
    iocs = extract_iocs(offense, [{"sourceip": "", "destinationip": "", "username": "", "payload": payload}])
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]


def test_no_iocs_when_clean():
    offense = {"offense_source": "", "description": "Clean event", "_resolved_source_ips": []}
    iocs = extract_iocs(offense, [])
    assert iocs["ips"] == []


if __name__ == "__main__":
    test_extracts_public_ip()
    test_filters_private_ip()
    test_extracts_hash_from_event()
    test_no_iocs_when_clean()
    print("All tests passed.")
