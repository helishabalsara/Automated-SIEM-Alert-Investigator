"""
Build structured incident triage cards from offense + enrichment data.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List


def build_triage_card(
    offense: dict,
    events: List[dict],
    iocs: Dict[str, List[str]],
    enrichment: Dict[str, dict],
    techniques: List[dict],
    recommendation: str,
) -> dict:
    triage_id = f"TRG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{offense.get('id', 0):04d}"
    return {
        "triage_id": triage_id,
        "offense_id": offense.get("id"),
        "offense_description": offense.get("description", ""),
        "offense_type": offense.get("offense_type_str", ""),
        "severity": offense.get("severity", 0),
        "magnitude": offense.get("magnitude", 0),
        "status": offense.get("status", "OPEN"),
        "event_count": offense.get("event_count", len(events)),
        "start_time": _ms_to_iso(offense.get("start_time")),
        "last_updated": _ms_to_iso(offense.get("last_updated_time")),
        "source_ips": offense.get("_resolved_source_ips", []),
        "mitre_techniques": techniques,
        "iocs": iocs,
        "enrichment": enrichment,
        "recommendation": recommendation,
        "sample_events": events[:5],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def save_triage_card(card: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{card['triage_id']}.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w") as fh:
        json.dump(card, fh, indent=2, default=str)
    return path


def _ms_to_iso(ms_timestamp) -> str:
    if not ms_timestamp:
        return ""
    try:
        return datetime.fromtimestamp(int(ms_timestamp) / 1000, tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return str(ms_timestamp)
