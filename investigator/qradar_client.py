"""
IBM QRadar REST API client.
Fetches offenses and associated event payloads.
"""

import logging
from typing import List, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Version": "14.0",
}


class QRadarClient:
    def __init__(self, host: str, api_token: str, verify_ssl: bool = False):
        self.base_url = host.rstrip("/") + "/api"
        self.session = requests.Session()
        self.session.headers.update({**HEADERS, "SEC": api_token})
        self.session.verify = verify_ssl

    def _get(self, endpoint: str, params: dict = None) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        resp = self.session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_offenses(self, limit: int = 50, status: str = "OPEN") -> List[dict]:
        """Return a list of QRadar offenses."""
        params = {
            "filter": f"status={status}",
            "fields": "id,description,offense_type,offense_source,magnitude,severity,status,start_time,last_updated_time,category_count,event_count,source_address_ids,local_destination_address_ids",
            "range": f"0-{limit - 1}",
            "sort": "-magnitude",
        }
        try:
            return self._get("siem/offenses", params=params)
        except requests.RequestException as e:
            logger.error(f"Failed to fetch offenses: {e}")
            return []

    def get_offense_events(self, offense_id: int, max_events: int = 20) -> List[dict]:
        """Run an AQL query to retrieve raw events for an offense."""
        aql = (
            f"SELECT sourceip, destinationip, username, eventid, category, "
            f"qid, logsourceid, starttime, payload "
            f"FROM events WHERE INOFFENSE({offense_id}) LIMIT {max_events} LAST 24 HOURS"
        )
        try:
            search_resp = self.session.post(
                f"{self.base_url}/ariel/searches",
                json={"query_expression": aql},
            )
            search_resp.raise_for_status()
            search_id = search_resp.json()["search_id"]

            import time
            for _ in range(30):
                status_resp = self._get(f"ariel/searches/{search_id}")
                if status_resp.get("status") == "COMPLETED":
                    break
                time.sleep(1)

            results = self._get(f"ariel/searches/{search_id}/results")
            return results.get("events", [])
        except requests.RequestException as e:
            logger.warning(f"Could not fetch events for offense {offense_id}: {e}")
            return []

    def get_source_addresses(self, address_ids: List[int]) -> List[str]:
        """Resolve QRadar source address IDs to IP strings."""
        ips = []
        for addr_id in address_ids[:10]:
            try:
                data = self._get(f"siem/source_addresses/{addr_id}")
                ips.append(data.get("source_ip", ""))
            except requests.RequestException:
                pass
        return [ip for ip in ips if ip]
