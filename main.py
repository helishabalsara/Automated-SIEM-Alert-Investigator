"""
Automated SIEM Alert Investigator
Entry point.
"""

import json
import logging
import os
import sys
import time

import click
import yaml
from rich.console import Console
from rich.table import Table

from investigator.qradar_client import QRadarClient
from investigator.ioc_extractor import extract_iocs
from investigator.threat_intel import enrich_iocs
from investigator.mitre_mapper import map_to_mitre, get_recommendation
from investigator.triage_card import build_triage_card, save_triage_card

console = Console()
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def load_config(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def load_mock_offenses() -> list:
    mock_path = os.path.join(os.path.dirname(__file__), "mock_data", "sample_offenses.json")
    with open(mock_path) as fh:
        return json.load(fh)


def process_offenses(offenses: list, client, cfg: dict, output_dir: str):
    cards = []
    for offense in offenses:
        offense_id = offense.get("id", 0)
        console.print(f"  Processing offense [cyan]#{offense_id}[/cyan]: {offense.get('description', '')[:60]}")

        # Resolve source IPs
        if client and offense.get("source_address_ids"):
            offense["_resolved_source_ips"] = client.get_source_addresses(
                offense["source_address_ids"]
            )
        else:
            offense["_resolved_source_ips"] = [offense.get("offense_source", "")]

        # Fetch events (skip for mock)
        events = []
        if client:
            events = client.get_offense_events(offense_id)

        iocs = extract_iocs(offense, events)
        enrichment = enrich_iocs(iocs, cfg.get("threat_intel", {}))
        techniques = map_to_mitre(offense)
        recommendation = get_recommendation(techniques)
        card = build_triage_card(offense, events, iocs, enrichment, techniques, recommendation)
        path = save_triage_card(card, output_dir)
        cards.append(card)
        console.print(f"    [green]✓[/green] Triage card saved: {path}")

    return cards


@click.command()
@click.option("--config", default="config.yaml", show_default=True, help="Config file.")
@click.option("--mock", is_flag=True, help="Use mock data instead of live QRadar.")
@click.option("--poll", is_flag=True, help="Run in continuous polling mode.")
@click.option("--interval", default=300, show_default=True, help="Polling interval in seconds.")
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(config, mock, poll, interval, verbose):
    """Automated SIEM Alert Investigator — QRadar offense triage bot."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(config)
    output_dir = cfg.get("output", {}).get("directory", "triage_cards/")

    client = None
    if not mock:
        qr_cfg = cfg["qradar"]
        if not qr_cfg.get("api_token") or qr_cfg["api_token"] == "YOUR_QRADAR_API_TOKEN":
            console.print("[red]QRadar API token not configured. Use --mock for demo mode.[/red]")
            sys.exit(1)
        client = QRadarClient(qr_cfg["host"], qr_cfg["api_token"], qr_cfg.get("verify_ssl", False))

    console.print("[bold cyan]Automated SIEM Alert Investigator[/bold cyan]")

    while True:
        console.print(f"\n[bold]Fetching offenses...[/bold]  ({_now()})")
        if mock:
            offenses = load_mock_offenses()
        else:
            offenses = client.get_offenses(
                limit=cfg["qradar"].get("offense_limit", 50),
                status=cfg["qradar"].get("status_filter", "OPEN"),
            )

        console.print(f"Found [yellow]{len(offenses)}[/yellow] offenses.")
        cards = process_offenses(offenses, client, cfg, output_dir)
        _print_summary(cards)

        if not poll:
            break
        console.print(f"\nNext poll in [dim]{interval}s[/dim]...")
        time.sleep(interval)


def _print_summary(cards):
    if not cards:
        return
    table = Table(title="Triage Summary", show_lines=True)
    table.add_column("Triage ID", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Description", max_width=45)
    table.add_column("IOCs", justify="center")
    table.add_column("MITRE", justify="center")

    for c in cards:
        total_iocs = sum(len(v) for v in c["iocs"].values())
        table.add_row(
            c["triage_id"],
            str(c["severity"]),
            c["offense_description"][:45],
            str(total_iocs),
            str(len(c["mitre_techniques"])),
        )
    console.print(table)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


if __name__ == "__main__":
    main()
