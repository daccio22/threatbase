#!/usr/bin/env python3
"""Fetch MITRE SPARTA space-attack framework data."""

import json
import sys
import urllib.request
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "sparta.json"

# SPARTA GitHub repo raw URLs to check for structured data
SPARTA_JSON_URLS = [
    "https://raw.githubusercontent.com/mitre/SPARTA/main/sparta.json",
    "https://raw.githubusercontent.com/mitre/SPARTA/master/sparta.json",
    "https://raw.githubusercontent.com/mitre/SPARTA/main/data/sparta.json",
    "https://raw.githubusercontent.com/mitre/SPARTA/master/data/sparta.json",
]

SPARTA_CSV_URLS = [
    "https://raw.githubusercontent.com/mitre/SPARTA/main/sparta.csv",
    "https://raw.githubusercontent.com/mitre/SPARTA/master/sparta.csv",
    "https://raw.githubusercontent.com/mitre/SPARTA/main/data/sparta.csv",
]

# API index to find files
SPARTA_API_URL = "https://api.github.com/repos/mitre/SPARTA/git/trees/HEAD?recursive=1"


def try_fetch(url: str) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "threatbase/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status == 200:
                return resp.read()
    except Exception:
        pass
    return None


def find_sparta_files():
    """Query GitHub API to find JSON/CSV files in the SPARTA repo."""
    data = try_fetch(SPARTA_API_URL)
    if not data:
        return [], []
    tree = json.loads(data).get("tree", [])
    json_files = [
        f"https://raw.githubusercontent.com/mitre/SPARTA/HEAD/{item['path']}"
        for item in tree
        if item["path"].endswith(".json") and "sparta" in item["path"].lower()
    ]
    csv_files = [
        f"https://raw.githubusercontent.com/mitre/SPARTA/HEAD/{item['path']}"
        for item in tree
        if item["path"].endswith(".csv") and item["path"] != ".github"
    ]
    return json_files, csv_files


def parse_sparta_json(raw: bytes) -> list[dict]:
    data = json.loads(raw)
    entries = []

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("techniques") or data.get("entries") or list(data.values())
        if isinstance(items, dict):
            items = list(items.values())
    else:
        return []

    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id") or item.get("ID") or item.get("sparta_id") or ""
        if not item_id:
            continue
        entries.append(normalise(item_id, item))

    return entries


def parse_sparta_csv(raw: bytes) -> list[dict]:
    import csv
    import io
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
    entries = []
    for row in reader:
        item_id = (
            row.get("ID") or row.get("id") or row.get("Technique ID")
            or row.get("SPARTA ID") or ""
        ).strip()
        if not item_id:
            continue
        entries.append(normalise(item_id, row))
    return entries


def normalise(item_id: str, item: dict) -> dict:
    name = (
        item.get("name") or item.get("Name") or item.get("Technique Name")
        or item.get("Tactic Name") or item_id
    )
    description = (
        item.get("description") or item.get("Description")
        or item.get("Details") or ""
    )
    tactic = (
        item.get("tactic") or item.get("Tactic") or item.get("Category")
        or item.get("tactic_category") or ""
    )
    countermeasures_raw = (
        item.get("countermeasures") or item.get("Countermeasures")
        or item.get("mitigations") or []
    )
    if isinstance(countermeasures_raw, str):
        countermeasures = [c.strip() for c in countermeasures_raw.split(",") if c.strip()]
    elif isinstance(countermeasures_raw, list):
        countermeasures = countermeasures_raw
    else:
        countermeasures = []

    attack_ids_raw = (
        item.get("attack_ids") or item.get("ATT&CK IDs") or item.get("ATT&CK Mapping")
        or item.get("attack_mappings") or []
    )
    if isinstance(attack_ids_raw, str):
        attack_ids = [a.strip() for a in attack_ids_raw.split(",") if a.strip()]
    elif isinstance(attack_ids_raw, list):
        attack_ids = attack_ids_raw
    else:
        attack_ids = []

    return {
        "id": item_id,
        "name": name,
        "description": description,
        "tactic": tactic,
        "countermeasures": countermeasures,
        "attack_ids": attack_ids,
        "url": f"https://github.com/mitre/SPARTA",
        "source": "SPARTA",
    }


SPARTA_SEED = [
    {"id": "SPA-0001", "name": "Reconnaissance", "description": "Adversary gathers information about the target space system including orbital parameters, frequency bands, and ground station locations.", "tactic": "Reconnaissance", "countermeasures": ["RF Monitoring", "OPSEC"], "attack_ids": ["T1595", "T1592"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0002", "name": "Resource Development", "description": "Adversary establishes resources to support space operations targeting, including jamming equipment and cyber tools.", "tactic": "Resource Development", "countermeasures": ["Signal Authentication", "Encryption"], "attack_ids": ["T1583", "T1587"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0003", "name": "Initial Access - Ground Segment", "description": "Adversary gains access to ground control systems via phishing, vulnerable internet-facing services, or supply chain compromise.", "tactic": "Initial Access", "countermeasures": ["MFA", "Network Segmentation", "Patch Management"], "attack_ids": ["T1190", "T1566", "T1195"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0004", "name": "Initial Access - Space Segment", "description": "Adversary gains access to the space vehicle via malicious commands over RF link or compromised firmware.", "tactic": "Initial Access", "countermeasures": ["Command Authentication", "Encrypted Uplinks"], "attack_ids": ["T1190", "T1200"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0005", "name": "Execution - Command Injection", "description": "Adversary injects unauthorized commands into the spacecraft command queue.", "tactic": "Execution", "countermeasures": ["Command Validation", "Message Authentication Codes"], "attack_ids": ["T1059", "T1203"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0006", "name": "Persistence - Firmware Modification", "description": "Adversary modifies spacecraft firmware to maintain persistent access across power cycles.", "tactic": "Persistence", "countermeasures": ["Firmware Signing", "Secure Boot"], "attack_ids": ["T1542", "T1601"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0007", "name": "Defense Evasion - Safe Mode Trigger", "description": "Adversary intentionally triggers safe mode to disrupt operations or mask malicious activity.", "tactic": "Defense Evasion", "countermeasures": ["Anomaly Detection", "Fault Management Review"], "attack_ids": ["T1562"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0008", "name": "Denial of Service - Jamming", "description": "Adversary jams the uplink or downlink frequencies to deny communication with the spacecraft.", "tactic": "Impact", "countermeasures": ["Spread Spectrum", "Anti-Jam Receivers", "Frequency Hopping"], "attack_ids": ["T1498", "T1499"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0009", "name": "Exfiltration - Downlink Interception", "description": "Adversary intercepts unencrypted downlink data to collect telemetry, imagery, or sensitive payload data.", "tactic": "Exfiltration", "countermeasures": ["Downlink Encryption", "Data Classification"], "attack_ids": ["T1020", "T1030"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0010", "name": "Impact - Orbit Modification", "description": "Adversary sends unauthorized commands to alter spacecraft orbit, potentially causing collision or mission failure.", "tactic": "Impact", "countermeasures": ["Command Authentication", "Dual-Control Procedures"], "attack_ids": ["T1485", "T1489"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0011", "name": "Lateral Movement - Ground to Space", "description": "Adversary pivots from ground segment compromise to issue commands to the space segment.", "tactic": "Lateral Movement", "countermeasures": ["Network Segmentation", "Privileged Access Management"], "attack_ids": ["T1210", "T1021"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
    {"id": "SPA-0012", "name": "Collection - Telemetry Harvesting", "description": "Adversary collects spacecraft telemetry to understand system state, vulnerabilities, and operations schedule.", "tactic": "Collection", "countermeasures": ["Telemetry Encryption", "OPSEC"], "attack_ids": ["T1119", "T1005"], "url": "https://github.com/mitre/SPARTA", "source": "SPARTA"},
]


def main():
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing SPARTA data: {len(existing)} entries")
        except Exception:
            pass

    entries = []

    # Try known JSON URLs first
    for url in SPARTA_JSON_URLS:
        print(f"Trying {url} ...")
        raw = try_fetch(url)
        if raw:
            try:
                entries = parse_sparta_json(raw)
                if entries:
                    print(f"Parsed {len(entries)} SPARTA entries from JSON at {url}")
                    break
            except Exception as exc:
                print(f"  Parse error: {exc}")

    # Try CSV if JSON failed
    if not entries:
        print("JSON not found or empty, trying CSV files...")
        _, csv_urls = find_sparta_files()
        all_csv = SPARTA_CSV_URLS + [u for u in csv_urls if u not in SPARTA_CSV_URLS]
        for url in all_csv:
            print(f"Trying {url} ...")
            raw = try_fetch(url)
            if raw:
                try:
                    entries = parse_sparta_csv(raw)
                    if entries:
                        print(f"Parsed {len(entries)} SPARTA entries from CSV at {url}")
                        break
                except Exception as exc:
                    print(f"  Parse error: {exc}")

    if not entries:
        print("No machine-readable SPARTA data found — using seed data.")
        entries = SPARTA_SEED

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(entries, indent=2))
    print(f"Wrote {len(entries)} SPARTA entries to {OUTPUT}")


if __name__ == "__main__":
    main()
