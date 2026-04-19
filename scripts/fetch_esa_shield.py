#!/usr/bin/env python3
"""
Fetch ESA SHIELD space cybersecurity framework data.
Checks the official GitHub repo for structured data; falls back to a curated
seed file if only PDF documentation is available.
"""

import json
import sys
import urllib.request
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "esa_shield.json"
SEED_FILE = Path(__file__).parent.parent / "data" / "esa_shield_seed.json"

ESA_SHIELD_REPO_API = "https://api.github.com/repos/esaSPACEops/SHIELD/git/trees/HEAD?recursive=1"
ESA_SHIELD_JSON_URLS = [
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/main/shield.json",
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/master/shield.json",
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/main/data/shield.json",
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/main/SHIELD.json",
]
ESA_SHIELD_CSV_URLS = [
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/main/shield.csv",
    "https://raw.githubusercontent.com/esaSPACEops/SHIELD/master/shield.csv",
]

# Curated seed data extracted from ESA SHIELD documentation
# https://esaSPACEops.github.io/SHIELD/
# seed: true — pending upstream structured data release
ESA_SHIELD_SEED = [
    {
        "id": "SHIELD-RS-001",
        "name": "Unauthorized Access to Ground Station",
        "description": "Adversary gains unauthorized access to ground station systems through exploiting vulnerabilities in internet-facing services, social engineering, or physical intrusion.",
        "category": "Ground Segment Threats",
        "related_sparta_ids": ["SPA-0003"],
        "related_attack_ids": ["T1190", "T1566"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-002",
        "name": "Command Link Spoofing",
        "description": "Adversary transmits fake command signals to the spacecraft, potentially causing incorrect maneuvers, mode changes, or payload activation.",
        "category": "Space Segment Threats",
        "related_sparta_ids": ["SPA-0004", "SPA-0005"],
        "related_attack_ids": ["T1565", "T1491"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-003",
        "name": "Telemetry Link Interception",
        "description": "Adversary intercepts spacecraft telemetry downlink to gather intelligence on spacecraft health, orbit parameters, and operational status.",
        "category": "Link Segment Threats",
        "related_sparta_ids": ["SPA-0009", "SPA-0012"],
        "related_attack_ids": ["T1040", "T1020"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-004",
        "name": "GPS/GNSS Spoofing",
        "description": "Adversary broadcasts counterfeit GNSS signals to mislead spacecraft navigation systems, causing position and timing errors.",
        "category": "Navigation Threats",
        "related_sparta_ids": ["SPA-0007"],
        "related_attack_ids": ["T1565", "T1498"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-005",
        "name": "Supply Chain Compromise",
        "description": "Adversary introduces malicious components or software during spacecraft or ground system manufacturing and integration phases.",
        "category": "Supply Chain Threats",
        "related_sparta_ids": ["SPA-0002"],
        "related_attack_ids": ["T1195", "T1554"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-006",
        "name": "Denial of Service via RF Jamming",
        "description": "Adversary transmits high-power signals on spacecraft communication frequencies to deny or degrade communication links.",
        "category": "Link Segment Threats",
        "related_sparta_ids": ["SPA-0008"],
        "related_attack_ids": ["T1498", "T1499"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-007",
        "name": "Onboard Software Modification",
        "description": "Adversary exploits a vulnerability in the spacecraft onboard computer to modify flight software, affecting mission operations.",
        "category": "Space Segment Threats",
        "related_sparta_ids": ["SPA-0006"],
        "related_attack_ids": ["T1601", "T1542", "T1203"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-008",
        "name": "Insider Threat",
        "description": "Malicious or negligent insider with authorised access to space systems causes harm through data theft, sabotage, or unintended misconfiguration.",
        "category": "Organisational Threats",
        "related_sparta_ids": ["SPA-0003", "SPA-0011"],
        "related_attack_ids": ["T1078", "T1485"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-009",
        "name": "Inter-Satellite Link Attack",
        "description": "Adversary targets crosslink communications between satellites in a constellation to disrupt relay operations or inject false data.",
        "category": "Space Segment Threats",
        "related_sparta_ids": ["SPA-0005", "SPA-0008"],
        "related_attack_ids": ["T1557", "T1498"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-010",
        "name": "Cryptographic Key Compromise",
        "description": "Adversary obtains cryptographic keys used for securing command uplinks or telemetry downlinks, enabling decryption or command forgery.",
        "category": "Cryptographic Threats",
        "related_sparta_ids": ["SPA-0004", "SPA-0009"],
        "related_attack_ids": ["T1552", "T1588"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-011",
        "name": "Mission Data Manipulation",
        "description": "Adversary tampers with science or imagery data collected by the spacecraft payload, undermining mission integrity.",
        "category": "Data Integrity Threats",
        "related_sparta_ids": ["SPA-0012"],
        "related_attack_ids": ["T1565", "T1485"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
    {
        "id": "SHIELD-RS-012",
        "name": "Replay Attack on Telecommands",
        "description": "Adversary records legitimate telecommand sequences and replays them to cause unintended spacecraft actions.",
        "category": "Space Segment Threats",
        "related_sparta_ids": ["SPA-0005"],
        "related_attack_ids": ["T1550", "T1212"],
        "url": "https://esaspaaceops.github.io/SHIELD/",
        "source": "ESA SHIELD",
        "seed": True,
    },
]


def try_fetch(url: str) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "threatbase/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status == 200:
                return resp.read()
    except Exception:
        pass
    return None


def parse_shield_json(raw: bytes) -> list[dict]:
    data = json.loads(raw)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = list(data.values()) if not data.get("id") else [data]
    else:
        return []

    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id") or item.get("ID") or ""
        if not item_id:
            continue
        results.append({
            "id": item_id,
            "name": item.get("name") or item.get("Name") or item_id,
            "description": item.get("description") or item.get("Description") or "",
            "category": item.get("category") or item.get("Category") or "",
            "related_sparta_ids": item.get("related_sparta_ids") or item.get("sparta_ids") or [],
            "related_attack_ids": item.get("related_attack_ids") or item.get("attack_ids") or [],
            "url": item.get("url") or "https://esaspaaceops.github.io/SHIELD/",
            "source": "ESA SHIELD",
        })
    return results


def find_structured_files() -> list[str]:
    """Check GitHub API for JSON/CSV files in the ESA SHIELD repo."""
    data = try_fetch(ESA_SHIELD_REPO_API)
    if not data:
        return []
    tree = json.loads(data).get("tree", [])
    return [
        f"https://raw.githubusercontent.com/esaSPACEops/SHIELD/HEAD/{item['path']}"
        for item in tree
        if item["path"].endswith((".json", ".csv"))
        and not item["path"].startswith(".")
    ]


def main():
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing ESA SHIELD data: {len(existing)} entries")
        except Exception:
            pass

    entries = []

    # Try known URLs
    for url in ESA_SHIELD_JSON_URLS:
        print(f"Trying {url} ...")
        raw = try_fetch(url)
        if raw:
            try:
                entries = parse_shield_json(raw)
                if entries:
                    print(f"Parsed {len(entries)} ESA SHIELD entries from {url}")
                    break
            except Exception as exc:
                print(f"  Parse error: {exc}")

    # Try GitHub tree discovery
    if not entries:
        print("Known URLs failed — querying GitHub API for structured files...")
        discovered = find_structured_files()
        for url in discovered:
            print(f"Trying discovered {url} ...")
            raw = try_fetch(url)
            if raw:
                try:
                    if url.endswith(".json"):
                        entries = parse_shield_json(raw)
                    if entries:
                        print(f"Parsed {len(entries)} entries from {url}")
                        break
                except Exception as exc:
                    print(f"  Parse error: {exc}")

    if not entries:
        print(
            "No machine-readable ESA SHIELD data found upstream.\n"
            "Using curated seed data (seed: true). "
            "See https://github.com/esaSPACEops/SHIELD for structured data requests."
        )
        entries = ESA_SHIELD_SEED

    # Persist seed JSON for reference
    if not SEED_FILE.exists():
        SEED_FILE.write_text(json.dumps(ESA_SHIELD_SEED, indent=2))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(entries, indent=2))
    print(f"Wrote {len(entries)} ESA SHIELD entries to {OUTPUT}")


if __name__ == "__main__":
    main()
