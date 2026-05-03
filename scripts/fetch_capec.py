#!/usr/bin/env python3
"""
Build a CAPEC → ATT&CK technique mapping from the MITRE CAPEC STIX bundle.
Output: data/capec_attack_map.json  (dict: {"CAPEC-1": ["T1234", ...], ...})
This is a helper mapping used by build_index.py — not a data source of its own.
"""

import json
import re
import urllib.request
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "capec_attack_map.json"
CAPEC_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def fetch_capec_stix() -> dict:
    print(f"Downloading CAPEC STIX bundle from {CAPEC_STIX_URL} ...")
    req = urllib.request.Request(CAPEC_STIX_URL, headers={"User-Agent": "threatbase/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def build_mapping(bundle: dict) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        capec_id = None
        attack_ids = []

        for ref in obj.get("external_references", []):
            source = ref.get("source_name", "")
            ext_id = ref.get("external_id", "")

            if source == "capec" and ext_id:
                capec_id = f"CAPEC-{ext_id}" if not ext_id.startswith("CAPEC-") else ext_id

            if source in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack", "ATTACK"):
                if ATTACK_ID_RE.match(ext_id):
                    attack_ids.append(ext_id)

        if capec_id and attack_ids:
            mapping[capec_id] = sorted(set(attack_ids))

    return mapping


def main():
    try:
        bundle = fetch_capec_stix()
        mapping = build_mapping(bundle)
        print(f"Built CAPEC→ATT&CK mapping: {len(mapping)} CAPEC entries with ATT&CK links")
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(mapping, indent=2))
        print(f"Wrote {OUTPUT}")
    except Exception as exc:
        import traceback
        print(f"ERROR fetching CAPEC: {exc}")
        traceback.print_exc()
        if not OUTPUT.exists():
            OUTPUT.write_text("{}")


if __name__ == "__main__":
    main()
