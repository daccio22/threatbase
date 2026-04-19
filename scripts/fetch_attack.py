#!/usr/bin/env python3
"""Fetch MITRE ATT&CK enterprise techniques from STIX bundle."""

import json
import sys
import urllib.request
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "attack.json"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


def fetch_stix_bundle():
    print(f"Downloading ATT&CK STIX bundle from {STIX_URL} ...")
    req = urllib.request.Request(STIX_URL, headers={"User-Agent": "threatbase/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def extract_external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def parse_techniques(bundle):
    objects = bundle.get("objects", [])

    # Build tactic phase name -> tactic ID map from x-mitre-tactic objects
    tactic_shortname_map = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            ext_id, _ = extract_external_id(obj)
            tactic_shortname_map[shortname] = TACTIC_NAMES.get(ext_id or "", shortname)

    # Build relationship map: source_ref -> list of target_refs (for mitigations)
    mitigation_map = {}  # technique_id -> list of mitigation names
    mitigation_objects = {o["id"]: o for o in objects if o.get("type") == "course-of-action"}
    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        if rel.get("relationship_type") == "mitigates":
            src = rel.get("source_ref", "")
            tgt = rel.get("target_ref", "")
            if src in mitigation_objects:
                mitigation_map.setdefault(tgt, []).append(
                    mitigation_objects[src].get("name", "")
                )

    techniques = {}
    subtechniques = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        tech_id, url = extract_external_id(obj)
        if not tech_id:
            continue

        tactics = [
            tactic_shortname_map.get(kc["phase_name"], kc["phase_name"])
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]

        entry = {
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", ""),
            "mitigations": mitigation_map.get(obj["id"], []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "url": url or f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
            "subtechniques": [],
            "source": "ATT&CK",
            "stix_id": obj["id"],
        }

        if "." in tech_id:
            subtechniques[tech_id] = entry
        else:
            techniques[tech_id] = entry

    # Link subtechniques to parents
    for sub_id, sub in subtechniques.items():
        parent_id = sub_id.split(".")[0]
        if parent_id in techniques:
            techniques[parent_id]["subtechniques"].append(
                {"id": sub_id, "name": sub["name"], "url": sub["url"]}
            )

    # Combine: parent techniques + standalone sub-techniques (also searchable)
    result = list(techniques.values()) + list(subtechniques.values())
    # Remove stix_id from final output
    for entry in result:
        entry.pop("stix_id", None)

    return result


def main():
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing data: {len(existing)} entries")
        except Exception:
            pass

    try:
        bundle = fetch_stix_bundle()
        techniques = parse_techniques(bundle)
        print(f"Parsed {len(techniques)} ATT&CK techniques/sub-techniques")
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(techniques, indent=2))
        print(f"Wrote {OUTPUT}")
    except Exception as exc:
        print(f"ERROR fetching ATT&CK: {exc}", file=sys.stderr)
        if existing:
            print("Falling back to existing data.")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text("[]")
        sys.exit(0)


if __name__ == "__main__":
    main()
