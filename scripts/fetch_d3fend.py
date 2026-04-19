#!/usr/bin/env python3
"""Fetch MITRE D3FEND ontology and extract defensive techniques."""

import json
import sys
import urllib.request
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "d3fend.json"
D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"


def fetch_d3fend():
    print(f"Downloading D3FEND full ontology from {D3FEND_URL} ...")
    req = urllib.request.Request(D3FEND_URL, headers={"User-Agent": "threatbase/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def parse_d3fend(data):
    """Parse the D3FEND JSON — structure varies by API version, handle both."""
    techniques = []

    # The full.json is a JSON-LD document; bindings are under results.bindings
    # or it may be a flat object with offensive/defensive mappings
    # Try multiple structures
    entries_raw = []

    if isinstance(data, list):
        entries_raw = data
    elif "results" in data and "bindings" in data.get("results", {}):
        # SPARQL-style JSON
        bindings = data["results"]["bindings"]
        seen = set()
        for b in bindings:
            d3id = _val(b, "d3f_id") or _val(b, "id") or _val(b, "technique_id")
            if not d3id or d3id in seen:
                continue
            seen.add(d3id)
            entries_raw.append({
                "id": d3id,
                "name": _val(b, "name") or _val(b, "label") or d3id,
                "description": _val(b, "definition") or _val(b, "description") or "",
                "category": _val(b, "d3f_tactic") or _val(b, "category") or "",
                "attack_ids": [],
            })
    elif "@graph" in data:
        for node in data["@graph"]:
            if not isinstance(node, dict):
                continue
            node_id = node.get("@id", "")
            if not node_id.startswith("d3f:"):
                continue
            d3id = node_id.replace("d3f:", "D3-")
            entries_raw.append({
                "id": d3id,
                "name": node.get("rdfs:label", d3id),
                "description": _extract_str(node.get("d3f:definition", "")),
                "category": _extract_str(node.get("d3f:d3fend-category", "")),
                "attack_ids": _extract_attack_ids(node),
            })
    elif "d3fend-techniques" in data or "techniques" in data:
        raw = data.get("d3fend-techniques") or data.get("techniques") or {}
        if isinstance(raw, list):
            entries_raw = raw
        elif isinstance(raw, dict):
            entries_raw = list(raw.values())

    if not entries_raw:
        print("WARNING: Could not parse D3FEND structure, got keys:", list(data.keys())[:10])

    for e in entries_raw:
        if not isinstance(e, dict):
            continue
        d3id = e.get("id") or e.get("d3f_id") or ""
        if not d3id:
            continue
        name = e.get("name") or e.get("label") or d3id
        desc = e.get("description") or e.get("definition") or ""
        category = e.get("category") or e.get("d3f_tactic") or ""
        attack_ids = e.get("attack_ids") or e.get("attack_mappings") or e.get("counters_attack_ids") or []
        if isinstance(attack_ids, str):
            attack_ids = [a.strip() for a in attack_ids.split(",") if a.strip()]

        # Normalise D3- prefix
        if not d3id.startswith("D3-"):
            d3id = f"D3-{d3id}"

        techniques.append({
            "id": d3id,
            "name": name,
            "description": desc,
            "category": category,
            "counters_attack_ids": attack_ids,
            "url": f"https://d3fend.mitre.org/technique/{d3id}/",
            "source": "D3FEND",
        })

    return techniques


def _val(binding, key):
    return binding.get(key, {}).get("value") if isinstance(binding.get(key), dict) else binding.get(key)


def _extract_str(val):
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return val.get("@value", "") or val.get("value", "")
    return ""


def _extract_attack_ids(node):
    attacks = node.get("d3f:attack-id") or node.get("d3f:counters") or []
    if isinstance(attacks, str):
        return [attacks]
    if isinstance(attacks, dict):
        return [attacks.get("@value", "")]
    if isinstance(attacks, list):
        ids = []
        for a in attacks:
            if isinstance(a, str):
                ids.append(a)
            elif isinstance(a, dict):
                ids.append(a.get("@value") or a.get("@id", ""))
        return [i for i in ids if i]
    return []


def main():
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing data: {len(existing)} entries")
        except Exception:
            pass

    try:
        data = fetch_d3fend()
        techniques = parse_d3fend(data)
        print(f"Parsed {len(techniques)} D3FEND techniques")
        if len(techniques) == 0 and existing:
            print("No techniques parsed — keeping existing data.")
            sys.exit(0)
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(techniques, indent=2))
        print(f"Wrote {OUTPUT}")
    except Exception as exc:
        print(f"ERROR fetching D3FEND: {exc}", file=sys.stderr)
        if existing:
            print("Falling back to existing data.")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text("[]")
        sys.exit(0)


if __name__ == "__main__":
    main()
