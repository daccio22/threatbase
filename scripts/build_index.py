#!/usr/bin/env python3
"""
Merge all source JSON files into unified_index.json with cross-references.
Splits off CVEs into cves_index.json if unified_index.json would exceed 50 MB.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
LAST_RUN_FILE = DATA_DIR / "last_run.json"

SOURCE_FILES = {
    "ATT&CK": DATA_DIR / "attack.json",
    "D3FEND": DATA_DIR / "d3fend.json",
    "CVE": DATA_DIR / "cve.json",
    "CWE": DATA_DIR / "cwe.json",
    "SPARTA": DATA_DIR / "sparta.json",
    "ESA SHIELD": DATA_DIR / "esa_shield.json",
}

SIZE_LIMIT_BYTES = 50 * 1024 * 1024  # 50 MB


def load_source(path: Path, source_name: str) -> list[dict]:
    if not path.exists():
        print(f"  WARNING: {path} not found — skipping {source_name}")
        return []
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return data
        print(f"  WARNING: {path} is not a JSON array — skipping")
        return []
    except Exception as exc:
        print(f"  ERROR loading {path}: {exc}")
        return []


def build_id_index(entries: list[dict]) -> dict[str, dict]:
    """Build a fast lookup map from entry ID to entry."""
    return {e["id"]: e for e in entries if e.get("id")}


def add_cross_refs(entries: list[dict]) -> None:
    """
    Build bidirectional cross_refs for each entry by scanning
    known relationship fields across all entries.
    """
    id_map = build_id_index(entries)

    # forward_refs: entry_id -> set of referenced IDs
    forward: dict[str, set[str]] = {e["id"]: set() for e in entries if e.get("id")}

    def link(src_id: str, target_ids: list[str]) -> None:
        if src_id not in forward:
            return
        for tid in target_ids:
            if tid in id_map and tid != src_id:
                forward[src_id].add(tid)

    for entry in entries:
        eid = entry.get("id", "")
        src = entry.get("source", "")

        # CVE → CWE
        if src == "CVE":
            link(eid, entry.get("cwe_ids", []))

        # D3FEND → ATT&CK
        if src == "D3FEND":
            link(eid, entry.get("counters_attack_ids", []))

        # SPARTA → ATT&CK
        if src == "SPARTA":
            link(eid, entry.get("attack_ids", []))

        # ESA SHIELD → SPARTA and ATT&CK
        if src == "ESA SHIELD":
            link(eid, entry.get("related_sparta_ids", []))
            link(eid, entry.get("related_attack_ids", []))

        # ATT&CK sub-technique → parent
        if src == "ATT&CK" and "." in eid:
            parent = eid.split(".")[0]
            link(eid, [parent])

    # Build reverse map
    reverse: dict[str, set[str]] = {e["id"]: set() for e in entries if e.get("id")}
    for src_id, targets in forward.items():
        for tgt_id in targets:
            if tgt_id in reverse:
                reverse[tgt_id].add(src_id)

    # Assign cross_refs
    for entry in entries:
        eid = entry.get("id", "")
        if not eid:
            continue
        refs = (forward.get(eid, set()) | reverse.get(eid, set())) - {eid}
        entry["cross_refs"] = sorted(refs)


def add_tags(entry: dict) -> None:
    """Add a flat tags list for Fuse.js indexing."""
    tags = set()
    src = entry.get("source", "")

    if src == "ATT&CK":
        tags.update(entry.get("tactics", []))
        tags.update(entry.get("platforms", []))
    elif src == "D3FEND":
        if entry.get("category"):
            tags.add(entry["category"])
    elif src == "CVE":
        tags.update(entry.get("cwe_ids", []))
        sev = entry.get("cvss_severity", "")
        if sev:
            tags.add(sev.lower())
    elif src == "CWE":
        tags.update(entry.get("platforms", []))
    elif src == "SPARTA":
        if entry.get("tactic"):
            tags.add(entry["tactic"])
    elif src == "ESA SHIELD":
        if entry.get("category"):
            tags.add(entry["category"])

    entry["tags"] = sorted(t for t in tags if t)


def main():
    now = datetime.now(timezone.utc).isoformat()
    print(f"Building unified index at {now}")

    all_entries: list[dict] = []
    counts_by_source: dict[str, int] = {}
    last_run: dict = {}

    if LAST_RUN_FILE.exists():
        try:
            last_run = json.loads(LAST_RUN_FILE.read_text())
        except Exception:
            pass

    for source_name, path in SOURCE_FILES.items():
        entries = load_source(path, source_name)
        counts_by_source[source_name] = len(entries)
        last_run[source_name] = {
            "last_fetch": now,
            "count": len(entries),
            "error": None if entries else f"{path.name} missing or empty",
        }

        # Stamp last_updated
        for e in entries:
            e["last_updated"] = now
            add_tags(e)

        all_entries.extend(entries)
        print(f"  {source_name}: {len(entries):,} entries")

    print(f"Building cross-references for {len(all_entries):,} total entries...")
    add_cross_refs(all_entries)

    # Separate CVEs to manage file size
    cve_entries = [e for e in all_entries if e.get("source") == "CVE"]
    non_cve_entries = [e for e in all_entries if e.get("source") != "CVE"]

    metadata = {
        "generated_at": now,
        "counts_by_source": counts_by_source,
        "total": len(all_entries),
        "total_non_cve": len(non_cve_entries),
        "total_cve": len(cve_entries),
    }

    # Check if unified would exceed 50 MB
    unified_payload = {"metadata": metadata, "entries": all_entries}
    unified_json = json.dumps(unified_payload)
    size_mb = len(unified_json.encode()) / (1024 * 1024)
    print(f"Unified index size: {size_mb:.1f} MB")

    if size_mb > 50:
        print(f"Size {size_mb:.1f} MB exceeds 50 MB limit — splitting CVEs to cves_index.json")
        metadata["split"] = True
        # Write non-CVE unified index
        meta_payload = {"metadata": metadata, "entries": non_cve_entries}
        (DATA_DIR / "unified_index.json").write_text(json.dumps(meta_payload))
        # Write separate CVE index
        cve_payload = {"metadata": {"generated_at": now, "total": len(cve_entries)}, "entries": cve_entries}
        (DATA_DIR / "cves_index.json").write_text(json.dumps(cve_payload))
        print(f"Wrote unified_index.json ({len(non_cve_entries):,} entries) + cves_index.json ({len(cve_entries):,} entries)")
    else:
        (DATA_DIR / "unified_index.json").write_text(unified_json)
        metadata["split"] = False
        print(f"Wrote unified_index.json ({len(all_entries):,} entries, {size_mb:.1f} MB)")

    # Update last_run.json
    last_run["_generated_at"] = now
    LAST_RUN_FILE.write_text(json.dumps(last_run, indent=2))
    print(f"Wrote last_run.json")


if __name__ == "__main__":
    main()
