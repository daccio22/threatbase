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

CAPEC_MAP_FILE = DATA_DIR / "capec_attack_map.json"

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


def load_capec_attack_map() -> dict[str, list[str]]:
    """Load CAPEC→ATT&CK mapping, return empty dict if unavailable."""
    if not CAPEC_MAP_FILE.exists():
        print("  WARNING: capec_attack_map.json not found — CWE→ATT&CK links disabled")
        return {}
    try:
        return json.loads(CAPEC_MAP_FILE.read_text())
    except Exception as exc:
        print(f"  WARNING: could not load capec_attack_map.json: {exc}")
        return {}


def add_cross_refs(entries: list[dict]) -> None:
    """
    Build bidirectional cross_refs for each entry by scanning
    known relationship fields across all entries.
    """
    id_map = build_id_index(entries)
    capec_attack_map = load_capec_attack_map()

    # Build CWE → ATT&CK lookup via CAPEC intermediate
    cwe_to_attack: dict[str, list[str]] = {}
    for entry in entries:
        if entry.get("source") != "CWE":
            continue
        attack_ids = []
        for capec_id in entry.get("capec_ids", []):
            attack_ids.extend(capec_attack_map.get(capec_id, []))
        if attack_ids:
            cwe_to_attack[entry["id"]] = list(dict.fromkeys(attack_ids))

    # Build ATT&CK → D3FEND reverse lookup
    attack_to_d3fend: dict[str, list[str]] = {}
    for entry in entries:
        if entry.get("source") != "D3FEND":
            continue
        for att_id in entry.get("counters_attack_ids", []):
            attack_to_d3fend.setdefault(att_id, []).append(entry["id"])

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

        # CVE → CWE, ATT&CK (via CWE→CAPEC), D3FEND (via ATT&CK)
        if src == "CVE":
            link(eid, entry.get("cwe_ids", []))
            cve_attack_ids: list[str] = []
            for cwe_id in entry.get("cwe_ids", []):
                cve_attack_ids.extend(cwe_to_attack.get(cwe_id, []))
            cve_attack_ids = list(dict.fromkeys(cve_attack_ids))
            link(eid, cve_attack_ids)
            cve_d3fend_ids: list[str] = []
            for att_id in cve_attack_ids:
                cve_d3fend_ids.extend(attack_to_d3fend.get(att_id, []))
            link(eid, list(dict.fromkeys(cve_d3fend_ids)))

        # CWE → ATT&CK (via CAPEC), D3FEND (via ATT&CK)
        if src == "CWE":
            cwe_attack_ids = cwe_to_attack.get(eid, [])
            link(eid, cwe_attack_ids)
            cwe_d3fend_ids: list[str] = []
            for att_id in cwe_attack_ids:
                cwe_d3fend_ids.extend(attack_to_d3fend.get(att_id, []))
            link(eid, list(dict.fromkeys(cwe_d3fend_ids)))

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


def add_connection_scores(entries: list[dict]) -> None:
    """Add connection_score (0-100) and connection_rank based on cross_ref count."""
    scores = {e["id"]: len(e.get("cross_refs", [])) for e in entries if e.get("id")}
    max_s = max(scores.values(), default=1) or 1

    sorted_vals = sorted(scores.values())
    n = len(sorted_vals)
    p95 = sorted_vals[min(n - 1, max(0, int(n * 0.95)))] if sorted_vals else 0
    p80 = sorted_vals[min(n - 1, max(0, int(n * 0.80)))] if sorted_vals else 0
    p50 = sorted_vals[min(n - 1, max(0, int(n * 0.50)))] if sorted_vals else 0

    for entry in entries:
        eid = entry.get("id", "")
        if not eid:
            continue
        raw = scores.get(eid, 0)
        entry["connection_score"] = round((raw / max_s) * 100)
        if raw >= p95 and p95 > 0:
            entry["connection_rank"] = "critical"
        elif raw >= p80 and p80 > 0:
            entry["connection_rank"] = "high"
        elif raw >= p50 and p50 > 0:
            entry["connection_rank"] = "medium"
        else:
            entry["connection_rank"] = "low"


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

    cve_path = SOURCE_FILES["CVE"]
    cve_is_lfs = cve_path.exists() and cve_path.read_bytes()[:20] == b"version https://git-"
    if cve_is_lfs:
        print("  WARNING: cve.json appears to be a Git LFS pointer — cannot build without full CVE data.")
        print("  Aborting to avoid dropping CVE reverse links from existing unified_index.json.")
        print("  Run this script only after fetching real CVE data (fetch_cve.py).")
        sys.exit(1)

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

    print(f"Computing connection scores...")
    add_connection_scores(all_entries)

    # Separate CVEs to manage file size
    cve_entries = [e for e in all_entries if e.get("source") == "CVE"]
    non_cve_entries = [e for e in all_entries if e.get("source") != "CVE"]

    # Detect LFS pointer: if cves_index.json exists but is tiny (<1 KB), CVE data
    # wasn't fetched locally. Preserve total_cve from the existing file if available.
    cves_path = DATA_DIR / "cves_index.json"
    existing_total_cve = len(cve_entries)
    cve_is_lfs_pointer = cves_path.exists() and cves_path.stat().st_size < 1024
    if cve_is_lfs_pointer and not cve_entries:
        try:
            existing_meta = json.loads((DATA_DIR / "unified_index.json").read_text()).get("metadata", {})
            existing_total_cve = existing_meta.get("total_cve", 0)
            print(f"  NOTE: cves_index.json appears to be an LFS pointer — preserving existing total_cve={existing_total_cve}")
        except Exception:
            pass

    metadata = {
        "generated_at": now,
        "counts_by_source": counts_by_source,
        "total": len(non_cve_entries) + existing_total_cve,
        "total_non_cve": len(non_cve_entries),
        "total_cve": existing_total_cve,
    }

    # Check if unified would exceed 50 MB
    unified_payload = {"metadata": metadata, "entries": all_entries}
    unified_json = json.dumps(unified_payload)
    size_mb = len(unified_json.encode()) / (1024 * 1024)
    print(f"Unified index size: {size_mb:.1f} MB")

    if size_mb > 50 or cve_is_lfs_pointer:
        if cve_is_lfs_pointer:
            print(f"LFS pointer detected — writing non-CVE unified index with split=True (CVEs stay in cves_index.json)")
        else:
            print(f"Size {size_mb:.1f} MB exceeds 50 MB limit — splitting CVEs to cves_index.json")
        metadata["split"] = True
        meta_payload = {"metadata": metadata, "entries": non_cve_entries}
        (DATA_DIR / "unified_index.json").write_text(json.dumps(meta_payload))
        if cve_entries:
            cve_payload = {"metadata": {"generated_at": now, "total": len(cve_entries)}, "entries": cve_entries}
            (DATA_DIR / "cves_index.json").write_text(json.dumps(cve_payload))
            print(f"Wrote unified_index.json ({len(non_cve_entries):,} entries) + cves_index.json ({len(cve_entries):,} entries)")
        else:
            print(f"Wrote unified_index.json ({len(non_cve_entries):,} entries, cves_index.json unchanged)")
    else:
        metadata["split"] = False
        (DATA_DIR / "unified_index.json").write_text(unified_json)
        print(f"Wrote unified_index.json ({len(all_entries):,} entries, {size_mb:.1f} MB)")

    # Update last_run.json
    last_run["_generated_at"] = now
    LAST_RUN_FILE.write_text(json.dumps(last_run, indent=2))
    print(f"Wrote last_run.json")


if __name__ == "__main__":
    main()
