#!/usr/bin/env python3
"""
Fetch CVEs from NVD API v2.
- First run: full paginated ingest with checkpoint resumption.
- Subsequent runs: incremental update (last 2 days).
"""

import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

OUTPUT = Path(__file__).parent.parent / "data" / "cve.json"
CHECKPOINT = Path(__file__).parent.parent / "data" / ".cve_checkpoint.json"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
PAGE_SIZE = 2000
MIN_CVSS = 4.0
SLEEP_WITH_KEY = 0.6
SLEEP_NO_KEY = 6.0


def nvd_request(params: dict, api_key: str | None) -> dict:
    url = NVD_BASE + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "threatbase/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            if attempt == 2:
                raise
            wait = (attempt + 1) * 5
            print(f"  Retry {attempt+1} after {wait}s: {exc}")
            time.sleep(wait)


def extract_cve(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description (English preferred)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS — prefer v3.1, fall back to v3.0, then v2
    cvss_score = None
    cvss_severity = ""
    cvss_vector = ""
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            m = entries[0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_severity = m.get("baseSeverity", "")
            cvss_vector = m.get("vectorString", "")
            break

    if cvss_score is None:
        entries = metrics.get("cvssMetricV2", [])
        if entries:
            m = entries[0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_severity = entries[0].get("baseSeverity", "")
            cvss_vector = m.get("vectorString", "")

    if cvss_score is None or cvss_score < MIN_CVSS:
        return None

    # CWE IDs
    cwe_ids = []
    for w in cve.get("weaknesses", []):
        for wd in w.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    cwe_ids = list(dict.fromkeys(cwe_ids))  # deduplicate

    # CPE strings (top 5)
    cpes = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpes.append(match["criteria"])
                    if len(cpes) >= 5:
                        break
            if len(cpes) >= 5:
                break
        if len(cpes) >= 5:
            break

    # References (top 3)
    refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

    # CVEs have no short name — derive one from the description for UI display
    name = (desc[:120] + "…") if len(desc) > 120 else desc

    return {
        "id": cve_id,
        "name": name,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwe_ids": cwe_ids,
        "cpes": cpes,
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "references": refs,
        "source": "CVE",
    }


def full_ingest(api_key: str | None) -> list[dict]:
    sleep_time = SLEEP_WITH_KEY if api_key else SLEEP_NO_KEY
    if not api_key:
        print("WARNING: No NVD_API_KEY set — using public rate limit (6s between requests)")

    # Load checkpoint
    start_index = 0
    results: dict[str, dict] = {}
    if CHECKPOINT.exists():
        try:
            cp = json.loads(CHECKPOINT.read_text())
            start_index = cp.get("next_index", 0)
            saved = cp.get("partial", [])
            results = {e["id"]: e for e in saved}
            print(f"Resuming from checkpoint: index={start_index}, saved={len(results)}")
        except Exception:
            pass

    # Get total count
    first = nvd_request({"startIndex": 0, "resultsPerPage": 1}, api_key)
    total = first.get("totalResults", 0)
    print(f"Total CVEs in NVD: {total:,}")

    page = start_index // PAGE_SIZE
    index = start_index

    while index < total:
        params = {"startIndex": index, "resultsPerPage": PAGE_SIZE}
        print(f"  Page {page+1} | startIndex={index:,} / {total:,} | saved={len(results):,}", flush=True)

        data = nvd_request(params, api_key)
        vulns = data.get("vulnerabilities", [])

        new_count = 0
        for item in vulns:
            entry = extract_cve(item)
            if entry:
                results[entry["id"]] = entry
                new_count += 1

        index += len(vulns)
        page += 1

        # Checkpoint every 10 pages
        if page % 10 == 0:
            CHECKPOINT.write_text(json.dumps({
                "next_index": index,
                "partial": list(results.values()),
            }))

        if index < total:
            time.sleep(sleep_time)

    # Clear checkpoint
    if CHECKPOINT.exists():
        CHECKPOINT.unlink()

    return list(results.values())


def incremental_update(existing: list[dict], api_key: str | None) -> tuple[list[dict], int, int, int]:
    sleep_time = SLEEP_WITH_KEY if api_key else SLEEP_NO_KEY
    existing_map = {e["id"]: e for e in existing}

    now = datetime.now(timezone.utc)
    start_dt = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end_dt = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "lastModStartDate": start_dt,
        "lastModEndDate": end_dt,
        "startIndex": 0,
        "resultsPerPage": PAGE_SIZE,
    }

    print(f"Fetching CVEs modified between {start_dt} and {end_dt}")
    added = updated = unchanged = 0

    while True:
        data = nvd_request(params, api_key)
        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        for item in vulns:
            entry = extract_cve(item)
            if entry is None:
                continue
            old = existing_map.get(entry["id"])
            if old is None:
                existing_map[entry["id"]] = entry
                added += 1
            elif old != entry:
                existing_map[entry["id"]] = entry
                updated += 1
            else:
                unchanged += 1

        next_idx = params["startIndex"] + len(vulns)
        if next_idx >= total:
            break
        params["startIndex"] = next_idx
        time.sleep(sleep_time)

    return list(existing_map.values()), added, updated, unchanged


def main():
    api_key = os.environ.get("NVD_API_KEY")
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing CVE data: {len(existing):,} entries")
        except Exception:
            pass

    try:
        if CHECKPOINT.exists():
            # An interrupted full ingest left a checkpoint — resume it.
            print("Checkpoint found — resuming interrupted full ingest...")
            entries = full_ingest(api_key)
        elif existing:
            print("Existing data found — performing incremental update...")
            entries, added, updated, unchanged = incremental_update(existing, api_key)
            print(f"  Added: {added:,}  Updated: {updated:,}  Unchanged: {unchanged:,}")
        else:
            print("No existing data — performing full ingest (this will take 10-20 minutes)...")
            entries = full_ingest(api_key)

        # Sort by modified date descending
        entries.sort(key=lambda e: e.get("modified", ""), reverse=True)

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(entries, indent=2))
        print(f"Wrote {len(entries):,} CVEs to {OUTPUT}")
    except Exception as exc:
        print(f"ERROR fetching CVEs: {exc}", file=sys.stderr)
        import traceback; traceback.print_exc()
        if existing:
            print("Falling back to existing data.")
            OUTPUT.write_text(json.dumps(existing, indent=2))
        elif CHECKPOINT.exists():
            # Preserve whatever the checkpoint has so the next run can resume.
            print("Keeping checkpoint for next run to resume from.")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text("[]")
        sys.exit(0)


if __name__ == "__main__":
    main()
