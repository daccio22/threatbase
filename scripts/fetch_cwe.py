#!/usr/bin/env python3
"""Fetch CWE catalog from MITRE XML ZIP and parse weaknesses."""

import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

OUTPUT = Path(__file__).parent.parent / "data" / "cwe.json"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NS = {
    "cwe": "http://cwe.mitre.org/cwe-7",
    "xhtml": "http://www.w3.org/1999/xhtml",
}


def fetch_cwe_zip():
    print(f"Downloading CWE XML from {CWE_URL} ...")
    req = urllib.request.Request(CWE_URL, headers={"User-Agent": "threatbase/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def text_content(element) -> str:
    """Extract all text from an element tree, collapsing whitespace."""
    if element is None:
        return ""
    parts = []
    for node in element.iter():
        if node.text:
            parts.append(node.text.strip())
        if node.tail:
            parts.append(node.tail.strip())
    return " ".join(p for p in parts if p)


def parse_cwe(xml_bytes: bytes) -> list[dict]:
    tree = ET.parse(io.BytesIO(xml_bytes))
    root = tree.getroot()

    # Root may be Weakness_Catalog
    weaknesses_el = root.find(".//cwe:Weaknesses", NS) or root
    weakness_list = weaknesses_el.findall("cwe:Weakness", NS) or root.findall(
        ".//{http://cwe.mitre.org/cwe-7}Weakness"
    )

    if not weakness_list:
        # Try without namespace
        weakness_list = root.findall(".//Weakness")

    print(f"Found {len(weakness_list)} weakness elements")
    results = []

    for w in weakness_list:
        cwe_num = w.get("ID", "")
        if not cwe_num:
            continue
        cwe_id = f"CWE-{cwe_num}"
        name = w.get("Name", "")

        desc_el = (
            w.find("cwe:Description", NS)
            or w.find("{http://cwe.mitre.org/cwe-7}Description")
            or w.find("Description")
        )
        description = text_content(desc_el)

        ext_desc_el = (
            w.find("cwe:Extended_Description", NS)
            or w.find("{http://cwe.mitre.org/cwe-7}Extended_Description")
            or w.find("Extended_Description")
        )
        extended_description = text_content(ext_desc_el)

        # Related weaknesses
        related = []
        for rw in w.findall(".//cwe:Related_Weakness", NS) or w.findall(".//{http://cwe.mitre.org/cwe-7}Related_Weakness") or w.findall(".//Related_Weakness"):
            nature = rw.get("Nature", "")
            rel_id = rw.get("CWE_ID", "")
            if rel_id:
                related.append({"nature": nature, "id": f"CWE-{rel_id}"})

        # Applicable platforms
        platforms = []
        for lang in w.findall(".//cwe:Language", NS) or w.findall(".//{http://cwe.mitre.org/cwe-7}Language") or w.findall(".//Language"):
            name_val = lang.get("Name") or lang.get("Class", "")
            if name_val:
                platforms.append(name_val)
        for tech in w.findall(".//cwe:Technology", NS) or w.findall(".//{http://cwe.mitre.org/cwe-7}Technology") or w.findall(".//Technology"):
            name_val = tech.get("Name") or tech.get("Class", "")
            if name_val:
                platforms.append(name_val)

        # CAPEC references (attack patterns)
        capec_ids = []
        for rap in (
            w.findall(".//cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern", NS)
            or w.findall(".//{http://cwe.mitre.org/cwe-7}Related_Attack_Pattern")
            or w.findall(".//Related_Attack_Pattern")
        ):
            capec_id = rap.get("CAPEC_ID", "")
            if capec_id:
                capec_ids.append(f"CAPEC-{capec_id}")

        # Common consequences
        consequences = []
        for cc in w.findall(".//cwe:Consequence", NS) or w.findall(".//{http://cwe.mitre.org/cwe-7}Consequence") or w.findall(".//Consequence"):
            scope_els = cc.findall("cwe:Scope", NS) or cc.findall("{http://cwe.mitre.org/cwe-7}Scope") or cc.findall("Scope")
            impact_els = cc.findall("cwe:Impact", NS) or cc.findall("{http://cwe.mitre.org/cwe-7}Impact") or cc.findall("Impact")
            scopes = [e.text for e in scope_els if e.text]
            impacts = [e.text for e in impact_els if e.text]
            if scopes or impacts:
                consequences.append({"scopes": scopes, "impacts": impacts})

        # Mitigations
        mitigations = []
        for m in w.findall(".//cwe:Mitigation", NS) or w.findall(".//{http://cwe.mitre.org/cwe-7}Mitigation") or w.findall(".//Mitigation"):
            desc_m = m.find("cwe:Description", NS) or m.find("{http://cwe.mitre.org/cwe-7}Description") or m.find("Description")
            text = text_content(desc_m)
            if text:
                mitigations.append(text)

        results.append({
            "id": cwe_id,
            "name": w.get("Name", ""),
            "description": description,
            "extended_description": extended_description,
            "related_weaknesses": related,
            "platforms": list(dict.fromkeys(platforms)),
            "consequences": consequences,
            "mitigations": mitigations,
            "capec_ids": capec_ids,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            "source": "CWE",
        })

    return results


def main():
    existing = []
    if OUTPUT.exists():
        try:
            existing = json.loads(OUTPUT.read_text())
            print(f"Existing CWE data: {len(existing)} entries")
        except Exception:
            pass

    try:
        zip_data = fetch_cwe_zip()
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            xml_files = [n for n in zf.namelist() if n.endswith(".xml")]
            if not xml_files:
                raise ValueError("No XML file found in ZIP")
            xml_bytes = zf.read(xml_files[0])
            print(f"Parsing {xml_files[0]} ({len(xml_bytes):,} bytes)")

        weaknesses = parse_cwe(xml_bytes)
        print(f"Parsed {len(weaknesses)} CWE entries")
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(weaknesses, indent=2))
        print(f"Wrote {OUTPUT}")
    except Exception as exc:
        print(f"ERROR fetching CWE: {exc}", file=sys.stderr)
        import traceback; traceback.print_exc()
        if existing:
            print("Falling back to existing data.")
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text("[]")
        sys.exit(0)


if __name__ == "__main__":
    main()
