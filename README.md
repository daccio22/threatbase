# ThreatBase

A fully static, GitHub Pages-deployable threat intelligence search hub that aggregates **MITRE ATT&CK**, **D3FEND**, **SPARTA**, **ESA SHIELD**, **CVE** (via NVD), and **CWE** into a unified, cross-referenced, browsable UI. Data is refreshed nightly via GitHub Actions.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GitHub Actions                    │
│  ┌──────────────────┐    ┌────────────────────────┐ │
│  │  update-data.yml │    │  deploy-pages.yml      │ │
│  │  (3am UTC daily) │    │  (on push to main)     │ │
│  │                  │    │                        │ │
│  │  fetch_attack.py │    │  npm ci && npm build   │ │
│  │  fetch_d3fend.py │    │  copy data/ → public/  │ │
│  │  fetch_cve.py    │───▶│  deploy to Pages       │ │
│  │  fetch_cwe.py    │    └────────────────────────┘ │
│  │  fetch_sparta.py │                               │
│  │  fetch_esa_shield│                               │
│  │  build_index.py  │                               │
│  └──────────────────┘                               │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────────────┐
│  data/           │     │  ui/ (React + Vite)       │
│  attack.json     │────▶│  Fuse.js fuzzy search     │
│  d3fend.json     │     │  Tailwind dark UI         │
│  cve.json        │     │  D3.js graph view         │
│  cwe.json        │     │  Filter + source pills    │
│  sparta.json     │     │  URL-synced search state  │
│  esa_shield.json │     └──────────────────────────┘
│  unified_index   │
│  last_run.json   │
└──────────────────┘
```

## Setup

### 1. Fork / clone this repository

```bash
git clone https://github.com/YOUR_USERNAME/threatbase
cd threatbase
```

### 2. Add NVD API key secret

1. Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
2. In your GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**
3. Name: `NVD_API_KEY`, Value: your key

### 3. Enable GitHub Pages from Actions

1. **Settings → Pages → Source**: select **GitHub Actions**

### 4. Trigger the first data build

```
Actions → Update threat data → Run workflow
```

The first run will perform a full NVD CVE ingest (~10–20 min, ~150 API calls). Subsequent runs are incremental.

After the data workflow completes, the deploy workflow fires automatically.

### Local development

```bash
# Install Python deps and run fetch scripts
pip install -r requirements.txt
python scripts/fetch_attack.py
python scripts/fetch_d3fend.py
NVD_API_KEY=your_key python scripts/fetch_cve.py
python scripts/fetch_cwe.py
python scripts/fetch_sparta.py
python scripts/fetch_esa_shield.py
python scripts/build_index.py

# Run the UI dev server
cd ui
npm install
npm run dev
# → http://localhost:5173/threatbase/
```

## Data Sources

| Source | Description | License |
|---|---|---|
| [MITRE ATT&CK](https://attack.mitre.org) | Adversary tactics and techniques | [CC BY 4.0](https://attack.mitre.org/resources/terms-of-use/) |
| [MITRE D3FEND](https://d3fend.mitre.org) | Defensive countermeasure ontology | [MIT](https://github.com/mitre/d3fend-ontology/blob/main/LICENSE.txt) |
| [NVD CVE](https://nvd.nist.gov) | Common Vulnerabilities and Exposures | Public domain |
| [MITRE CWE](https://cwe.mitre.org) | Common Weakness Enumeration | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html) |
| [MITRE SPARTA](https://github.com/mitre/SPARTA) | Space-specific attack framework | [Apache 2.0](https://github.com/mitre/SPARTA/blob/main/LICENSE) |
| [ESA SHIELD](https://github.com/esaSPACEops/SHIELD) | Space cybersecurity framework | See repo |

> **ESA SHIELD note**: If structured machine-readable data is not yet available in the ESA SHIELD GitHub repository, ThreatBase falls back to a curated seed file (`data/esa_shield_seed.json`) with entries marked `"seed": true`.

## Search Syntax

| Syntax | Example | Meaning |
|---|---|---|
| Plain text | `credential dumping` | Fuzzy full-text search |
| `source:X` | `source:CVE` | Filter by source |
| `score:>N` | `score:>7` | CVE CVSS score filter |
| `tag:X` | `tag:linux` | Filter by tag |
| Combined | `source:ATT&CK tag:windows lateral` | All filters apply |

## License

MIT — see [LICENSE](LICENSE)
# threatbase
