# GovSource Watch

> **"Monitoring the reliability of Philippine government information."**

GovSource Watch is an open-source civic technology platform that monitors the accessibility, availability, documented freshness, and technical change status of publicly accessible Philippine government websites, open-data portals, APIs, and official publications.

> **Disclaimer:** GovSource Watch is an independent civic technology project and is not affiliated with, endorsed by, or an official representative of any Philippine government agency. Technical availability (e.g., HTTP 200) does not verify the factual accuracy of government publications.

## Architecture Overview

- **100% Static & Free-Tier Native:** Built with zero-dependency HTML, CSS, and ES Modules, deployed on **Cloudflare Pages Free** (`site/`).
- **Automated Checks (Planned Stage 5):** Scheduled GitHub Actions workflows will check curated endpoints in `config/sources.json` and update `site/data/*.json`.
- **Transparent Provenance:** Every source record preserves its official `.gov.ph` URL, check method, and known limitations (including WAF/bot-protection restrictions).

## Project Structure

```text
govsource-watch/
├── config/
│   └── sources.json        # Curated registry of official .gov.ph sources
├── site/                   # Cloudflare Pages publish directory
│   ├── index.html          # Observatory dashboard shell
│   ├── styles.css          # Dark-mode civic observatory design system
│   ├── app.js              # Client-side state & view renderer
│   └── data/
│       ├── status.json     # Current source status & summary counts
│       ├── incidents.json  # Confirmed multi-check incident records
│       └── datasets.json   # Schedule-aware dataset freshness registry
├── LICENSE                 # MIT License
└── README.md
```

## Local Preview

Serve the `site/` directory with any static HTTP server:

```bash
python3 -m http.server 8080 --directory site
```

Then open `http://localhost:8080` in your browser.

## Free-Tier Deployment (GitHub + Cloudflare Pages)

1. Push this repository to a **public** GitHub repository (required for unlimited free GitHub Actions minutes).
2. In **Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git**, select the repository:
   - **Build command:** *(leave empty)*
   - **Build output directory:** `site`
3. The workflow in `.github/workflows/monitor.yml` runs every **4 hours** (~180 runs/month, safely below Cloudflare Pages Free's 500 builds/month limit) and commits updated JSON files to `site/data/`.

