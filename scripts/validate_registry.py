#!/usr/bin/env python3
"""Validate GovSource Watch registry and static JSON data files."""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
CONFIG_SOURCES = ROOT / "config" / "sources.json"
SITE_DATA = ROOT / "site" / "data"

ALLOWED_CATEGORIES = {
    "agency_portal",
    "open_data_portal",
    "open_data_api",
    "statistical_api",
    "document_repository",
    "public_service_portal",
}
ALLOWED_METHODS = {"HEAD", "GET"}


def validate_sources(path: Path) -> list[str]:
    errors = []
    data = json.loads(path.read_text(encoding="utf-8"))
    sources = data.get("sources", [])
    if not sources:
        return [f"{path}: 'sources' list is empty"]

    seen_ids = set()
    for idx, src in enumerate(sources):
        sid = src.get("id", "")
        if not sid or sid in seen_ids:
            errors.append(f"{path}[{idx}]: missing or duplicate id '{sid}'")
        seen_ids.add(sid)

        url = src.get("url", "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc.endswith(".gov.ph"):
            errors.append(f"{path}[{sid}]: URL must use https:// and .gov.ph domain (got '{url}')")

        if src.get("category") not in ALLOWED_CATEGORIES:
            errors.append(f"{path}[{sid}]: invalid category '{src.get('category')}'")

        if src.get("check_method") not in ALLOWED_METHODS:
            errors.append(f"{path}[{sid}]: invalid check_method '{src.get('check_method')}'")

    return errors


def main() -> int:
    all_errors = []
    all_errors.extend(validate_sources(CONFIG_SOURCES))
    all_errors.extend(validate_sources(SITE_DATA / "sources.json"))

    if (CONFIG_SOURCES.read_text(encoding="utf-8") != (SITE_DATA / "sources.json").read_text(encoding="utf-8")):
        all_errors.append("config/sources.json and site/data/sources.json are out of sync")

    for name in ("status.json", "incidents.json", "datasets.json"):
        p = SITE_DATA / name
        try:
            json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            all_errors.append(f"{p}: invalid JSON ({exc})")

    if all_errors:
        for err in all_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("OK: Registry and site/data JSON files validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
