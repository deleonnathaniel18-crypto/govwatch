#!/usr/bin/env python3
"""GovSource Watch monitoring engine.

Performs respectful, rate-limited HTTP checks against curated .gov.ph sources,
classifies WAF restrictions separately from outages, maintains daily history
aggregates, and updates multi-check confirmed incident records.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCES_PATH = ROOT / "config" / "sources.json"
SITE_DATA = ROOT / "site" / "data"
STATUS_PATH = SITE_DATA / "status.json"
INCIDENTS_PATH = SITE_DATA / "incidents.json"
DATASETS_PATH = SITE_DATA / "datasets.json"
HISTORY_DIR = SITE_DATA / "history"

USER_AGENT = "GovSourceWatch/1.0 (+https://github.com/govsource-watch; civic-tech-observatory)"
MAX_BODY_HASH_BYTES = 5 * 1024 * 1024  # 5 MiB cap for SHA-256 hashing
DOMAIN_DELAY_SECONDS = 2.0
RETRY_BACKOFFS = (2.0,)
UNAVAILABLE_THRESHOLD = 2


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def is_valid_govph_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.netloc.lower().endswith(".gov.ph")


def detect_waf_block(status_code: int, headers: dict[str, str], snippet: str) -> bool:
    """Detect Cloudflare/Imperva WAF challenges without masking real 503 origin outages."""
    lowered_headers = {k.lower(): v.lower() for k, v in headers.items()}
    if "challenge" in lowered_headers.get("cf-mitigated", ""):
        return True
    if status_code in (403, 429):
        server = lowered_headers.get("server", "")
        lowered_body = snippet.lower()
        if "cloudflare" in server and (
            "just a moment" in lowered_body
            or "attention required" in lowered_body
            or "cf-chl" in lowered_body
            or "cf-ray" in lowered_headers
        ):
            return True
        if "incapsula" in lowered_body or "x-iinfo" in lowered_headers:
            return True
    return False


def check_robots_allowed(url: str, cache: dict[str, urllib.robotparser.RobotFileParser | None]) -> bool:
    parsed = urllib.parse.urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in cache:
        rp = urllib.robotparser.RobotFileParser()
        robots_url = f"{origin}/robots.txt"
        try:
            req = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read(65536).decode("utf-8", errors="replace")
            rp.parse(content.splitlines())
            cache[origin] = rp
        except urllib.error.HTTPError as exc:
            # 404 means no robots.txt restrictions; 403/5xx means we cannot read it
            cache[origin] = None if exc.code == 404 else None
        except Exception:
            cache[origin] = None

    rp = cache[origin]
    if rp is None:
        return True
    return rp.can_fetch(USER_AGENT, url)


def classify_relay_payload(
    payload: dict[str, Any],
    expected_statuses: list[int],
) -> dict[str, Any]:
    """Convert a Cloudflare Worker relay JSON payload into a standard check result."""
    if "error" in payload and "http_status" not in payload:
        return {
            "outcome": "issues",
            "http_status": None,
            "response_time_ms": None,
            "etag": None,
            "last_modified": None,
            "sha256": None,
            "error": f"Relay: {payload['error']}",
        }

    status_code = payload.get("http_status")
    headers = payload.get("headers") or {}
    snippet = payload.get("snippet") or ""
    latency_ms = payload.get("response_time_ms")

    if status_code in expected_statuses:
        return {
            "outcome": "online",
            "http_status": status_code,
            "response_time_ms": latency_ms,
            "etag": payload.get("etag"),
            "last_modified": payload.get("last_modified"),
            "sha256": None,
            "error": None,
        }

    if status_code is not None and detect_waf_block(status_code, headers, snippet):
        return {
            "outcome": "monitoring_restricted",
            "http_status": status_code,
            "response_time_ms": latency_ms,
            "etag": None,
            "last_modified": None,
            "sha256": None,
            "error": f"WAF/bot protection detected (HTTP {status_code})",
        }

    return {
        "outcome": "issues",
        "http_status": status_code,
        "response_time_ms": latency_ms,
        "etag": None,
        "last_modified": None,
        "sha256": None,
        "error": f"HTTP {status_code}" if status_code is not None else "Relay check failed",
    }


def perform_relay_check(
    relay_url: str,
    relay_key: str,
    url: str,
    method: str,
    timeout: int,
    expected_statuses: list[int],
) -> dict[str, Any]:
    """Probe a .gov.ph URL via the optional Cloudflare Worker relay."""
    qs = urllib.parse.urlencode({"url": url, "method": method})
    full_url = f"{relay_url.rstrip('/')}?{qs}"
    req = urllib.request.Request(
        full_url,
        method="GET",
        headers={"X-Probe-Key": relay_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=max(timeout, 20)) as resp:
            payload = json.loads(resp.read(65536).decode("utf-8"))
            return classify_relay_payload(payload, expected_statuses)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read(8192).decode("utf-8"))
            return classify_relay_payload(payload, expected_statuses)
        except Exception:
            return {
                "outcome": "issues",
                "http_status": None,
                "response_time_ms": None,
                "etag": None,
                "last_modified": None,
                "sha256": None,
                "error": f"Relay HTTP {exc.code}",
            }
    except Exception as exc:
        msg = str(exc).strip()
        return {
            "outcome": "issues",
            "http_status": None,
            "response_time_ms": None,
            "etag": None,
            "last_modified": None,
            "sha256": None,
            "error": f"Relay {type(exc).__name__}: {msg}" if msg else f"Relay {type(exc).__name__}",
        }


def perform_http_check(
    url: str,
    method: str,
    timeout: int,
    expected_statuses: list[int],
) -> dict[str, Any]:
    """Execute a single HTTP check with retries and WAF detection."""
    attempts = 1 + len(RETRY_BACKOFFS)
    last_error: str | None = None

    for attempt in range(attempts):
        start = time.monotonic()
        req = urllib.request.Request(
            url,
            method=method,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                latency_ms = round((time.monotonic() - start) * 1000)
                headers = dict(resp.headers.items())
                sha256_hex: str | None = None
                if method == "GET":
                    body = resp.read(MAX_BODY_HASH_BYTES + 1)
                    if len(body) <= MAX_BODY_HASH_BYTES:
                        sha256_hex = hashlib.sha256(body).hexdigest()

                ok = resp.status in expected_statuses
                return {
                    "outcome": "online" if ok else "issues",
                    "http_status": resp.status,
                    "response_time_ms": latency_ms,
                    "etag": headers.get("ETag"),
                    "last_modified": headers.get("Last-Modified"),
                    "sha256": sha256_hex,
                    "error": None if ok else f"Unexpected HTTP {resp.status}",
                }
        except urllib.error.HTTPError as exc:
            latency_ms = round((time.monotonic() - start) * 1000)
            headers = dict(exc.headers.items()) if exc.headers else {}
            snippet = ""
            try:
                snippet = exc.read(4096).decode("utf-8", errors="replace")
            except Exception:
                pass

            if exc.code in (400, 403, 405) and method == "HEAD":
                return perform_http_check(url, "GET", timeout, expected_statuses)

            if detect_waf_block(exc.code, headers, snippet):
                return {
                    "outcome": "monitoring_restricted",
                    "http_status": exc.code,
                    "response_time_ms": latency_ms,
                    "etag": None,
                    "last_modified": None,
                    "sha256": None,
                    "error": f"WAF/bot protection detected (HTTP {exc.code})",
                }

            last_error = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code != 429:
                return {
                    "outcome": "issues",
                    "http_status": exc.code,
                    "response_time_ms": latency_ms,
                    "etag": None,
                    "last_modified": None,
                    "sha256": None,
                    "error": last_error,
                }
        except urllib.error.URLError as exc:
            reason = exc.reason
            reason_str = str(reason).strip()
            if not reason_str:
                reason_str = type(reason).__name__
            last_error = f"URLError: {reason_str}"
        except Exception as exc:
            msg = str(exc).strip()
            last_error = f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__

        if attempt < len(RETRY_BACKOFFS):
            time.sleep(RETRY_BACKOFFS[attempt])

    if method == "HEAD":
        return perform_http_check(url, "GET", max(timeout, 25), expected_statuses)

    return {
        "outcome": "issues",
        "http_status": None,
        "response_time_ms": None,
        "etag": None,
        "last_modified": None,
        "sha256": None,
        "error": last_error or "Request failed",
    }


def update_incidents(
    incidents_data: dict[str, Any],
    source_id: str,
    new_status: str,
    consecutive_failures: int,
    http_status: int | None,
    now_iso: str,
) -> None:
    incidents = incidents_data.setdefault("incidents", [])
    open_inc = next(
        (inc for inc in incidents if inc["source_id"] == source_id and inc["status"] == "open"),
        None,
    )

    if new_status == "unavailable":
        if open_inc is None:
            inc_id = f"inc-{source_id}-{now_iso.replace(':', '').replace('-', '')}"
            incidents.insert(
                0,
                {
                    "id": inc_id,
                    "source_id": source_id,
                    "status": "open",
                    "severity": "unavailable",
                    "first_detected_at": now_iso,
                    "last_observed_at": now_iso,
                    "resolved_at": None,
                    "consecutive_failures_peak": consecutive_failures,
                    "evidence": {
                        "observed_http_statuses": [http_status] if http_status is not None else [],
                    },
                },
            )
        else:
            open_inc["last_observed_at"] = now_iso
            open_inc["consecutive_failures_peak"] = max(
                open_inc["consecutive_failures_peak"], consecutive_failures
            )
            if http_status is not None:
                statuses = open_inc["evidence"].setdefault("observed_http_statuses", [])
                if http_status not in statuses:
                    statuses.append(http_status)
    elif new_status == "online" and open_inc is not None:
        open_inc["status"] = "resolved"
        open_inc["resolved_at"] = now_iso
        open_inc["last_observed_at"] = now_iso


def update_daily_history(
    history_dir: Path,
    source_id: str,
    day_str: str,
    status: str,
    latency_ms: int | None,
) -> None:
    history_dir.mkdir(parents=True, exist_ok=True)
    month_str = day_str[:7]
    month_file = history_dir / f"daily-{month_str}.json"

    if month_file.exists():
        data = json.loads(month_file.read_text(encoding="utf-8"))
    else:
        data = {"schema_version": "1.0", "month": month_str, "sources": {}}

    src_days = data["sources"].setdefault(source_id, {})
    day_rec = src_days.setdefault(
        day_str,
        {
            "checks": 0,
            "success": 0,
            "issues": 0,
            "unavailable": 0,
            "restricted": 0,
            "avg_latency_ms": None,
        },
    )

    day_rec["checks"] += 1
    if status == "online":
        day_rec["success"] += 1
    elif status == "experiencing_issues":
        day_rec["issues"] += 1
    elif status == "unavailable":
        day_rec["unavailable"] += 1
    elif status == "monitoring_restricted":
        day_rec["restricted"] += 1

    if latency_ms is not None:
        prev_avg = day_rec["avg_latency_ms"]
        n = day_rec["checks"]
        day_rec["avg_latency_ms"] = (
            latency_ms if prev_avg is None else round(((prev_avg * (n - 1)) + latency_ms) / n)
        )

    month_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    months = sorted({p.stem.replace("daily-", "") for p in history_dir.glob("daily-*.json")}, reverse=True)
    index_file = history_dir / "index.json"
    index_file.write_text(
        json.dumps({"schema_version": "1.0", "months": months}, indent=2) + "\n",
        encoding="utf-8",
    )


def compute_30d_uptime(history_dir: Path, source_id: str) -> tuple[float | None, int]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    total_valid = 0
    total_success = 0

    for path in sorted(history_dir.glob("daily-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        src_days = data.get("sources", {}).get(source_id, {})
        for day_str, rec in src_days.items():
            if day_str >= cutoff:
                valid = rec["checks"] - rec.get("restricted", 0)
                total_valid += valid
                total_success += rec["success"]

    if total_valid == 0:
        return None, 0
    return round((total_success / total_valid) * 100, 2), total_valid


def run_monitoring() -> None:
    sources_cfg = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    status_data = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    incidents_data = json.loads(INCIDENTS_PATH.read_text(encoding="utf-8"))

    now_iso = utc_now_iso()
    today_str = utc_today()
    robots_cache: dict[str, urllib.robotparser.RobotFileParser | None] = {}
    last_domain_hit: dict[str, float] = {}

    summary = {
        "total_monitored": 0,
        "online": 0,
        "experiencing_issues": 0,
        "unavailable": 0,
        "monitoring_restricted": 0,
        "not_yet_checked": 0,
        "monitoring_suspended": 0,
    }

    for src in sources_cfg["sources"]:
        sid = src["id"]
        url = src["url"]
        summary["total_monitored"] += 1

        prev = status_data["sources"].get(sid, {})
        if not src.get("monitoring_enabled", True) or not is_valid_govph_url(url):
            status_data["sources"][sid] = {
                **prev,
                "status": "monitoring_suspended",
                "last_checked_at": now_iso,
                "last_error": src.get("notes") or "Monitoring disabled in registry",
            }
            summary["monitoring_suspended"] += 1
            continue

        if not check_robots_allowed(url, robots_cache):
            status_data["sources"][sid] = {
                **prev,
                "status": "monitoring_suspended",
                "last_checked_at": now_iso,
                "last_error": "Disallowed by robots.txt",
            }
            summary["monitoring_suspended"] += 1
            continue

        domain = urllib.parse.urlparse(url).netloc.lower()
        elapsed = time.monotonic() - last_domain_hit.get(domain, 0.0)
        if domain in last_domain_hit and elapsed < DOMAIN_DELAY_SECONDS:
            time.sleep(DOMAIN_DELAY_SECONDS - elapsed)

        relay_url = os.environ.get("PROBE_RELAY_URL", "").strip()
        relay_key = os.environ.get("PROBE_RELAY_KEY", "").strip()

        if relay_url and relay_key:
            result = perform_relay_check(
                relay_url=relay_url,
                relay_key=relay_key,
                url=url,
                method=src.get("check_method", "HEAD"),
                timeout=src.get("timeout_seconds", 15),
                expected_statuses=src.get("expected_status", [200]),
            )
        else:
            result = perform_http_check(
                url=url,
                method=src.get("check_method", "HEAD"),
                timeout=src.get("timeout_seconds", 15),
                expected_statuses=src.get("expected_status", [200]),
            )
        last_domain_hit[domain] = time.monotonic()

        outcome = result["outcome"]
        prev_failures = prev.get("consecutive_failures", 0)

        if outcome == "online":
            new_status = "online"
            consecutive_failures = 0
        elif outcome == "monitoring_restricted":
            new_status = "monitoring_restricted"
            consecutive_failures = 0
        else:
            consecutive_failures = prev_failures + 1
            new_status = (
                "unavailable" if consecutive_failures >= UNAVAILABLE_THRESHOLD else "experiencing_issues"
            )

        update_daily_history(HISTORY_DIR, sid, today_str, new_status, result["response_time_ms"])
        uptime_pct, sample_count = compute_30d_uptime(HISTORY_DIR, sid)
        update_incidents(
            incidents_data, sid, new_status, consecutive_failures, result["http_status"], now_iso
        )

        status_data["sources"][sid] = {
            "status": new_status,
            "last_checked_at": now_iso,
            "last_successful_at": now_iso if new_status == "online" else prev.get("last_successful_at"),
            "last_failed_at": now_iso if new_status in ("experiencing_issues", "unavailable") else prev.get("last_failed_at"),
            "http_status": result["http_status"],
            "response_time_ms": result["response_time_ms"],
            "last_error": result["error"],
            "consecutive_failures": consecutive_failures,
            "uptime_30d_pct": uptime_pct,
            "uptime_30d_sample_count": sample_count,
            "etag": result["etag"] or prev.get("etag"),
            "last_modified": result["last_modified"] or prev.get("last_modified"),
            "sha256": result["sha256"] or prev.get("sha256"),
        }
        summary[new_status] += 1

    status_data["generated_at"] = now_iso
    status_data["monitoring_active"] = True
    status_data["summary"] = summary

    STATUS_PATH.write_text(json.dumps(status_data, indent=2) + "\n", encoding="utf-8")
    INCIDENTS_PATH.write_text(json.dumps(incidents_data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    run_monitoring()
    print("Monitoring run completed.")
