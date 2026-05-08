"""
guardian-ssdlc · tools/sca.py
──────────────────────────────
Software Composition Analysis (SCA) tool.
Parses requirements.txt / package.json and queries the OSV vulnerability
database (https://osv.dev) to surface known CVEs in third-party dependencies.

Live API mode: set GUARDIAN_LIVE_OSV=true in .env to query osv.dev in real time.
Offline/default mode: uses the curated mock database in helpers.py.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.utils.helpers import (
    OSV_MOCK_DB,
    normalize_package_name,
    parse_package_json,
    parse_requirements_txt,
    severity_rank,
)

logger = logging.getLogger("guardian.sca")
logger.debug(
    "OSV mode: %s",
    "LIVE (osv.dev)"
    if os.getenv("GUARDIAN_LIVE_OSV", "").lower() in ("1", "true", "yes")
    else "OFFLINE (mock DB)",
)

# ──────────────────────────────────────────────────────────────────
# OSV API configuration
# ──────────────────────────────────────────────────────────────────
_OSV_API_URL = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT = 5  # seconds — fail fast, fall back to mock

# Set GUARDIAN_LIVE_OSV=true in .env to query osv.dev; default is mock.
_USE_LIVE_OSV: bool = os.getenv("GUARDIAN_LIVE_OSV", "").lower() in ("1", "true", "yes")

# OSV uses "MODERATE" — map to our internal "MEDIUM"
_OSV_SEV_MAP: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Rough CVSS midpoint per bucket (used when OSV omits the numeric score)
_SEV_TO_CVSS: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}


# ──────────────────────────────────────────────────────────────────
# Input Schema
# ──────────────────────────────────────────────────────────────────


class CheckDependenciesInput(BaseModel):
    manifest_path: str = Field(
        ...,
        description=(
            "Absolute or relative path to requirements.txt or package.json. "
            "Alternatively, pass raw file content as a string prefixed with "
            "'CONTENT:' for inline scanning."
        ),
        examples=["./requirements.txt", "./package.json"],
    )

    @field_validator("manifest_path")
    @classmethod
    def validate_manifest(cls, v: str) -> str:
        if v.startswith("CONTENT:"):
            return v
        p = Path(v)
        if not p.exists():
            raise ValueError(f"Manifest file not found: {v}")
        if p.name not in ("requirements.txt", "package.json"):
            raise ValueError(f"Only requirements.txt and package.json are supported. Got: {p.name}")
        return v


# ──────────────────────────────────────────────────────────────────
# Core Logic
# ──────────────────────────────────────────────────────────────────


def _parse_osv_response(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a raw OSV API response dict to our internal finding format."""
    results: list[dict[str, Any]] = []
    for vuln in data.get("vulns", []):
        # Severity: prefer database_specific.severity, fall back to MEDIUM
        raw_sev = vuln.get("database_specific", {}).get("severity", "MEDIUM")
        severity = _OSV_SEV_MAP.get(raw_sev.upper(), "MEDIUM")
        cvss_score = _SEV_TO_CVSS.get(severity, 5.0)

        # Fixed version: walk affected[].ranges[].events for {"fixed": "x.y.z"}
        fixed_version = "Unknown"
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break

        results.append(
            {
                "id": vuln.get("id", ""),
                "aliases": vuln.get("aliases", []),
                "summary": (vuln.get("summary") or vuln.get("details", "No description"))[:250],
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_versions": "",
                "fixed_version": fixed_version,
                "published": vuln.get("published", ""),
                "references": [r.get("url", "") for r in vuln.get("references", [])[:3]],
            }
        )
    return results


def _query_osv(package_name: str, ecosystem: str = "PyPI") -> list[dict[str, Any]]:
    """
    Query OSV for a package.

    Live mode (GUARDIAN_LIVE_OSV=true): POST to osv.dev API; falls back to
    mock DB on any network error so the tool always returns a result.
    Offline mode (default): return from the curated mock database only.
    """
    norm = normalize_package_name(package_name)

    if not _USE_LIVE_OSV:
        return OSV_MOCK_DB.get(norm, [])

    try:
        payload = json.dumps({"package": {"name": norm, "ecosystem": ecosystem}}).encode()
        req = urllib.request.Request(
            _OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_OSV_TIMEOUT) as resp:
            data: dict[str, Any] = json.loads(resp.read().decode())
        logger.debug(
            "OSV live hit for %s/%s: %d vulns", ecosystem, norm, len(data.get("vulns", []))
        )
        return _parse_osv_response(data)
    except Exception as exc:
        logger.warning("OSV API unavailable for %s (%s); falling back to mock DB.", norm, exc)
        return OSV_MOCK_DB.get(norm, [])


def _load_packages(manifest_path: str) -> tuple[str, list[dict[str, str]]]:
    """
    Load and parse a manifest file. Returns (ecosystem, packages).
    """
    if manifest_path.startswith("CONTENT:"):
        raw = manifest_path[len("CONTENT:") :]
        # Guess ecosystem from content shape
        if raw.strip().startswith("{"):
            data = json.loads(raw)
            return "npm", parse_package_json(data)
        return "PyPI", parse_requirements_txt(raw)

    p = Path(manifest_path)
    content = p.read_text(encoding="utf-8")

    if p.name == "requirements.txt":
        return "PyPI", parse_requirements_txt(content)
    else:  # package.json
        data = json.loads(content)
        return "npm", parse_package_json(data)


def run_sca(manifest_path: str) -> dict[str, Any]:
    """
    Main SCA entry-point.
    Returns a structured report: summary, vulnerable packages, clean packages.
    """
    logger.info("Starting SCA scan: %s", manifest_path)

    ecosystem, packages = _load_packages(manifest_path)
    logger.info("Detected ecosystem: %s | Packages found: %d", ecosystem, len(packages))

    vulnerable: list[dict[str, Any]] = []
    clean: list[str] = []
    total_vulns = 0

    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        findings = _query_osv(name, ecosystem=ecosystem)

        if findings:
            total_vulns += len(findings)
            # Sort by CVSS score descending
            sorted_findings = sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)
            vulnerable.append(
                {
                    "package": name,
                    "installed_version": version,
                    "vulnerabilities": sorted_findings,
                    "highest_severity": sorted_findings[0]["severity"],
                    "vuln_count": len(sorted_findings),
                }
            )
        else:
            clean.append(name)

    # Sort vulnerable packages by highest severity
    vulnerable.sort(key=lambda x: severity_rank(x["highest_severity"]), reverse=True)

    critical_count = sum(1 for v in vulnerable if v["highest_severity"] == "CRITICAL")
    high_count = sum(1 for v in vulnerable if v["highest_severity"] == "HIGH")

    report: dict[str, Any] = {
        "scan_type": "Software Composition Analysis (SCA)",
        "ecosystem": ecosystem,
        "manifest": manifest_path,
        "summary": {
            "total_packages_scanned": len(packages),
            "vulnerable_packages": len(vulnerable),
            "clean_packages": len(clean),
            "total_vulnerabilities": total_vulns,
            "critical": critical_count,
            "high": high_count,
            "risk_rating": (
                "CRITICAL"
                if critical_count > 0
                else "HIGH"
                if high_count > 0
                else "MEDIUM"
                if vulnerable
                else "LOW"
            ),
        },
        "vulnerable_packages": vulnerable,
        "clean_packages": clean,
        "remediation_priority": [
            f"Upgrade {v['package']} (installed: {v['installed_version']}) — "
            f"{v['vuln_count']} vuln(s), highest: {v['highest_severity']}"
            for v in vulnerable
        ],
        "data_source": "OSV.dev (mock — replace with live API in production)",
    }

    logger.info(
        "SCA complete: %d vulnerable, %d clean, risk=%s",
        len(vulnerable),
        len(clean),
        report["summary"]["risk_rating"],
    )
    return report


# ──────────────────────────────────────────────────────────────────
# Compatibility wrapper — flattened response schema
# ──────────────────────────────────────────────────────────────────


def _load_packages_from_json(
    data: dict[str, Any],
    include_dev: bool,
) -> list[dict[str, str]]:
    """Parse package.json, optionally skipping devDependencies."""
    import re as _re

    packages: list[dict[str, str]] = []
    sections = ["dependencies"]
    if include_dev:
        sections.append("devDependencies")
    for section in sections:
        for name, version in data.get(section, {}).items():
            clean = _re.sub(r"[^0-9.]", "", version) if version else ""
            packages.append({"name": name.lower(), "version": clean or "unknown"})
    return packages


def run_dependency_check(
    manifest_path: str,
    include_dev_dependencies: bool = True,
) -> dict[str, Any]:
    """
    Compatibility entry-point with a flat response schema.

    Returns a dict with top-level keys:
      scan_status, ecosystem, total_dependencies, vulnerable_count,
      risk_score, findings (flat list), and error (on failure).

    Each finding: package, installed_version, severity, cvss_score,
                  cve_id, summary, fixed_version.
    """
    import json as _json

    p = Path(manifest_path)

    # ── file validation ───────────────────────────────────────────
    if not p.exists():
        return {"scan_status": "FAILED", "error": f"File not found: {manifest_path}"}

    if p.name not in ("requirements.txt", "package.json"):
        return {
            "scan_status": "FAILED",
            "error": (
                f"Unsupported manifest format: {p.name}. "
                "Only requirements.txt and package.json are supported."
            ),
        }

    # ── parse manifest ────────────────────────────────────────────
    try:
        if p.name == "requirements.txt":
            ecosystem = "PyPI"
            packages = parse_requirements_txt(p.read_text(encoding="utf-8"))
        else:
            ecosystem = "npm"
            packages = _load_packages_from_json(
                _json.loads(p.read_text(encoding="utf-8")),
                include_dev=include_dev_dependencies,
            )
    except Exception as exc:
        return {"scan_status": "FAILED", "error": str(exc)}

    # ── scan ─────────────────────────────────────────────────────
    flat_findings: list[dict[str, Any]] = []

    for pkg in packages:
        name = pkg["name"]
        raw_version = pkg["version"]
        installed_version = "UNPINNED" if raw_version in ("unknown", "") else raw_version
        osv_hits = _query_osv(name, ecosystem=ecosystem)

        for vuln in osv_hits:
            flat_findings.append(
                {
                    "package": name,
                    "installed_version": installed_version,
                    "severity": vuln.get("severity", "MEDIUM"),
                    "cvss_score": float(vuln.get("cvss_score", 0.0)),
                    "cve_id": (vuln.get("aliases") or ["N/A"])[0],
                    "summary": vuln.get("summary", ""),
                    "fixed_version": vuln.get("fixed_version", "Unknown"),
                }
            )

    # Sort CRITICAL → HIGH → MEDIUM → LOW
    flat_findings.sort(key=lambda x: severity_rank(x["severity"]), reverse=True)

    vulnerable_packages = {f["package"] for f in flat_findings}
    max_cvss = max((f["cvss_score"] for f in flat_findings), default=0.0)
    risk_score = round(max_cvss / 10.0, 2)

    return {
        "scan_status": "COMPLETED",
        "ecosystem": ecosystem,
        "total_dependencies": len(packages),
        "vulnerable_count": len(vulnerable_packages),
        "risk_score": risk_score,
        "findings": flat_findings,
    }
