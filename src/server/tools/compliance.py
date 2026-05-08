"""
guardian-ssdlc · tools/compliance.py
──────────────────────────────────────
Compliance Guardrails tool.

Maps technical security findings to NIST SP 800-53 Rev 5 controls and
OWASP Top 10 2021 categories, producing an auditable compliance gap report.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("guardian.compliance")

# Policy files live at <project_root>/data/policies
# File is at src/server/tools/compliance.py → parents[3] = project root
_POLICY_DIR = Path(__file__).parents[3] / "data" / "policies"
_NIST_PATH = _POLICY_DIR / "nist_800_53.yaml"
_OWASP_PATH = _POLICY_DIR / "owasp_top10.yaml"


# ──────────────────────────────────────────────────────────────────
# Policy Loader (cached at module level)
# ──────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


_NIST_DATA: dict[str, Any] | None = None
_OWASP_DATA: dict[str, Any] | None = None


def _get_nist() -> dict[str, Any]:
    global _NIST_DATA
    if _NIST_DATA is None:
        _NIST_DATA = _load_yaml(_NIST_PATH)
    return _NIST_DATA


def _get_owasp() -> dict[str, Any]:
    global _OWASP_DATA
    if _OWASP_DATA is None:
        _OWASP_DATA = _load_yaml(_OWASP_PATH)
    return _OWASP_DATA


# ──────────────────────────────────────────────────────────────────
# Input Schema
# ──────────────────────────────────────────────────────────────────

SUPPORTED_FINDING_TYPES = frozenset(
    {
        "known_cve",
        "outdated_dependency",
        "hardcoded_secret",
        "api_key_exposure",
        "spoofing",
        "tampering",
        "repudiation",
        "information_disclosure",
        "denial_of_service",
        "elevation_of_privilege",
        "sql_injection",
        "command_injection",
        "missing_auth",
        "weak_crypto",
        "missing_threat_model",
    }
)

# Aliases map caller-supplied category names → canonical finding_type values
FINDING_TYPE_ALIASES: dict[str, str] = {
    "vulnerable_dependency": "known_cve",
    "hardcoded_credentials": "hardcoded_secret",
    "missing_logging": "repudiation",
    "sqli": "sql_injection",
    "insecure_transport": "information_disclosure",
    "missing_rate_limiting": "denial_of_service",
    "xss": "tampering",
    "csrf": "tampering",
    "broken_access_control": "elevation_of_privilege",
    "sensitive_data_exposure": "information_disclosure",
}

# Severity → suggested remediation timeline
REMEDIATION_TIMELINES: dict[str, str] = {
    "CRITICAL": "4 hours",
    "HIGH": "24 hours (1 business day)",
    "MEDIUM": "30 days",
    "LOW": "90 days",
}


def _normalize_finding_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalise a raw finding dict to the canonical field names expected by
    FindingInput.  Handles legacy keys (category, component) and applies
    FINDING_TYPE_ALIASES so callers can use informal category names.
    """
    d = dict(raw)
    # Rename legacy keys
    if "category" in d and "finding_type" not in d:
        d["finding_type"] = d.pop("category")
    if "component" in d and "affected_component" not in d:
        d["affected_component"] = d.pop("component")
    # Apply type aliases (case-insensitive, normalised)
    raw_type = d.get("finding_type", "")
    normalised = raw_type.lower().replace("-", "_").replace(" ", "_")
    if normalised in FINDING_TYPE_ALIASES:
        d["finding_type"] = FINDING_TYPE_ALIASES[normalised]
    return d


def _compliance_status(severity: str) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return "NON_COMPLIANT"
    if severity == "MEDIUM":
        return "PARTIAL_COMPLIANCE"
    return "COMPLIANT"


class FindingInput(BaseModel):
    finding_type: str = Field(
        ...,
        description=(
            "Normalised finding type. Supported values: "
            + ", ".join(sorted(SUPPORTED_FINDING_TYPES))
        ),
    )
    severity: str = Field(
        default="MEDIUM",
        description="Finding severity: CRITICAL, HIGH, MEDIUM, LOW.",
    )
    description: str = Field(
        default="",
        description="Human-readable description of the finding.",
    )
    affected_component: str | None = Field(
        default=None,
        description="Name of the component or file where the finding was detected.",
    )

    @field_validator("finding_type")
    @classmethod
    def normalise_finding(cls, v: str) -> str:
        return v.lower().replace("-", "_").replace(" ", "_")

    @field_validator("severity")
    @classmethod
    def normalise_severity(cls, v: str) -> str:
        return v.upper()


class AuditComplianceInput(BaseModel):
    findings: list[FindingInput] = Field(
        ...,
        min_length=1,
        description="List of security findings to map to compliance frameworks.",
    )
    frameworks: list[str] = Field(
        default=["NIST_800_53", "OWASP_TOP10"],
        description="Compliance frameworks to evaluate: NIST_800_53, OWASP_TOP10.",
    )

    @field_validator("frameworks")
    @classmethod
    def normalise_frameworks(cls, v: list[str]) -> list[str]:
        return [f.upper().replace("-", "_") for f in v]


# ──────────────────────────────────────────────────────────────────
# Core Logic
# ──────────────────────────────────────────────────────────────────

def _map_to_nist(finding: FindingInput) -> list[dict[str, Any]]:
    """Return NIST 800-53 controls applicable to the finding type."""
    nist = _get_nist()
    mappings = nist.get("mappings", {})
    entry = mappings.get(finding.finding_type, {})
    controls = entry.get("controls", [])

    # Also check broader STRIDE categories
    stride_map = {
        "sql_injection": "tampering",
        "command_injection": "tampering",
        "missing_auth": "spoofing",
        "weak_crypto": "information_disclosure",
        "missing_threat_model": "elevation_of_privilege",
    }
    if not controls and finding.finding_type in stride_map:
        fallback = stride_map[finding.finding_type]
        controls = mappings.get(fallback, {}).get("controls", [])

    return controls


def _map_to_owasp(finding: FindingInput) -> list[dict[str, Any]]:
    """Return OWASP Top 10 categories that apply to the finding type."""
    owasp = _get_owasp()
    matched: list[dict[str, Any]] = []

    for _cat_key, cat_data in owasp.get("categories", {}).items():
        triggers = cat_data.get("triggers", [])
        if finding.finding_type in triggers:
            matched.append(
                {
                    "id": cat_data["id"],
                    "name": cat_data["name"],
                    "description": cat_data["description"],
                    "remediation": cat_data.get("remediation", []),
                }
            )

    return matched


def run_compliance_audit(
    findings: list[dict[str, Any]] | str,
    frameworks: list[str] | None = None,
    include_remediation_timeline: bool = False,
) -> dict[str, Any]:
    """
    Main entry-point for compliance auditing.

    Accepts *findings* as either a list of dicts or a JSON string.
    Legacy field names (``category``, ``component``) and informal
    finding types (``vulnerable_dependency``, ``sqli``, …) are
    automatically normalised before processing.

    Extra response keys added for compatibility:
      ``total_findings``, ``compliance_gaps``, ``overall_posture``
    """
    import json as _json

    if frameworks is None:
        frameworks = ["NIST_800_53", "OWASP_TOP10"]

    # Accept JSON string as well as list
    if isinstance(findings, str):
        findings = _json.loads(findings)

    # Normalise each finding dict (legacy keys + type aliases)
    findings = [_normalize_finding_dict(f) for f in findings]

    logger.info(
        "Starting compliance audit: %d findings, frameworks=%s",
        len(findings),
        frameworks,
    )

    parsed = [FindingInput(**f) for f in findings]
    normalised_frameworks = [f.upper().replace("-", "_") for f in frameworks]

    mapped_findings: list[dict[str, Any]] = []
    nist_control_ids: set[str] = set()
    owasp_category_ids: set[str] = set()

    for finding in parsed:
        entry: dict[str, Any] = {
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "description": finding.description,
            "affected_component": finding.affected_component,
            "framework_mappings": {},
        }

        if "NIST_800_53" in normalised_frameworks:
            nist_controls = _map_to_nist(finding)
            entry["framework_mappings"]["NIST_800_53"] = {
                "controls": nist_controls,
                "control_ids": [c["id"] for c in nist_controls],
                "mapped": bool(nist_controls),
            }
            nist_control_ids.update(c["id"] for c in nist_controls)

        if "OWASP_TOP10" in normalised_frameworks:
            owasp_cats = _map_to_owasp(finding)
            entry["framework_mappings"]["OWASP_TOP10"] = {
                "categories": owasp_cats,
                "category_ids": [c["id"] for c in owasp_cats],
                "mapped": bool(owasp_cats),
            }
            owasp_category_ids.update(c["id"] for c in owasp_cats)

        mapped_findings.append(entry)

    # Severity breakdown
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in parsed:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    unmapped = [
        f.finding_type
        for f in parsed
        if not any(
            v.get("mapped") is True
            for v in mapped_findings[parsed.index(f)]["framework_mappings"].values()
        )
    ]

    # ── build compliance_gaps (flat, annotated per-finding view) ──
    compliance_gaps: list[dict[str, Any]] = []
    for i, f_input in enumerate(parsed):
        mapped = mapped_findings[i]
        nist_fm = mapped["framework_mappings"].get("NIST_800_53", {})
        owasp_fm = mapped["framework_mappings"].get("OWASP_TOP10", {})

        # Add control_id alias to each NIST control (tests use control_id key)
        nist_controls = [
            {**ctrl, "control_id": ctrl.get("id", "")}
            for ctrl in nist_fm.get("controls", [])
        ]
        # Add risk_id alias to each OWASP category (tests use risk_id key)
        owasp_risks = [
            {**cat, "risk_id": cat.get("id", "")}
            for cat in owasp_fm.get("categories", [])
        ]

        timeline = (
            REMEDIATION_TIMELINES.get(f_input.severity, "90 days")
            if include_remediation_timeline
            else ""
        )

        compliance_gaps.append(
            {
                "finding_type": f_input.finding_type,
                "severity": f_input.severity,
                "description": f_input.description,
                "affected_component": f_input.affected_component,
                "nist_controls": nist_controls,
                "owasp_risks": owasp_risks,
                "compliance_status": _compliance_status(f_input.severity),
                "remediation_timeline": timeline,
            }
        )

    # ── overall posture ───────────────────────────────────────────
    if sev_counts.get("CRITICAL", 0) > 0:
        overall_posture = "CRITICAL_NON_COMPLIANCE"
    elif sev_counts.get("HIGH", 0) > 0:
        overall_posture = "HIGH_RISK_NON_COMPLIANCE"
    elif sev_counts.get("MEDIUM", 0) > 0:
        overall_posture = "PARTIAL_COMPLIANCE"
    else:
        overall_posture = "COMPLIANT"

    report: dict[str, Any] = {
        "scan_type": "Compliance Guardrails Audit",
        "frameworks_evaluated": normalised_frameworks,
        # Top-level convenience keys
        "total_findings": len(parsed),
        "compliance_gaps": compliance_gaps,
        "overall_posture": overall_posture,
        "summary": {
            "total_findings": len(parsed),
            "severity_breakdown": sev_counts,
            "nist_controls_triggered": sorted(nist_control_ids),
            "owasp_categories_triggered": sorted(owasp_category_ids),
            "unmapped_findings": unmapped,
            "compliance_coverage": (
                f"{(len(parsed) - len(unmapped)) / len(parsed) * 100:.0f}%"
                if parsed else "0%"
            ),
        },
        "findings": mapped_findings,
        "executive_summary": _generate_executive_summary(
            parsed, nist_control_ids, owasp_category_ids, sev_counts
        ),
    }

    logger.info(
        "Compliance audit complete: %d NIST controls, %d OWASP categories triggered.",
        len(nist_control_ids),
        len(owasp_category_ids),
    )
    return report


def _generate_executive_summary(
    findings: list[FindingInput],
    nist_ids: set[str],
    owasp_ids: set[str],
    sev: dict[str, int],
) -> str:
    lines = [
        f"Audit identified {len(findings)} security finding(s) across "
        f"{sev.get('CRITICAL', 0)} CRITICAL, {sev.get('HIGH', 0)} HIGH, "
        f"{sev.get('MEDIUM', 0)} MEDIUM, and {sev.get('LOW', 0)} LOW severities.",
    ]
    if nist_ids:
        lines.append(
            f"NIST SP 800-53 controls requiring attention: {', '.join(sorted(nist_ids))}."
        )
    if owasp_ids:
        lines.append(
            f"OWASP Top 10 2021 categories implicated: {', '.join(sorted(owasp_ids))}."
        )
    if sev.get("CRITICAL", 0) > 0:
        lines.append(
            "⚠ CRITICAL findings require immediate remediation before deployment."
        )
    return " ".join(lines)
