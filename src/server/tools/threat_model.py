"""
guardian-ssdlc · tools/threat_model.py
────────────────────────────────────────
STRIDE-based Threat Modelling Engine.

Accepts a JSON architecture descriptor and produces a structured risk
assessment aligned with the STRIDE taxonomy (Spoofing, Tampering,
Repudiation, Information Disclosure, Denial of Service, Elevation of
Privilege).
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("guardian.threat_model")


# ──────────────────────────────────────────────────────────────────
# Input Schema
# ──────────────────────────────────────────────────────────────────

class ComponentModel(BaseModel):
    name: str = Field(..., description="Component display name, e.g. 'API Gateway'.")
    type: str = Field(
        ...,
        description=(
            "Component type: 'web_app', 'api', 'database', 'queue', "
            "'external_service', 'user', 'cdn', 'cache', 'auth_service'."
        ),
    )
    exposes_internet: bool = Field(
        default=False,
        description="True if the component is directly reachable from the internet.",
    )
    handles_pii: bool = Field(
        default=False, description="True if the component processes PII or sensitive data."
    )
    auth_mechanism: str | None = Field(
        default=None,
        description="Authentication mechanism used: 'jwt', 'oauth2', 'api_key', 'mtls', 'none'.",
    )


class DataFlowModel(BaseModel):
    from_component: str = Field(..., description="Source component name.")
    to_component: str = Field(..., description="Destination component name.")
    protocol: str = Field(
        default="HTTPS",
        description="Transport protocol: HTTPS, gRPC, AMQP, TCP, etc.",
    )
    encrypted: bool = Field(default=True, description="Whether the channel is encrypted.")
    authenticated: bool = Field(
        default=True, description="Whether the channel requires authentication."
    )


class SystemArchitectureInput(BaseModel):
    system_name: str = Field(..., description="Name or identifier of the system under review.")
    components: list[ComponentModel] = Field(
        ...,
        min_length=1,
        description="List of architectural components.",
    )
    data_flows: list[DataFlowModel] = Field(
        default_factory=list,
        description="Data flows between components.",
    )
    trust_boundary: str | None = Field(
        default=None,
        description="Description of the primary trust boundary (e.g. 'DMZ → Internal network').",
    )

    @field_validator("components")
    @classmethod
    def validate_components(cls, v: list[ComponentModel]) -> list[ComponentModel]:
        names = [c.name for c in v]
        if len(names) != len(set(names)):
            raise ValueError("Component names must be unique.")
        return v


# ──────────────────────────────────────────────────────────────────
# STRIDE Threat Catalogue
# ──────────────────────────────────────────────────────────────────

STRIDE_CATALOGUE: dict[str, dict[str, Any]] = {
    "Spoofing": {
        "code": "S",
        "description": "An attacker impersonates a user, component, or system identity.",
        "affected_property": "Authentication",
        "triggers": lambda c, _df: (
            c.type in ("api", "web_app", "auth_service")
            or c.exposes_internet
            or c.auth_mechanism in ("none", None)
        ),
        "base_likelihood": "HIGH",
        "mitigations": [
            "Enforce strong authentication (MFA, mutual TLS, OAuth 2.0).",
            "Validate all caller identities at trust boundaries.",
            "Use signed tokens (JWT with RS256 / ES256) and short expiry.",
            "Implement certificate pinning for mobile/embedded clients.",
        ],
    },
    "Tampering": {
        "code": "T",
        "description": "An attacker modifies data in transit or at rest without authorisation.",
        "affected_property": "Integrity",
        "triggers": lambda c, df_list: (
            any(not df.encrypted for df in df_list
                if df.from_component == c.name or df.to_component == c.name)
            or c.type in ("database", "queue", "cache")
        ),
        "base_likelihood": "MEDIUM",
        "mitigations": [
            "Encrypt all data flows with TLS 1.2+ (prefer 1.3).",
            "Apply HMAC or digital signatures to sensitive messages.",
            "Enforce database row-level integrity constraints.",
            "Implement idempotent, signed messages in queuing systems.",
        ],
    },
    "Repudiation": {
        "code": "R",
        "description": "An attacker performs an action and denies having done so.",
        "affected_property": "Non-repudiation",
        "triggers": lambda c, _df: (
            c.type in ("api", "web_app", "auth_service")
            or c.handles_pii
        ),
        "base_likelihood": "MEDIUM",
        "mitigations": [
            "Implement tamper-evident, centralised audit logging.",
            "Capture actor identity, timestamp, and action on all sensitive operations.",
            "Store logs in an immutable, separate log store (e.g. WORM storage).",
            "Apply digital signatures to audit records for non-repudiation guarantees.",
        ],
    },
    "Information Disclosure": {
        "code": "I",
        "description": "Sensitive data is exposed to unauthorised parties.",
        "affected_property": "Confidentiality",
        "triggers": lambda c, _df: (
            c.handles_pii
            or c.exposes_internet
            or c.type in ("database", "cache", "external_service")
        ),
        "base_likelihood": "HIGH",
        "mitigations": [
            "Encrypt sensitive data at rest (AES-256-GCM) and in transit (TLS 1.3).",
            "Apply least-privilege access to data stores.",
            "Sanitise error messages — never expose stack traces to end users.",
            "Mask or tokenise PII in logs, debug output, and API responses.",
        ],
    },
    "Denial of Service": {
        "code": "D",
        "description": "An attacker disrupts the availability of a component or the system.",
        "affected_property": "Availability",
        "triggers": lambda c, _df: (
            c.exposes_internet
            or c.type in ("api", "web_app", "cdn", "queue")
        ),
        "base_likelihood": "MEDIUM",
        "mitigations": [
            "Implement rate limiting and request throttling at the gateway.",
            "Deploy WAF rules to block known DDoS patterns.",
            "Use auto-scaling and circuit-breaker patterns for internal services.",
            "Protect DNS with DNSSEC and use Anycast networks for load distribution.",
        ],
    },
    "Elevation of Privilege": {
        "code": "E",
        "description": "An attacker gains elevated rights beyond what was intended.",
        "affected_property": "Authorisation",
        "triggers": lambda c, _df: (
            c.type in ("api", "web_app", "auth_service", "database")
            or c.auth_mechanism in ("none", "api_key", None)
        ),
        "base_likelihood": "HIGH",
        "mitigations": [
            "Enforce principle of least privilege for all service accounts.",
            "Use attribute-based access control (ABAC) or RBAC consistently.",
            "Validate authorisation on every request — do not trust client-side claims.",
            "Regularly audit permission assignments and remove stale grants.",
        ],
    },
}


# ──────────────────────────────────────────────────────────────────
# Risk Scoring
# ──────────────────────────────────────────────────────────────────

LIKELIHOOD_SCORE: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
IMPACT_SCORE: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _calculate_impact(component: ComponentModel, stride_key: str) -> str:
    score = 1
    if component.handles_pii:
        score += 2
    if component.exposes_internet:
        score += 1
    if stride_key == "Information Disclosure" and component.handles_pii:
        score += 1
    if stride_key == "Denial of Service" and component.exposes_internet:
        score += 1

    if score >= 4:
        return "CRITICAL"
    if score == 3:
        return "HIGH"
    if score == 2:
        return "MEDIUM"
    return "LOW"


def _risk_level(likelihood: str, impact: str) -> str:
    l = LIKELIHOOD_SCORE.get(likelihood, 2)
    i = IMPACT_SCORE.get(impact, 2)
    score = l * i
    if score >= 9:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


# ──────────────────────────────────────────────────────────────────
# Core Logic
# ──────────────────────────────────────────────────────────────────

def generate_threat_model(architecture: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry-point for the threat modelling engine.
    Validates input, evaluates STRIDE per component, and returns a
    structured risk assessment report.
    """
    logger.info("Parsing system architecture for threat modelling.")
    arch = SystemArchitectureInput(**architecture)

    findings: list[dict[str, Any]] = []
    data_flows = arch.data_flows or []

    for component in arch.components:
        for stride_key, meta in STRIDE_CATALOGUE.items():
            trigger_fn = meta["triggers"]
            if trigger_fn(component, data_flows):
                impact = _calculate_impact(component, stride_key)
                likelihood = meta["base_likelihood"]
                # Downgrade likelihood if component is not internet-exposed
                if likelihood == "HIGH" and not component.exposes_internet:
                    likelihood = "MEDIUM"
                risk = _risk_level(likelihood, impact)

                findings.append(
                    {
                        "component": component.name,
                        "component_type": component.type,
                        "stride_category": stride_key,
                        "stride_code": meta["code"],
                        "affected_property": meta["affected_property"],
                        "threat_description": meta["description"],
                        "likelihood": likelihood,
                        "impact": impact,
                        "risk_level": risk,
                        "mitigations": meta["mitigations"],
                        "internet_exposed": component.exposes_internet,
                        "handles_pii": component.handles_pii,
                    }
                )

    # Sort by risk level
    risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda x: risk_order.get(x["risk_level"], 0), reverse=True)

    # Unencrypted flow warnings
    flow_warnings: list[str] = [
        f"⚠ Unencrypted flow: {df.from_component} → {df.to_component} ({df.protocol})"
        for df in data_flows
        if not df.encrypted
    ]

    critical_count = sum(1 for f in findings if f["risk_level"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["risk_level"] == "HIGH")

    report: dict[str, Any] = {
        "scan_type": "STRIDE Threat Model",
        "system": arch.system_name,
        "trust_boundary": arch.trust_boundary,
        "components_analysed": len(arch.components),
        "data_flows_analysed": len(data_flows),
        "summary": {
            "total_threats_identified": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": sum(1 for f in findings if f["risk_level"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["risk_level"] == "LOW"),
            "overall_risk": (
                "CRITICAL" if critical_count > 0
                else "HIGH" if high_count > 0
                else "MEDIUM" if findings
                else "LOW"
            ),
        },
        "threat_findings": findings,
        "data_flow_warnings": flow_warnings,
        "stride_coverage": list(STRIDE_CATALOGUE.keys()),
        "methodology": "STRIDE (Microsoft) + DREAD-lite risk scoring",
    }

    logger.info(
        "Threat model complete: %d threats, overall risk=%s",
        len(findings),
        report["summary"]["overall_risk"],
    )
    return report


# ──────────────────────────────────────────────────────────────────
# Compatibility wrapper — simplified JSON-string interface
# ──────────────────────────────────────────────────────────────────

# Maps risk level → DREAD score (1–10 scale)
_DREAD_MAP: dict[str, int] = {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 2}

# PCI-DSS / GDPR / SOC 2 compliance note templates
_COMPLIANCE_NOTES: dict[str, str] = {
    "PCI": (
        "PCI-DSS requires cardholder data encryption (Req 3), strict access control (Req 7), "
        "network segmentation (Req 1), and regular penetration testing (Req 11)."
    ),
    "GDPR": (
        "GDPR mandates data minimisation, explicit consent management, right-to-erasure "
        "support, and breach notification within 72 hours (Art 33)."
    ),
    "SOC": (
        "SOC 2 Trust Services Criteria require evidence of security, availability, "
        "processing integrity, confidentiality, and privacy controls."
    ),
    "HIPAA": (
        "HIPAA Security Rule requires safeguards for ePHI: access controls (164.312(a)), "
        "audit controls (164.312(b)), and transmission security (164.312(e))."
    ),
    "ISO": (
        "ISO 27001 requires an ISMS with risk assessment (A.6), asset management (A.8), "
        "and incident management (A.16) controls."
    ),
}


def run_threat_model(architecture_json: str) -> dict[str, Any]:
    """
    Simplified entry-point that accepts a JSON string with relaxed field names.

    Differences from generate_threat_model:
    - Input is a JSON *string* (not a dict).
    - Components may use ``exposed_to_internet`` instead of ``exposes_internet``
      and ``authenticated`` (bool) instead of ``auth_mechanism``.
    - All 6 STRIDE categories are generated for *every* component
      (unconditional — suitable for comprehensive risk inventories).
    - Each threat carries a ``dread_score`` (1–10) and ``risk_rating``.
    - Top-level ``total_threats`` and ``compliance_notes`` are returned.
    - Invalid JSON returns ``{"error": "<reason>"}``.
    """
    import json as _json

    # ── parse ─────────────────────────────────────────────────────
    try:
        raw = _json.loads(architecture_json)
    except (ValueError, TypeError) as exc:
        return {"error": f"Invalid JSON: {exc}"}

    system_name: str = raw.get("system_name", "Unknown System")
    compliance_reqs: list[str] = raw.get("compliance_requirements", [])

    # ── adapt and score components ────────────────────────────────
    findings: list[dict[str, Any]] = []

    for raw_comp in raw.get("components", []):
        # Normalise field names from the simplified input format
        auth_raw = raw_comp.get("authenticated")
        if auth_raw is False:
            auth_mechanism: str | None = "none"
        elif auth_raw is True:
            auth_mechanism = "jwt"
        else:
            auth_mechanism = raw_comp.get("auth_mechanism")

        component = ComponentModel(
            name=raw_comp["name"],
            type=raw_comp.get("type", "api"),
            exposes_internet=raw_comp.get(
                "exposed_to_internet", raw_comp.get("exposes_internet", False)
            ),
            handles_pii=raw_comp.get("handles_pii", False),
            auth_mechanism=auth_mechanism,
        )

        for stride_key, meta in STRIDE_CATALOGUE.items():
            impact = _calculate_impact(component, stride_key)
            likelihood = meta["base_likelihood"]
            # Downgrade likelihood for non-internet-exposed components
            if likelihood == "HIGH" and not component.exposes_internet:
                likelihood = "MEDIUM"
            risk = _risk_level(likelihood, impact)
            dread = _DREAD_MAP.get(risk, 5)

            findings.append(
                {
                    "component": component.name,
                    # Format: "S — Spoofing" so callers can split on " — "
                    "stride_category": f"{meta['code']} — {stride_key}",
                    "threat_name": f"{stride_key} — {component.name}",
                    "risk_rating": risk,
                    "dread_score": dread,
                    "impact": impact,
                    "likelihood": likelihood,
                    "description": meta["description"],
                    "mitigations": meta["mitigations"],
                    "internet_exposed": component.exposes_internet,
                    "handles_pii": component.handles_pii,
                }
            )

    # Sort by DREAD score descending so highest-risk threats come first
    findings.sort(key=lambda x: x["dread_score"], reverse=True)

    # ── compliance notes ──────────────────────────────────────────
    compliance_notes: list[str] = []
    for req in compliance_reqs:
        req_upper = req.upper()
        for keyword, note in _COMPLIANCE_NOTES.items():
            if keyword in req_upper and note not in compliance_notes:
                compliance_notes.append(note)

    # ── trust boundary string ─────────────────────────────────────
    trust_boundaries = raw.get("trust_boundaries", [])
    trust_boundary_str: str = (
        " / ".join(trust_boundaries)
        if trust_boundaries
        else raw.get("trust_boundary", "")
    )

    return {
        "scan_type": "STRIDE Threat Model",
        "system": system_name,
        "trust_boundary": trust_boundary_str,
        "total_threats": len(findings),
        "threat_findings": findings,
        "compliance_notes": compliance_notes,
        "methodology": "STRIDE (Microsoft) + DREAD risk scoring",
    }
