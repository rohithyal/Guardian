"""
guardian-ssdlc · server/main.py
────────────────────────────────
FastMCP Server — Guardian S-SDLC Orchestrator

Exposes four security tools over the MCP stdio transport:
  • check_dependencies   — SCA / OSV vulnerability scanning
  • generate_threat_model — STRIDE-based threat modelling
  • audit_compliance     — NIST 800-53 / OWASP Top 10 mapping
  • scan_secrets         — Regex-based credential detection

Run directly:
    python -m src.server.main

Or via the client:
    python -m src.client.consultant
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastmcp import FastMCP
from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler

from src.server.tools.compliance import AuditComplianceInput, run_compliance_audit
from src.server.tools.iac_scanner import ScanIaCInput, run_iac_scan
from src.server.tools.sca import CheckDependenciesInput, run_sca
from src.server.tools.secret_scanner import ScanSecretsInput, run_secret_scan, scan_git_history
from src.server.tools.threat_model import SystemArchitectureInput, generate_threat_model

# ──────────────────────────────────────────────────────────────────
# Logging — Rich handler writes to stderr so it doesn't pollute
# the MCP stdio transport on stdout.
# ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=Console(stderr=True),
            rich_tracebacks=True,
            markup=True,
            show_path=False,
        )
    ],
)
logger = logging.getLogger("guardian.server")

# ──────────────────────────────────────────────────────────────────
# FastMCP Application
# ──────────────────────────────────────────────────────────────────
mcp = FastMCP(name="Guardian S-SDLC Orchestrator")


# ──────────────────────────────────────────────────────────────────
# Tool 1: Software Composition Analysis
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="check_dependencies",
    description=(
        "Performs Software Composition Analysis (SCA) on a requirements.txt or "
        "package.json manifest. Queries the OSV vulnerability database to identify "
        "CVEs in third-party dependencies. Returns a structured risk report with "
        "affected packages, CVSS scores, and remediation priorities."
    ),
)
def check_dependencies(manifest_path: str) -> dict[str, Any]:
    """
    Args:
        manifest_path: Path to requirements.txt or package.json.
                       Use 'CONTENT:<raw_text>' for inline scanning.

    Returns:
        Structured SCA report with vulnerable packages, CVSS data, and
        remediation recommendations.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] check_dependencies")
    try:
        validated = CheckDependenciesInput(manifest_path=manifest_path)
        return run_sca(validated.manifest_path)
    except ValidationError as exc:
        logger.error("Validation error in check_dependencies: %s", exc)
        return {"error": "Input validation failed", "details": exc.errors()}
    except Exception as exc:
        logger.exception("Unexpected error in check_dependencies")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Tool 2: Threat Modelling Engine
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="generate_threat_model",
    description=(
        "Generates a STRIDE-based threat model from a JSON system architecture "
        "descriptor. Analyses components, data flows, and trust boundaries to "
        "identify Spoofing, Tampering, Repudiation, Information Disclosure, "
        "Denial of Service, and Elevation of Privilege risks. Returns a "
        "prioritised risk assessment with DREAD-lite scoring and mitigations."
    ),
)
def generate_threat_model_tool(architecture: str) -> dict[str, Any]:
    """
    Args:
        architecture: JSON string describing the system. Must contain:
                      - system_name (str)
                      - components (list of {name, type, exposes_internet,
                                             handles_pii, auth_mechanism})
                      - data_flows (optional list of {from_component, to_component,
                                                      protocol, encrypted, authenticated})
                      - trust_boundary (optional str)

    Returns:
        STRIDE threat model with per-component risks and mitigations.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] generate_threat_model")
    try:
        arch_dict: dict[str, Any] = (
            json.loads(architecture) if isinstance(architecture, str) else architecture
        )
        validated = SystemArchitectureInput(**arch_dict)
        return generate_threat_model(validated.model_dump())
    except (json.JSONDecodeError, TypeError) as exc:
        logger.error("JSON parsing error: %s", exc)
        return {"error": "Invalid JSON in architecture parameter", "details": str(exc)}
    except ValidationError as exc:
        logger.error("Validation error in generate_threat_model: %s", exc)
        return {"error": "Input validation failed", "details": exc.errors()}
    except Exception as exc:
        logger.exception("Unexpected error in generate_threat_model")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Tool 3: Compliance Guardrails
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="audit_compliance",
    description=(
        "Maps a list of security findings to NIST SP 800-53 Rev 5 controls and "
        "OWASP Top 10 2021 categories. Produces a compliance gap report showing "
        "which regulatory controls are triggered by the identified vulnerabilities, "
        "enabling evidence-based remediation planning and audit preparation."
    ),
)
def audit_compliance(findings: str, frameworks: str = "NIST_800_53,OWASP_TOP10") -> dict[str, Any]:
    """
    Args:
        findings: JSON array of finding objects. Each object: {
                    "finding_type": str,  # e.g. "known_cve", "hardcoded_secret"
                    "severity": str,      # CRITICAL | HIGH | MEDIUM | LOW
                    "description": str,
                    "affected_component": str  # optional
                  }
        frameworks: Comma-separated list of frameworks to evaluate.
                    Supported: NIST_800_53, OWASP_TOP10

    Returns:
        Compliance gap report with control mappings, executive summary,
        and severity breakdown per framework.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] audit_compliance")
    try:
        findings_list: list[dict[str, Any]] = (
            json.loads(findings) if isinstance(findings, str) else findings
        )
        fw_list = [f.strip() for f in frameworks.split(",") if f.strip()]
        validated = AuditComplianceInput(findings=findings_list, frameworks=fw_list)
        return run_compliance_audit(
            [f.model_dump() for f in validated.findings],
            list(validated.frameworks),
        )
    except (json.JSONDecodeError, TypeError) as exc:
        logger.error("JSON parsing error: %s", exc)
        return {"error": "Invalid JSON in findings parameter", "details": str(exc)}
    except ValidationError as exc:
        logger.error("Validation error in audit_compliance: %s", exc)
        return {"error": "Input validation failed", "details": exc.errors()}
    except Exception as exc:
        logger.exception("Unexpected error in audit_compliance")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Tool 4: Secret Scanner
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="scan_secrets",
    description=(
        "Scans a directory or inline code for hardcoded secrets using an extensible "
        "regex pattern library. Detects AWS keys, GitHub tokens, API keys, passwords, "
        "private keys, database connection strings, JWT tokens, Stripe/Slack/Twilio "
        "credentials, and more. Redacts findings in the report to avoid credential "
        "propagation. Returns file locations, line numbers, and remediation steps."
    ),
)
def scan_secrets(
    target: str,
    include_extensions: str = "",
    max_findings_per_file: int = 20,
    output_format: str = "json",
) -> dict[str, Any]:
    """
    Args:
        target: Directory path, single file path, or 'CONTENT:<code>' for inline scan.
        include_extensions: Comma-separated extension whitelist (e.g. '.py,.js,.env').
                            Empty string = scan all supported file types.
        max_findings_per_file: Cap on findings per file (default 20).
        output_format: 'json' (default) or 'sarif' for SARIF 2.1.0 output
                       compatible with GitHub Code Scanning and IDE extensions.

    Returns:
        Secret scan report with redacted findings, severity breakdown,
        affected file list, and remediation recommendations.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] scan_secrets")
    try:
        ext_list = (
            [e.strip() for e in include_extensions.split(",") if e.strip()]
            if include_extensions
            else None
        )
        validated = ScanSecretsInput(
            target=target,
            include_extensions=ext_list,
            max_findings_per_file=max_findings_per_file,
        )
        return run_secret_scan(
            target=validated.target,
            include_extensions=validated.include_extensions,
            max_findings_per_file=validated.max_findings_per_file,
            output_format=output_format,
        )
    except ValidationError as exc:
        logger.error("Validation error in scan_secrets: %s", exc)
        return {"error": "Input validation failed", "details": exc.errors()}
    except Exception as exc:
        logger.exception("Unexpected error in scan_secrets")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Tool 5: Git History Secret Scanner
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="scan_git_history",
    description=(
        "Scans the full git commit history of a repository for secrets that were "
        "committed and later removed. Uses 'git log -p' to replay every added line "
        "through the same 16-pattern regex engine as scan_secrets. Reports findings "
        "by commit hash, author, date, and file path — essential for confirming "
        "whether a credential was ever exposed even if it no longer appears in HEAD."
    ),
)
def scan_git_history_tool(
    repo_path: str,
    max_commits: int = 500,
) -> dict[str, Any]:
    """
    Args:
        repo_path: Absolute or relative path to the root of a git repository.
        max_commits: Maximum number of commits to inspect (default 500).
                     Increase for deep history audits; reduce for speed.

    Returns:
        Report with findings keyed by commit hash, author, date, file path,
        and severity. Includes remediation steps for purging secrets from history.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] scan_git_history")
    try:
        return scan_git_history(repo_path=repo_path, max_commits=max_commits)
    except Exception as exc:
        logger.exception("Unexpected error in scan_git_history")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Tool 6: IaC Misconfiguration Scanner
# ──────────────────────────────────────────────────────────────────


@mcp.tool(
    name="scan_iac",
    description=(
        "Scans Dockerfiles and docker-compose files for security misconfigurations. "
        "Detects 17 classes of risk across 9 Dockerfile rules (running as root, "
        "floating image tags, curl-pipe-bash, ADD vs COPY, apt-get recommends, "
        "secrets in ENV/ARG, chmod 777, missing HEALTHCHECK, sudo) and 8 "
        "docker-compose rules (privileged mode, host networking, Docker socket "
        "mount, sensitive host path mounts, all-interface port bindings, missing "
        "resource limits, cap_add ALL, missing no-new-privileges). Returns a "
        "structured report with rule IDs, severities, file locations, and "
        "remediation steps."
    ),
)
def scan_iac(target: str) -> dict[str, Any]:
    """
    Args:
        target: Directory to scan recursively, or path to a single
                Dockerfile / docker-compose.yml file.

    Returns:
        IaC misconfiguration report with per-finding rule IDs, severities,
        file locations, and remediation recommendations.
    """
    logger.info("[bold cyan]Tool invoked:[/bold cyan] scan_iac")
    try:
        validated = ScanIaCInput(target=target)
        return run_iac_scan(validated.target)
    except ValidationError as exc:
        logger.error("Validation error in scan_iac: %s", exc)
        return {"error": "Input validation failed", "details": exc.errors()}
    except Exception as exc:
        logger.exception("Unexpected error in scan_iac")
        return {"error": str(exc)}


# ──────────────────────────────────────────────────────────────────
# Entry-point
# ──────────────────────────────────────────────────────────────────


def main() -> None:
    logger.info(
        "[bold green]Guardian S-SDLC Orchestrator[/bold green] starting on stdio transport."
    )
    logger.info(
        "Registered tools: check_dependencies, generate_threat_model, audit_compliance, "
        "scan_secrets, scan_git_history, scan_iac"
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
