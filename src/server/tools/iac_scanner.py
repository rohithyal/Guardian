"""
guardian-ssdlc · tools/iac_scanner.py
──────────────────────────────────────
Infrastructure-as-Code (IaC) Misconfiguration Scanner.

Scans Dockerfiles and docker-compose.yml files for security
misconfigurations. Returns structured findings with rule IDs,
severity, line numbers, and remediation steps.

Supported file types:
  • Dockerfile (and files named Dockerfile.*)
  • docker-compose.yml / docker-compose.yaml / compose.yml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from src.utils.helpers import SECRET_PATTERNS, severity_rank

logger = logging.getLogger("guardian.iac_scanner")

# ──────────────────────────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────────────────────────


@dataclass
class IaCRule:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    remediation: str


# ── Dockerfile rules ──────────────────────────────────────────────

DOCKERFILE_RULES: list[IaCRule] = [
    IaCRule(
        rule_id="IAC-D001",
        severity="HIGH",
        title="Container runs as root",
        description=(
            "No USER instruction found. The container will run all processes as "
            "root (uid 0). If an attacker escapes the container, they have root "
            "on the host."
        ),
        remediation=(
            "Add 'RUN groupadd -g 1001 app && useradd -u 1001 -g app app' "
            "then 'USER app' before the final CMD/ENTRYPOINT."
        ),
    ),
    IaCRule(
        rule_id="IAC-D002",
        severity="MEDIUM",
        title="Base image uses floating 'latest' tag",
        description=(
            "FROM uses the 'latest' tag or no tag. The image pulled on each "
            "build can change silently, making builds non-reproducible and "
            "potentially pulling a compromised image."
        ),
        remediation=(
            "Pin to a specific version: 'FROM python:3.11.9-slim' or "
            "a digest 'FROM python@sha256:<hash>'."
        ),
    ),
    IaCRule(
        rule_id="IAC-D003",
        severity="HIGH",
        title="Script execution via curl/wget pipe",
        description=(
            "A RUN instruction pipes a remote script directly into a shell "
            "(curl | bash or wget | sh). This pattern runs arbitrary code from "
            "the internet without verification and cannot be audited."
        ),
        remediation=(
            "Download the script separately, verify its checksum "
            "(sha256sum), then execute. Never pipe remote content into a shell."
        ),
    ),
    IaCRule(
        rule_id="IAC-D004",
        severity="MEDIUM",
        title="ADD used instead of COPY",
        description=(
            "ADD can fetch remote URLs and auto-extract archives, expanding "
            "the attack surface unnecessarily. COPY is explicit and does "
            "exactly what it says."
        ),
        remediation=(
            "Replace ADD with COPY for local files. Use a dedicated RUN "
            "curl + checksum step if you need remote content."
        ),
    ),
    IaCRule(
        rule_id="IAC-D005",
        severity="MEDIUM",
        title="apt-get install without --no-install-recommends",
        description=(
            "apt-get install without --no-install-recommends pulls in "
            "suggested packages that increase image size and attack surface."
        ),
        remediation="Add --no-install-recommends to every apt-get install call.",
    ),
    IaCRule(
        rule_id="IAC-D006",
        severity="HIGH",
        title="Potential secret in ENV or ARG",
        description=(
            "An ENV or ARG instruction contains a value that matches a known "
            "secret pattern. Secrets baked into image layers are readable by "
            "anyone with access to the image."
        ),
        remediation=(
            "Remove the secret from the Dockerfile. Pass secrets at runtime "
            "via --secret, environment variables, or a secrets manager. "
            "Never store credentials in image layers."
        ),
    ),
    IaCRule(
        rule_id="IAC-D007",
        severity="HIGH",
        title="World-writable permissions set with chmod 777",
        description=(
            "chmod 777 makes files writable by any user inside the container. "
            "Combined with a path traversal or file write vulnerability, this "
            "allows privilege escalation."
        ),
        remediation=(
            "Use the minimum necessary permissions. Prefer 755 for executables "
            "and 644 for data files. Avoid 777 entirely."
        ),
    ),
    IaCRule(
        rule_id="IAC-D008",
        severity="LOW",
        title="No HEALTHCHECK defined",
        description=(
            "Without a HEALTHCHECK, container orchestrators cannot detect "
            "a hung process and will continue routing traffic to it."
        ),
        remediation=(
            "Add 'HEALTHCHECK --interval=30s --timeout=10s CMD <command>' "
            "that verifies the application is responding."
        ),
    ),
    IaCRule(
        rule_id="IAC-D009",
        severity="HIGH",
        title="sudo installed or invoked",
        description=(
            "Installing or using sudo in a container defeats the purpose of "
            "running as a non-root user and can be exploited to regain root."
        ),
        remediation=(
            "Design the image so the application user has the exact permissions "
            "it needs via chown/chmod during build, not sudo at runtime."
        ),
    ),
]

# ── docker-compose rules ──────────────────────────────────────────

COMPOSE_RULES: list[IaCRule] = [
    IaCRule(
        rule_id="IAC-C001",
        severity="CRITICAL",
        title="Privileged container enabled",
        description=(
            "'privileged: true' gives the container almost all Linux kernel "
            "capabilities. A compromised process can trivially escape to the "
            "host kernel."
        ),
        remediation=(
            "Remove 'privileged: true'. Use 'cap_add' to grant only the "
            "specific capabilities the container actually needs."
        ),
    ),
    IaCRule(
        rule_id="IAC-C002",
        severity="HIGH",
        title="Host network mode enabled",
        description=(
            "'network_mode: host' removes network isolation. The container "
            "shares the host's network stack and can access any host port "
            "or listen on privileged ports."
        ),
        remediation=(
            "Use the default bridge network and expose only the ports the "
            "service requires. Reserve host networking for performance-critical "
            "infrastructure where isolation is consciously sacrificed."
        ),
    ),
    IaCRule(
        rule_id="IAC-C003",
        severity="CRITICAL",
        title="Docker socket mounted inside container",
        description=(
            "Mounting /var/run/docker.sock gives the container full control "
            "over the Docker daemon — equivalent to unrestricted root on the "
            "host. This is a trivial container escape."
        ),
        remediation=(
            "Remove the Docker socket volume. If the container genuinely needs "
            "to manage other containers, use a rootless Docker alternative or "
            "a dedicated privileged sidecar with tightly scoped access."
        ),
    ),
    IaCRule(
        rule_id="IAC-C004",
        severity="HIGH",
        title="Sensitive host path mounted",
        description=(
            "A volume mounts a sensitive host path (/etc, /proc, /sys, /root, "
            "/home, or /boot). This exposes host filesystem contents to the "
            "container, enabling credential theft or configuration tampering."
        ),
        remediation=(
            "Mount only specific application data directories. Never mount "
            "system directories from the host into containers."
        ),
    ),
    IaCRule(
        rule_id="IAC-C005",
        severity="MEDIUM",
        title="Port bound to all interfaces (0.0.0.0)",
        description=(
            "A port mapping binds to 0.0.0.0, exposing the service on every "
            "network interface including external ones. Services intended for "
            "internal use become reachable from outside."
        ),
        remediation=(
            "Bind to a specific interface: '127.0.0.1:8080:8080' for "
            "localhost-only, or use an ingress proxy and avoid direct host "
            "port bindings for internal services."
        ),
    ),
    IaCRule(
        rule_id="IAC-C006",
        severity="MEDIUM",
        title="No resource limits defined",
        description=(
            "No memory or CPU limits are set. A compromised or misbehaving "
            "container can consume all host resources, causing a denial of "
            "service for other workloads."
        ),
        remediation=(
            "Add a 'deploy.resources.limits' block (Compose v3) or top-level "
            "'mem_limit' and 'cpus' fields to cap resource consumption."
        ),
    ),
    IaCRule(
        rule_id="IAC-C007",
        severity="HIGH",
        title="ALL Linux capabilities added",
        description=(
            "'cap_add: [ALL]' grants every Linux kernel capability, equivalent "
            "to running privileged. An attacker with code execution can "
            "immediately escalate to host root."
        ),
        remediation=(
            "Remove 'ALL' and add only the specific capabilities required "
            "(e.g., NET_BIND_SERVICE to bind privileged ports)."
        ),
    ),
    IaCRule(
        rule_id="IAC-C008",
        severity="MEDIUM",
        title="no-new-privileges not set",
        description=(
            "'security_opt: [no-new-privileges:true]' is not set. Without it, "
            "processes inside the container can gain additional privileges "
            "via setuid binaries."
        ),
        remediation=(
            "Add 'security_opt: [no-new-privileges:true]' to every service "
            "that does not explicitly require privilege escalation."
        ),
    ),
]

_RULE_MAP: dict[str, IaCRule] = {r.rule_id: r for r in DOCKERFILE_RULES + COMPOSE_RULES}

# Sensitive host paths that should never be mounted in containers
_SENSITIVE_MOUNTS = re.compile(r"^(/etc|/proc|/sys|/root|/home|/boot|/var/run/docker\.sock)(/|$)")

# Port binding pattern: "host_ip:host_port:container_port" or "host_port:container_port"
_ALLIF_PORT = re.compile(r"^(0\.0\.0\.0:)?\d+:\d+")


# ──────────────────────────────────────────────────────────────────
# Input Schema
# ──────────────────────────────────────────────────────────────────


class ScanIaCInput(BaseModel):
    target: str = Field(
        ...,
        description=(
            "Directory to scan recursively, or path to a single "
            "Dockerfile / docker-compose.yml file."
        ),
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        p = Path(v)
        if not p.exists():
            raise ValueError(f"Target not found: {v}")
        return v


# ──────────────────────────────────────────────────────────────────
# Dockerfile scanner
# ──────────────────────────────────────────────────────────────────


def _scan_dockerfile(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return findings

    has_user = False
    has_healthcheck = False

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        upper = line.upper()

        # Track presence of USER and HEALTHCHECK (whole-file rules)
        if re.match(r"^USER\s+", line, re.IGNORECASE):
            # Only counts if it's not USER root / USER 0
            user_val = line.split(None, 1)[1].strip() if len(line.split()) > 1 else ""
            if user_val.lower() not in ("root", "0"):
                has_user = True
        if upper.startswith("HEALTHCHECK"):
            has_healthcheck = True

        # IAC-D002: floating latest tag on FROM
        if re.match(r"^FROM\s+", line, re.IGNORECASE):
            # Extract image reference (ignore AS alias)
            parts = re.split(r"\s+AS\s+", line, flags=re.IGNORECASE)
            image_ref = parts[0].split(None, 1)[1].strip() if len(parts[0].split()) > 1 else ""
            # Floating if no tag + digest, or tag == latest
            if (
                image_ref
                and ":" not in image_ref
                and "@" not in image_ref
                or re.search(r":latest\s*$", image_ref, re.IGNORECASE)
            ):
                findings.append(_make_finding("IAC-D002", str(path), lineno, raw.strip()))

        # IAC-D003: curl | bash / wget | sh
        if upper.startswith("RUN"):
            if re.search(r"(curl|wget).+\|\s*(ba)?sh", line, re.IGNORECASE):
                findings.append(_make_finding("IAC-D003", str(path), lineno, raw.strip()))

            # IAC-D005: apt-get install without --no-install-recommends
            if (
                re.search(r"apt-get\s+install\b", line, re.IGNORECASE)
                and "--no-install-recommends" not in line
            ):
                findings.append(_make_finding("IAC-D005", str(path), lineno, raw.strip()))

            # IAC-D007: chmod 777
            if re.search(r"chmod\s+777", line):
                findings.append(_make_finding("IAC-D007", str(path), lineno, raw.strip()))

            # IAC-D009: sudo
            if re.search(r"\bsudo\b", line):
                findings.append(_make_finding("IAC-D009", str(path), lineno, raw.strip()))

        # IAC-D004: ADD (not COPY)
        if re.match(r"^ADD\s+", line, re.IGNORECASE):
            # Ignore if it's fetching from a URL (intentional use of ADD)
            src = line.split(None, 1)[1].strip().split()[0] if len(line.split()) > 1 else ""
            if not src.startswith(("http://", "https://")):
                findings.append(_make_finding("IAC-D004", str(path), lineno, raw.strip()))

        # IAC-D006: secrets in ENV or ARG
        if re.match(r"^(ENV|ARG)\s+", line, re.IGNORECASE):
            for _label, pattern, _sev, _desc in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(_make_finding("IAC-D006", str(path), lineno, raw.strip()))
                    break

    # Whole-file rules
    if not has_user:
        findings.append(_make_finding("IAC-D001", str(path), None, None))
    if not has_healthcheck:
        findings.append(_make_finding("IAC-D008", str(path), None, None))

    return findings


# ──────────────────────────────────────────────────────────────────
# docker-compose scanner
# ──────────────────────────────────────────────────────────────────


def _scan_compose(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(raw_text)
    except Exception as exc:
        logger.warning("Cannot parse %s: %s", path, exc)
        return findings

    if not isinstance(data, dict):
        return findings

    services = data.get("services", {}) or {}
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        svc_label = f"{path}:{svc_name}"

        # IAC-C001: privileged
        if svc.get("privileged") is True:
            findings.append(_make_finding("IAC-C001", svc_label, None, None))

        # IAC-C002: network_mode host
        if svc.get("network_mode", "").lower() == "host":
            findings.append(_make_finding("IAC-C002", svc_label, None, None))

        # IAC-C003 / IAC-C004: volume mounts
        volumes = svc.get("volumes", []) or []
        for vol in volumes:
            src = str(vol).split(":")[0] if ":" in str(vol) else str(vol)
            src = src.strip()
            if src == "/var/run/docker.sock":
                findings.append(_make_finding("IAC-C003", svc_label, None, str(vol)))
            elif _SENSITIVE_MOUNTS.match(src):
                findings.append(_make_finding("IAC-C004", svc_label, None, str(vol)))

        # IAC-C005: ports bound to 0.0.0.0
        ports = svc.get("ports", []) or []
        for port in ports:
            port_str = str(port)
            # Flag if explicitly 0.0.0.0 or bare port mapping (implicitly all interfaces)
            if (
                "0.0.0.0" in port_str or _ALLIF_PORT.match(port_str)
            ) and "127.0.0.1" not in port_str:
                findings.append(_make_finding("IAC-C005", svc_label, None, port_str))

        # IAC-C006: no resource limits
        deploy = svc.get("deploy", {}) or {}
        resources = deploy.get("resources", {}) or {}
        has_limits = bool(resources.get("limits"))
        # Also check legacy top-level mem_limit / cpus
        has_legacy = svc.get("mem_limit") or svc.get("cpus")
        if not has_limits and not has_legacy:
            findings.append(_make_finding("IAC-C006", svc_label, None, None))

        # IAC-C007: cap_add ALL
        cap_add = svc.get("cap_add", []) or []
        if "ALL" in [str(c).upper() for c in cap_add]:
            findings.append(_make_finding("IAC-C007", svc_label, None, None))

        # IAC-C008: no-new-privileges missing
        security_opt = [str(s).lower() for s in (svc.get("security_opt", []) or [])]
        if not any("no-new-privileges" in s for s in security_opt):
            findings.append(_make_finding("IAC-C008", svc_label, None, None))

    return findings


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────


def _make_finding(
    rule_id: str,
    location: str,
    line: int | None,
    snippet: str | None,
) -> dict[str, Any]:
    rule = _RULE_MAP[rule_id]
    return {
        "rule_id": rule_id,
        "severity": rule.severity,
        "title": rule.title,
        "description": rule.description,
        "remediation": rule.remediation,
        "file": location,
        "line": line,
        "snippet": snippet,
    }


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.")


def _is_compose(path: Path) -> bool:
    name = path.name.lower()
    return name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def _collect_iac_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files: list[Path] = []
    for p in sorted(target.rglob("*")):
        if p.is_file() and (_is_dockerfile(p) or _is_compose(p)):
            # Skip hidden dirs and common noise dirs
            if any(
                part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv")
                for part in p.parts
            ):
                continue
            files.append(p)
    return files


# ──────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────


def run_iac_scan(target: str) -> dict[str, Any]:
    """
    Scan Dockerfiles and docker-compose files for security misconfigurations.
    Returns a structured report consistent with other Guardian tool outputs.
    """
    logger.info("Starting IaC scan: %s", target)
    p = Path(target)
    iac_files = _collect_iac_files(p)

    all_findings: list[dict[str, Any]] = []
    files_scanned: list[str] = []

    for f in iac_files:
        files_scanned.append(str(f))
        if _is_dockerfile(f):
            all_findings.extend(_scan_dockerfile(f))
        elif _is_compose(f):
            all_findings.extend(_scan_compose(f))

    # Sort by severity then file
    all_findings.sort(
        key=lambda x: (severity_rank(x["severity"]), x["file"]),
        reverse=True,
    )

    severity_breakdown: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1

    critical = severity_breakdown["CRITICAL"]
    high = severity_breakdown["HIGH"]
    risk_rating = (
        "CRITICAL"
        if critical > 0
        else "HIGH"
        if high > 0
        else "MEDIUM"
        if severity_breakdown["MEDIUM"] > 0
        else "LOW"
    )

    report: dict[str, Any] = {
        "scan_type": "IaC Misconfiguration Scanner",
        "target": target,
        "summary": {
            "files_scanned": len(files_scanned),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_breakdown,
            "risk_rating": risk_rating,
        },
        "files_scanned": files_scanned,
        "findings": all_findings,
        "rules_evaluated": {
            "dockerfile": [r.rule_id for r in DOCKERFILE_RULES],
            "compose": [r.rule_id for r in COMPOSE_RULES],
        },
        "remediation_priority": [
            f"[{f['rule_id']}] {f['title']} — {f['file']}"
            for f in all_findings
            if f["severity"] in ("CRITICAL", "HIGH")
        ][:10],
    }

    logger.info(
        "IaC scan complete: %d files, %d findings, risk=%s",
        len(files_scanned),
        len(all_findings),
        risk_rating,
    )
    return report
