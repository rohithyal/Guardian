"""
guardian-ssdlc · utils/helpers.py
──────────────────────────────────
Shared utilities: regex secret-detection patterns, OSV mock database,
and helper functions used across server tools.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

# ──────────────────────────────────────────────────────────────────
# 1. SECRET-DETECTION REGEX PATTERNS
# ──────────────────────────────────────────────────────────────────
# Each entry: (label, compiled_regex, severity, description)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "CRITICAL",
        "Amazon Web Services Access Key — grants AWS API access.",
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "CRITICAL",
        "Amazon Web Services Secret Key — used to sign API requests.",
    ),
    (
        "Generic API Key",
        re.compile(r"(?i)(api[_\-\s]?key|apikey)['\"\s:=]+([A-Za-z0-9_\-]{20,64})"),
        "HIGH",
        "Generic API key pattern detected in source.",
    ),
    (
        "Generic Secret / Password",
        re.compile(r"(?i)(secret|password|passwd|pwd|token)['\"\s:=]+['\"]([^'\"]{8,64})['\"]"),
        "HIGH",
        "Generic secret or password assignment detected.",
    ),
    (
        "RSA Private Key Header",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "CRITICAL",
        "PEM private key block detected — never commit private keys.",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "CRITICAL",
        "GitHub Personal Access Token with repo/org scope.",
    ),
    (
        "GitHub OAuth Token",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        "HIGH",
        "GitHub OAuth access token.",
    ),
    (
        "Slack Bot Token",
        re.compile(r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}"),
        "HIGH",
        "Slack Bot token — allows posting as bot.",
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "MEDIUM",
        "Slack Incoming Webhook URL.",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),
        "HIGH",
        "Google API key — may grant access to GCP/Firebase services.",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
        "CRITICAL",
        "Stripe secret API key — grants full payment access.",
    ),
    (
        "Stripe Publishable Key",
        re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"),
        "MEDIUM",
        "Stripe publishable key (lower risk but should not be hardcoded).",
    ),
    (
        "Twilio Account SID",
        re.compile(r"AC[a-z0-9]{32}"),
        "HIGH",
        "Twilio Account SID.",
    ),
    (
        "Bearer / Authorization Header Value",
        re.compile(r"(?i)(Authorization|Bearer)['\"\s:=]+['\"]?Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
        "HIGH",
        "Hardcoded HTTP Authorization/Bearer token.",
    ),
    (
        "Database Connection String",
        re.compile(
            r"(?i)(postgres(?:ql)?|mysql|mongodb|redis|sqlite)://[^:'\"\s@]{1,64}:[^@'\"\s]{1,128}@[^'\"\s]{4,}"
        ),
        "HIGH",
        "Database connection string with embedded credentials.",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "MEDIUM",
        "JSON Web Token (JWT) hardcoded — may expose session or signing secrets.",
    ),
]

# Files and directories to skip during secret scanning
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
    }
)

SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".zip",
        ".tar",
        ".gz",
        ".lock",
        ".pyc",
        ".pyo",
        ".so",
        ".dylib",
        ".dll",
        ".pdf",
        ".docx",
        ".xlsx",
    }
)

# ──────────────────────────────────────────────────────────────────
# 2. OSV MOCK DATABASE
# ──────────────────────────────────────────────────────────────────
# Mirrors the structure of a real OSV API response (https://osv.dev).
# In a production system, replace this with live calls to:
#   POST https://api.osv.dev/v1/query  {"package": {"name": name, "ecosystem": eco}}

OSV_MOCK_DB: dict[str, list[dict[str, Any]]] = {
    # ── Python packages ──────────────────────────────────────────
    "requests": [
        {
            "id": "GHSA-j8r2-6x86-q33q",
            "aliases": ["CVE-2023-32681"],
            "summary": "Unintended leak of Proxy-Authorization header",
            "severity": "MEDIUM",
            "cvss_score": 6.1,
            "affected_versions": "<2.31.0",
            "fixed_version": "2.31.0",
            "published": "2023-05-26",
            "references": [
                "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"
            ],
        }
    ],
    "urllib3": [
        {
            "id": "GHSA-g4mx-q9vg-27p4",
            "aliases": ["CVE-2023-43804"],
            "summary": "urllib3 doesn't treat the Cookie HTTP header as sensitive",
            "severity": "MEDIUM",
            "cvss_score": 5.9,
            "affected_versions": "<1.26.17 || >=2.0.0,<2.0.6",
            "fixed_version": "1.26.17 / 2.0.6",
            "published": "2023-10-02",
            "references": [
                "https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4"
            ],
        }
    ],
    "cryptography": [
        {
            "id": "GHSA-jm77-qphf-c4w8",
            "aliases": ["CVE-2023-49083"],
            "summary": "Null pointer dereference when loading PKCS12 files",
            "severity": "MEDIUM",
            "cvss_score": 4.0,
            "affected_versions": "<41.0.6",
            "fixed_version": "41.0.6",
            "published": "2023-11-29",
            "references": [
                "https://github.com/pypa/advisory-database/tree/main/vulns/cryptography"
            ],
        }
    ],
    "pillow": [
        {
            "id": "GHSA-44wm-f244-xhp3",
            "aliases": ["CVE-2023-44271"],
            "summary": "Uncontrolled resource consumption in PIL ImageFont",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": "<10.0.1",
            "fixed_version": "10.0.1",
            "published": "2023-11-03",
            "references": [
                "https://github.com/python-pillow/Pillow/security/advisories/GHSA-44wm-f244-xhp3"
            ],
        }
    ],
    "paramiko": [
        {
            "id": "GHSA-c35q-ffpf-5qpm",
            "aliases": ["CVE-2023-48795"],
            "summary": "Prefix Truncation Attack on Binary Packet Protocol (Terrapin)",
            "severity": "MEDIUM",
            "cvss_score": 5.9,
            "affected_versions": "<3.4.0",
            "fixed_version": "3.4.0",
            "published": "2023-12-18",
            "references": ["https://github.com/paramiko/paramiko/issues/2337"],
        }
    ],
    "django": [
        {
            "id": "GHSA-qmf9-6jqf-j8fq",
            "aliases": ["CVE-2024-27351"],
            "summary": "Potential regular expression denial-of-service in django.utils.text.Truncator",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "affected_versions": ">=4.2,<4.2.11 || >=5.0,<5.0.3",
            "fixed_version": "4.2.11 / 5.0.3",
            "published": "2024-03-04",
            "references": ["https://www.djangoproject.com/weblog/2024/mar/04/security-releases/"],
        }
    ],
    "flask": [
        {
            "id": "GHSA-m2qf-hxjv-5gpq",
            "aliases": ["CVE-2023-30861"],
            "summary": "Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary header",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": "<2.3.2 || >=2.2.0,<2.2.5",
            "fixed_version": "2.3.2 / 2.2.5",
            "published": "2023-05-01",
            "references": [
                "https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq"
            ],
        }
    ],
    "pyyaml": [
        {
            "id": "GHSA-8q59-q68h-6hv4",
            "aliases": ["CVE-2020-14343"],
            "summary": "Arbitrary code execution via crafted YAML in PyYAML",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_versions": "<5.4",
            "fixed_version": "5.4",
            "published": "2021-02-09",
            "references": ["https://github.com/yaml/pyyaml/pull/539"],
        }
    ],
    # ── Node.js packages ─────────────────────────────────────────
    "lodash": [
        {
            "id": "GHSA-jf85-cpcp-j695",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "severity": "HIGH",
            "cvss_score": 7.2,
            "affected_versions": "<4.17.21",
            "fixed_version": "4.17.21",
            "published": "2021-02-15",
            "references": ["https://github.com/lodash/lodash/blob/master/CHANGELOG.md"],
        }
    ],
    "axios": [
        {
            "id": "GHSA-wf5p-g6vw-rhxx",
            "aliases": ["CVE-2023-45857"],
            "summary": "Axios Cross-Site Request Forgery Vulnerability",
            "severity": "MEDIUM",
            "cvss_score": 6.5,
            "affected_versions": ">=0.8.1,<=1.5.1",
            "fixed_version": "1.6.0",
            "published": "2023-11-08",
            "references": ["https://github.com/axios/axios/issues/6006"],
        }
    ],
    "minimist": [
        {
            "id": "GHSA-vh95-rmgr-6w4m",
            "aliases": ["CVE-2021-44906"],
            "summary": "Prototype Pollution in minimist",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_versions": "<0.2.4 || >=1.0.0,<1.2.6",
            "fixed_version": "0.2.4 / 1.2.6",
            "published": "2022-03-17",
            "references": ["https://github.com/advisories/GHSA-vh95-rmgr-6w4m"],
        }
    ],
    "express": [
        {
            "id": "GHSA-rv95-896h-c2vc",
            "aliases": ["CVE-2022-24999"],
            "summary": "qs vulnerable to Prototype Pollution (used by Express)",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": "<4.17.3",
            "fixed_version": "4.18.2",
            "published": "2022-11-26",
            "references": ["https://github.com/advisories/GHSA-rv95-896h-c2vc"],
        }
    ],
    "jsonwebtoken": [
        {
            "id": "GHSA-hjrf-2m68-5959",
            "aliases": ["CVE-2022-23529"],
            "summary": "Remote code execution when parsing a malicious JWK in jsonwebtoken",
            "severity": "HIGH",
            "cvss_score": 7.6,
            "affected_versions": "<=8.5.1",
            "fixed_version": "9.0.0",
            "published": "2022-12-22",
            "references": [
                "https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959"
            ],
        }
    ],
    "webpack": [
        {
            "id": "GHSA-hc6q-2mpp-qw7j",
            "aliases": ["CVE-2023-28154"],
            "summary": "webpack's AutoPublicPathRuntimeModule has a DOM Clobbering Gadget",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_versions": ">=5.0.0,<5.76.0",
            "fixed_version": "5.76.0",
            "published": "2023-03-13",
            "references": ["https://github.com/webpack/webpack/releases/tag/v5.76.0"],
        }
    ],
}

# ──────────────────────────────────────────────────────────────────
# 3. SEVERITY ORDERING
# ──────────────────────────────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}


def severity_rank(s: str) -> int:
    """Return numeric rank for sorting by severity (descending)."""
    return SEVERITY_ORDER.get(s.upper(), -1)


def normalize_package_name(name: str) -> str:
    """Normalize package name for OSV lookup (lowercase, strip extras)."""
    name = name.strip().lower()
    # Strip version specifiers and extras: requests[security]>=2.0 → requests
    name = re.split(r"[>=<!;\[\s@]", name)[0]
    return name


def parse_requirements_txt(content: str) -> list[dict[str, str]]:
    """
    Parse a requirements.txt file into a list of {name, version} dicts.
    Handles: bare names, ==, >=, pinned, URLs, and comment lines.
    """
    packages: list[dict[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip blanks, comments, and option flags
        if not line or line.startswith(("#", "-r", "-c", "--", "http://", "https://")):
            continue
        # Extract name and optional pinned version
        match = re.match(r"^([A-Za-z0-9_.\-]+)(\[.*?\])?\s*([><=!~]{0,2}\s*[\d.*]+)?", line)
        if match:
            name = normalize_package_name(match.group(1))
            version = (match.group(3) or "").strip().lstrip("=><! ")
            packages.append({"name": name, "version": version or "unknown"})
    return packages


def parse_package_json(content: dict[str, Any]) -> list[dict[str, str]]:
    """
    Extract dependencies from a parsed package.json object.
    Merges 'dependencies' and 'devDependencies'.
    """
    packages: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in content.get(section, {}).items():
            clean_version = re.sub(r"[^0-9.]", "", version) if version else "unknown"
            packages.append({"name": name.lower(), "version": clean_version or "unknown"})
    return packages


# ──────────────────────────────────────────────────────────────────
# 4. SEVERITY ENUM
# ──────────────────────────────────────────────────────────────────


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Map a CVSS numeric score to a Severity bucket."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


# ──────────────────────────────────────────────────────────────────
# 5. VERSION PARSING
# ──────────────────────────────────────────────────────────────────


def parse_version(version_str: str) -> tuple[int, ...]:
    """
    Parse a version string (optionally prefixed with operators) into a
    tuple of ints suitable for comparison.

    Examples::
        parse_version("2.31.0")   → (2, 31, 0)
        parse_version(">=2.31.0") → (2, 31, 0)
        parse_version("<1.6.0")   → (1, 6, 0)
    """
    clean = re.sub(r"^[><=!~]+\s*", "", version_str.strip())
    parts = clean.split(".")
    result: list[int] = []
    for part in parts:
        m = re.match(r"\d+", part)
        result.append(int(m.group()) if m else 0)
    return tuple(result)


# ──────────────────────────────────────────────────────────────────
# 6. FILE SCANNABILITY
# ──────────────────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".c",
        ".cpp",
        ".h",
        ".cs",
        ".swift",
        ".kt",
        ".rs",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".cfg",
        ".ini",
        ".conf",
        ".env",
        ".tf",
        ".hcl",
        ".xml",
        ".html",
        ".htm",
        ".md",
        ".txt",
        ".sql",
    }
)

SKIP_SCAN_FILENAMES: frozenset[str] = frozenset({".env.example", ".env.sample", ".env.template"})


def is_scannable_file(path: Any) -> bool:
    """
    Return True if *path* should be included in a secret scan.

    Rules (applied in order):
    1. Skip if any parent directory name is in SKIP_DIRS.
    2. Skip if the filename matches a known template/example pattern.
    3. Skip if the file extension is a binary/lock format (SKIP_EXTENSIONS).
    4. Accept only files whose extension is in SCANNABLE_EXTENSIONS.
    """
    from pathlib import Path as _Path

    p = _Path(path)

    # Rule 1: reject files inside skipped directories
    for parent in p.parents:
        if parent.name in SKIP_DIRS:
            return False

    # Rule 2: reject well-known placeholder filenames
    if p.name in SKIP_SCAN_FILENAMES:
        return False

    # Rule 3: reject binary/non-text extensions
    if p.suffix.lower() in SKIP_EXTENSIONS:
        return False

    # Rule 4: must have a recognised text/source extension
    return p.suffix.lower() in SCANNABLE_EXTENSIONS
