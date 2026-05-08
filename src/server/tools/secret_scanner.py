"""
guardian-ssdlc · tools/secret_scanner.py
──────────────────────────────────────────
Secret Scanner tool.

Performs regex-based detection of hardcoded credentials, API keys, tokens,
and other sensitive material in a source directory or inline code string.
"""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from src.utils.helpers import SECRET_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS

logger = logging.getLogger("guardian.secret_scanner")

# Maximum file size to scan (skip very large binary-like files)
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


# ──────────────────────────────────────────────────────────────────
# Shannon Entropy
# ──────────────────────────────────────────────────────────────────


def _calculate_entropy(s: str) -> float:
    """Return the Shannon entropy (bits) of *s*. Empty string → 0.0."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ──────────────────────────────────────────────────────────────────
# Input Schema
# ──────────────────────────────────────────────────────────────────


class ScanSecretsInput(BaseModel):
    target: str = Field(
        ...,
        description=(
            "Path to a directory or single file to scan for secrets. "
            "Alternatively, pass raw code/text prefixed with 'CONTENT:' "
            "for inline scanning (e.g. from a CI pipeline)."
        ),
    )
    include_extensions: list[str] | None = Field(
        default=None,
        description=(
            "Whitelist of file extensions to scan (e.g. ['.py', '.js', '.env']). "
            "If None, all non-binary files are scanned."
        ),
    )
    exclude_patterns: list[str] | None = Field(
        default=None,
        description="Additional glob-style filename patterns to exclude.",
    )
    max_findings_per_file: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Cap findings per file to avoid noise in huge generated files.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if v.startswith("CONTENT:"):
            return v
        p = Path(v)
        if not p.exists():
            raise ValueError(f"Target path does not exist: {v}")
        return str(p.resolve())


# ──────────────────────────────────────────────────────────────────
# File Iterator
# ──────────────────────────────────────────────────────────────────


def _iter_files(
    root: Path,
    include_exts: list[str] | None,
    exclude_patterns: list[str] | None,
) -> list[Path]:
    """Walk a directory tree and return scannable files."""
    files: list[Path] = []

    if root.is_file():
        return [root]

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place (avoids descending into them)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

        for fname in filenames:
            fpath = Path(dirpath) / fname

            # Extension filter
            if fpath.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if include_exts and fpath.suffix.lower() not in include_exts:
                continue
            if exclude_patterns and any(fpath.match(pat) for pat in exclude_patterns):
                continue

            # Size guard
            try:
                if fpath.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            files.append(fpath)

    return files


# ──────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────


def _scan_content(
    content: str,
    source_label: str,
    max_per_file: int,
) -> list[dict[str, Any]]:
    """Scan a string of content and return a list of findings."""
    findings: list[dict[str, Any]] = []
    lines = content.splitlines()

    for label, pattern, severity, description in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            if len(findings) >= max_per_file:
                break

            # Find the line number
            line_no = content[: match.start()].count("\n") + 1
            line_text = lines[line_no - 1] if lines else ""

            # Skip commented lines (# style — covers Python, YAML, shell)
            if line_text.strip().startswith("#"):
                continue

            # Redact matched value to avoid leaking it in reports
            full_match = match.group(0)
            visible = full_match[:6] + "***" + full_match[-3:] if len(full_match) > 12 else "***"

            findings.append(
                {
                    "file": source_label,
                    "file_path": source_label,  # convenience alias
                    "line": line_no,
                    "pattern_name": label,
                    "severity": severity,
                    "description": description,
                    "redacted_match": visible,
                    "line_preview": line_text.strip()[:120],
                }
            )

    return findings


def run_secret_scan(
    target: str,
    include_extensions: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_findings_per_file: int = 20,
    output_format: str = "json",
) -> dict[str, Any]:
    """
    Main entry-point for the secret scanner.
    Scans a directory/file or inline content and returns a structured report.

    output_format: "json" (default) or "sarif" (SARIF 2.1.0 for CI/GitHub integration).
    Returns {"scan_status": "FAILED", "error": "..."} on invalid input.
    """
    logger.info("Starting secret scan: %s", target)

    # Validate path existence for non-inline targets
    if not target.startswith("CONTENT:"):
        p = Path(target)
        if not p.exists():
            return {"scan_status": "FAILED", "error": f"Target path does not exist: {target}"}

    all_findings: list[dict[str, Any]] = []
    files_scanned = 0
    files_with_findings: set[str] = set()

    if target.startswith("CONTENT:"):
        content = target[len("CONTENT:") :]
        findings = _scan_content(content, "<inline>", max_findings_per_file)
        all_findings.extend(findings)
        files_scanned = 1
        if findings:
            files_with_findings.add("<inline>")
    else:
        root = Path(target)
        file_list = _iter_files(root, include_extensions, exclude_patterns)
        files_scanned = len(file_list)
        logger.info("Files to scan: %d", files_scanned)

        for fpath in file_list:
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                logger.warning("Could not read %s: %s", fpath, exc)
                continue

            rel = str(fpath.relative_to(root) if root.is_dir() else fpath)
            findings = _scan_content(content, rel, max_findings_per_file)
            if findings:
                all_findings.extend(findings)
                files_with_findings.add(rel)

    # Severity breakdown
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Sort by severity
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    all_findings.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    # Unique pattern types found
    pattern_types = list({f["pattern_name"] for f in all_findings})

    risk_rating = (
        "CRITICAL"
        if sev_counts["CRITICAL"] > 0
        else "HIGH"
        if sev_counts["HIGH"] > 0
        else "MEDIUM"
        if all_findings
        else "CLEAN"
    )

    report: dict[str, Any] = {
        "scan_type": "Secret & Credential Scanner",
        "scan_status": "COMPLETED",
        "files_scanned": files_scanned,  # top-level convenience field
        "target": target if not target.startswith("CONTENT:") else "<inline content>",
        "summary": {
            "files_scanned": files_scanned,
            "files_with_findings": len(files_with_findings),
            "total_secrets_found": len(all_findings),
            "severity_breakdown": sev_counts,
            "risk_rating": risk_rating,
            "pattern_types_detected": pattern_types,
        },
        "findings": all_findings,
        "affected_files": sorted(files_with_findings),
        "recommendations": _build_recommendations(all_findings),
    }

    logger.info(
        "Secret scan complete: %d findings in %d files, risk=%s",
        len(all_findings),
        len(files_with_findings),
        risk_rating,
    )

    if output_format.lower() == "sarif":
        return to_sarif(report)

    return report


# ──────────────────────────────────────────────────────────────────
# SARIF 2.1.0 Output
# ──────────────────────────────────────────────────────────────────

# Map pattern label → stable SARIF rule ID
_SARIF_RULE_IDS: dict[str, str] = {
    label: f"GUARD-S{str(i + 1).zfill(3)}" for i, (label, *_) in enumerate(SECRET_PATTERNS)
}

_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SEV_SCORE: dict[str, str] = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "5.0",
    "LOW": "2.0",
}


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a Guardian secret-scan report to SARIF 2.1.0 format.

    SARIF is the industry standard for static-analysis result interchange —
    GitHub Code Scanning, VS Code, and most CI systems consume it natively.
    """
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for label, _pat, severity, description in SECRET_PATTERNS:
        rule_id = _SARIF_RULE_IDS[label]
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": label.replace(" ", ""),
                    "shortDescription": {"text": label},
                    "fullDescription": {"text": description},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
                    "properties": {
                        "security-severity": _SEV_SCORE.get(severity, "5.0"),
                        "tags": ["security", "secret-detection"],
                    },
                }
            )

    results: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        rule_id = _SARIF_RULE_IDS.get(finding["pattern_name"], "GUARD-S000")
        uri = finding.get("file_path", finding.get("file", "<inline>"))
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(finding["severity"], "warning"),
                "message": {
                    "text": (
                        f"{finding['description']} — redacted match: {finding['redacted_match']}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": finding.get("line", 1)},
                        }
                    }
                ],
                "properties": {"severity": finding["severity"]},
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Guardian Secret Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-username/guardian-ssdlc",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "guardian_risk_rating": report.get("summary", {}).get("risk_rating", "UNKNOWN"),
                    "files_scanned": report.get("files_scanned", 0),
                },
            }
        ],
    }


# ──────────────────────────────────────────────────────────────────
# Git History Scanner
# ──────────────────────────────────────────────────────────────────


def scan_git_history(
    repo_path: str,
    max_commits: int = 500,
    branch: str = "--all",
) -> dict[str, Any]:
    """
    Scan git history for secrets that were committed and later removed.

    Runs ``git log -p`` and pipes the diff output through the same regex
    engine used by run_secret_scan.  Reports findings by commit hash, author,
    and file path so you can identify when a secret was introduced and by whom.

    Returns {"scan_status": "FAILED", "error": "..."} if the path is not a
    git repository or git is not available.
    """
    import subprocess

    p = Path(repo_path)
    if not p.exists() or not p.is_dir():
        return {
            "scan_status": "FAILED",
            "error": f"Path does not exist or is not a directory: {repo_path}",
        }

    # Verify it is a git repo
    try:
        check = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=str(p),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if check.returncode != 0:
            return {"scan_status": "FAILED", "error": f"Not a git repository: {repo_path}"}
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"scan_status": "FAILED", "error": f"git not available: {exc}"}

    # Fetch the full patch log
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "-p",
                branch,
                f"--max-count={max_commits}",
                "--no-merges",
                "--diff-filter=AM",  # only added / modified hunks
                "--format=COMMIT:%H%nAUTHOR:%an <%ae>%nDATE:%ci%nMESSAGE:%s",
            ],
            cwd=str(p),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {
            "scan_status": "FAILED",
            "error": "git log timed out after 120 s — try reducing max_commits",
        }

    if result.returncode != 0:
        return {"scan_status": "FAILED", "error": result.stderr.strip()}

    # ── parse the patch output ────────────────────────────────────
    findings: list[dict[str, Any]] = []
    current_commit = current_author = current_date = current_message = ""
    current_file = ""
    line_offset = 0

    for raw_line in result.stdout.splitlines():
        if raw_line.startswith("COMMIT:"):
            current_commit = raw_line[7:]
            line_offset = 0
        elif raw_line.startswith("AUTHOR:"):
            current_author = raw_line[7:]
        elif raw_line.startswith("DATE:"):
            current_date = raw_line[5:]
        elif raw_line.startswith("MESSAGE:"):
            current_message = raw_line[8:]
        elif raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            line_offset = 0
        elif raw_line.startswith("@@ "):
            # @@ -old_start,old_count +new_start,new_count @@
            try:
                new_part = raw_line.split("+")[1].split(",")[0]
                line_offset = int(new_part) - 1
            except (IndexError, ValueError):
                line_offset = 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_offset += 1
            added_line = raw_line[1:]  # strip leading +

            if added_line.strip().startswith("#"):
                continue

            for label, pattern, severity, description in SECRET_PATTERNS:
                for match in pattern.finditer(added_line):
                    full_match = match.group(0)
                    visible = (
                        full_match[:6] + "***" + full_match[-3:] if len(full_match) > 12 else "***"
                    )
                    findings.append(
                        {
                            "commit": current_commit[:12],
                            "author": current_author,
                            "date": current_date,
                            "message": current_message[:80],
                            "file": current_file,
                            "line": line_offset,
                            "pattern_name": label,
                            "severity": severity,
                            "description": description,
                            "redacted_match": visible,
                            "line_preview": added_line.strip()[:120],
                        }
                    )
        elif not raw_line.startswith("-"):
            # context lines (no +/-) still advance line counter
            line_offset += 1

    # Deduplicate by (commit, file, pattern, redacted) to avoid repeat matches
    seen: set[tuple[str, str, str, str]] = set()
    unique_findings: list[dict[str, Any]] = []
    for f in findings:
        key = (f["commit"], f["file"], f["pattern_name"], f["redacted_match"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    unique_findings.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in unique_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    risk_rating = (
        "CRITICAL"
        if sev_counts["CRITICAL"] > 0
        else "HIGH"
        if sev_counts["HIGH"] > 0
        else "MEDIUM"
        if unique_findings
        else "CLEAN"
    )

    commits_with_findings = len({f["commit"] for f in unique_findings})

    logger.info(
        "Git history scan complete: %d findings across %d commits, risk=%s",
        len(unique_findings),
        commits_with_findings,
        risk_rating,
    )

    return {
        "scan_type": "Git History Secret Scan",
        "scan_status": "COMPLETED",
        "repo_path": repo_path,
        "commits_scanned": max_commits,
        "summary": {
            "total_secrets_found": len(unique_findings),
            "commits_with_findings": commits_with_findings,
            "severity_breakdown": sev_counts,
            "risk_rating": risk_rating,
        },
        "findings": unique_findings,
        "recommendations": [
            "Use `git filter-repo` or BFG Repo Cleaner to purge secrets from git history.",
            "Rotate ALL credentials found — assume they are compromised.",
            "Add pre-commit hooks (detect-secrets, gitleaks) to prevent future commits.",
            "Consider the repository compromised if it was ever public while these commits existed.",
        ]
        if unique_findings
        else ["No secrets found in git history."],
    }


def _build_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    recs: list[str] = []
    types = {f["pattern_name"] for f in findings}

    if any("Private Key" in t for t in types) or "AWS Access Key ID" in types:
        recs.append("Rotate ALL exposed keys and revoke compromised credentials immediately.")

    if any("API" in t or "Token" in t or "Secret" in t for t in types):
        recs.append(
            "Move all secrets to environment variables or a secrets manager "
            "(HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)."
        )

    if findings:
        recs.append("Add pre-commit hooks (detect-secrets, git-secrets) to prevent future commits.")
        recs.append("Scan git history with truffleHog or gitleaks for historical secret leaks.")
        recs.append("Add .env, *.pem, *.key to your .gitignore immediately.")

    return recs
