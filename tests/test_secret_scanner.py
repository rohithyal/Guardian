"""
Tests for the Secret Scanner tool.
"""

import pytest

from src.server.tools.secret_scanner import run_secret_scan

# ──────────────────────────────────────────────────────────────────
# Test payloads (synthetic — never real credentials)
# ──────────────────────────────────────────────────────────────────

CLEAN_CODE = """
def add(a: int, b: int) -> int:
    return a + b

class Config:
    DEBUG = False
    DATABASE_URL = "postgres://localhost/mydb"
"""

# This triggers DB connection string pattern
DIRTY_CODE_DB = """
DATABASE_URL = "postgres://admin:hunter2@prod-db.internal:5432/users"
"""

DIRTY_CODE_AWS = """
import boto3
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

DIRTY_CODE_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29KnqThXcZxnfQ
-----END RSA PRIVATE KEY-----
"""

DIRTY_CODE_JWT = """
const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
"""


class TestRunSecretScanInline:
    def test_clean_code_returns_no_findings(self):
        report = run_secret_scan(target=f"CONTENT:{CLEAN_CODE}")
        assert report["summary"]["total_secrets_found"] == 0
        assert report["summary"]["risk_rating"] == "CLEAN"

    def test_detects_aws_access_key(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_AWS}")
        patterns = {f["pattern_name"] for f in report["findings"]}
        assert "AWS Access Key ID" in patterns

    def test_detects_private_key(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_PRIVATE_KEY}")
        patterns = {f["pattern_name"] for f in report["findings"]}
        assert "RSA Private Key Header" in patterns

    def test_detects_jwt(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_JWT}")
        patterns = {f["pattern_name"] for f in report["findings"]}
        assert "JWT Token" in patterns

    def test_findings_are_redacted(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_AWS}")
        for finding in report["findings"]:
            assert "***" in finding["redacted_match"]

    def test_critical_rating_for_aws(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_AWS}")
        assert report["summary"]["risk_rating"] == "CRITICAL"

    def test_report_structure(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_AWS}")
        assert "summary" in report
        assert "findings" in report
        assert "recommendations" in report
        assert report["scan_type"] == "Secret & Credential Scanner"

    def test_recommendations_present_for_findings(self):
        report = run_secret_scan(target=f"CONTENT:{DIRTY_CODE_PRIVATE_KEY}")
        assert len(report["recommendations"]) > 0


class TestRunSecretScanDirectory:
    def test_invalid_path_raises(self):
        from pydantic import ValidationError

        from src.server.tools.secret_scanner import ScanSecretsInput
        with pytest.raises(ValidationError):
            ScanSecretsInput(target="/nonexistent/path/to/scan")

    def test_scan_current_dir(self, tmp_path):
        # Create a temp file with a secret
        secret_file = tmp_path / "config.py"
        secret_file.write_text('API_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrs"\n')
        report = run_secret_scan(target=str(tmp_path))
        assert report["summary"]["files_scanned"] >= 1
        patterns = {f["pattern_name"] for f in report["findings"]}
        assert "Google API Key" in patterns
