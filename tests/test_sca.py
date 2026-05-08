"""
Tests for Software Composition Analysis (SCA) tool.
"""

import pytest

from src.server.tools.sca import run_sca
from src.utils.helpers import normalize_package_name, parse_package_json, parse_requirements_txt

# ──────────────────────────────────────────────────────────────────
# Unit: helpers
# ──────────────────────────────────────────────────────────────────

class TestNormalizePackageName:
    def test_lowercase(self):
        assert normalize_package_name("Requests") == "requests"

    def test_strip_version(self):
        assert normalize_package_name("requests>=2.28.0") == "requests"

    def test_strip_extras(self):
        assert normalize_package_name("requests[security]") == "requests"

    def test_strip_whitespace(self):
        assert normalize_package_name("  flask  ") == "flask"


class TestParseRequirementsTxt:
    def test_pinned_packages(self):
        content = "requests==2.28.0\nflask==2.3.2\n"
        pkgs = parse_requirements_txt(content)
        names = [p["name"] for p in pkgs]
        assert "requests" in names
        assert "flask" in names

    def test_skips_comments(self):
        content = "# This is a comment\nrequests==2.28.0\n"
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1

    def test_skips_flags(self):
        content = "--index-url https://pypi.org/simple\nrequests==2.28.0\n"
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1

    def test_bare_package(self):
        content = "requests\n"
        pkgs = parse_requirements_txt(content)
        assert pkgs[0]["name"] == "requests"
        assert pkgs[0]["version"] == "unknown"


class TestParsePackageJson:
    def test_extracts_dependencies(self):
        pkg_json = {
            "name": "my-app",
            "dependencies": {"lodash": "^4.17.20", "axios": "^1.5.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        pkgs = parse_package_json(pkg_json)
        names = [p["name"] for p in pkgs]
        assert "lodash" in names
        assert "axios" in names
        assert "jest" in names

    def test_empty_package_json(self):
        assert parse_package_json({}) == []


# ──────────────────────────────────────────────────────────────────
# Integration: run_sca
# ──────────────────────────────────────────────────────────────────

VULN_REQUIREMENTS = "requests==2.28.0\nflask==2.2.0\nurllib3==1.26.15\npyyaml==5.3\n"
CLEAN_REQUIREMENTS = "some-unknown-package==1.0.0\nanother-lib==2.3.4\n"


class TestRunSCA:
    def test_detects_known_vulnerabilities(self):
        report = run_sca(f"CONTENT:{VULN_REQUIREMENTS}")
        assert report["summary"]["vulnerable_packages"] > 0
        assert report["summary"]["total_vulnerabilities"] > 0

    def test_clean_manifest_has_zero_vulns(self):
        report = run_sca(f"CONTENT:{CLEAN_REQUIREMENTS}")
        assert report["summary"]["vulnerable_packages"] == 0
        assert report["summary"]["risk_rating"] == "LOW"

    def test_report_structure(self):
        report = run_sca(f"CONTENT:{VULN_REQUIREMENTS}")
        assert "summary" in report
        assert "vulnerable_packages" in report
        assert "clean_packages" in report
        assert "remediation_priority" in report
        assert report["scan_type"] == "Software Composition Analysis (SCA)"

    def test_pyyaml_critical(self):
        report = run_sca("CONTENT:pyyaml==5.3\n")
        vuln_names = [v["package"] for v in report["vulnerable_packages"]]
        assert "pyyaml" in vuln_names
        pyyaml_entry = next(v for v in report["vulnerable_packages"] if v["package"] == "pyyaml")
        assert pyyaml_entry["highest_severity"] == "CRITICAL"

    def test_npm_package_json(self):
        import json
        pkg = json.dumps({
            "dependencies": {"lodash": "4.17.20", "minimist": "1.2.5"}
        })
        report = run_sca(f"CONTENT:{pkg}")
        assert report["ecosystem"] == "npm"
        assert report["summary"]["vulnerable_packages"] > 0

    def test_invalid_path_raises(self):
        from pydantic import ValidationError

        from src.server.tools.sca import CheckDependenciesInput
        with pytest.raises(ValidationError):
            CheckDependenciesInput(manifest_path="/nonexistent/requirements.txt")
