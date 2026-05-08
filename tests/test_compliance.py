"""
Tests for the Compliance Guardrails audit tool.
"""

import pytest
from src.server.tools.compliance import run_compliance_audit


SAMPLE_FINDINGS = [
    {"finding_type": "known_cve", "severity": "HIGH", "description": "CVE in requests", "affected_component": "api"},
    {"finding_type": "hardcoded_secret", "severity": "CRITICAL", "description": "AWS key in config.py"},
    {"finding_type": "denial_of_service", "severity": "MEDIUM", "description": "No rate limiting"},
]

SINGLE_FINDING = [
    {"finding_type": "elevation_of_privilege", "severity": "HIGH", "description": "Missing RBAC"}
]


class TestRunComplianceAudit:
    def test_report_structure(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        assert "summary" in report
        assert "findings" in report
        assert "executive_summary" in report
        assert report["scan_type"] == "Compliance Guardrails Audit"

    def test_nist_controls_triggered(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        nist_ids = report["summary"]["nist_controls_triggered"]
        assert len(nist_ids) > 0
        # known_cve should trigger SI-2 and RA-5
        assert any("SI-2" in cid or "RA-5" in cid for cid in nist_ids)

    def test_owasp_categories_triggered(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        owasp_ids = report["summary"]["owasp_categories_triggered"]
        assert len(owasp_ids) > 0

    def test_hardcoded_secret_triggers_ia5(self):
        report = run_compliance_audit(
            [{"finding_type": "hardcoded_secret", "severity": "CRITICAL", "description": "test"}]
        )
        all_control_ids = []
        for f in report["findings"]:
            nist_map = f["framework_mappings"].get("NIST_800_53", {})
            all_control_ids.extend(nist_map.get("control_ids", []))
        assert "IA-5" in all_control_ids

    def test_severity_breakdown(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        breakdown = report["summary"]["severity_breakdown"]
        assert breakdown["CRITICAL"] == 1
        assert breakdown["HIGH"] == 1
        assert breakdown["MEDIUM"] == 1

    def test_compliance_coverage_percentage(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        coverage = report["summary"]["compliance_coverage"]
        assert "%" in coverage

    def test_nist_only_framework(self):
        report = run_compliance_audit(SAMPLE_FINDINGS, frameworks=["NIST_800_53"])
        assert "NIST_800_53" in report["frameworks_evaluated"]
        assert "OWASP_TOP10" not in report["frameworks_evaluated"]

    def test_executive_summary_contains_severity_counts(self):
        report = run_compliance_audit(SAMPLE_FINDINGS)
        summary = report["executive_summary"]
        assert "CRITICAL" in summary
        assert "HIGH" in summary

    def test_empty_findings_raises(self):
        from pydantic import ValidationError
        from src.server.tools.compliance import AuditComplianceInput
        with pytest.raises(ValidationError):
            AuditComplianceInput(findings=[])
