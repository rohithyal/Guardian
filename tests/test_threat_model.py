"""
Tests for the STRIDE Threat Modelling Engine.
"""

import pytest
from src.server.tools.threat_model import generate_threat_model, SystemArchitectureInput


SIMPLE_ARCH = {
    "system_name": "E-Commerce Platform",
    "components": [
        {
            "name": "Web Frontend",
            "type": "web_app",
            "exposes_internet": True,
            "handles_pii": True,
            "auth_mechanism": "jwt",
        },
        {
            "name": "Product API",
            "type": "api",
            "exposes_internet": False,
            "handles_pii": False,
            "auth_mechanism": "oauth2",
        },
        {
            "name": "User Database",
            "type": "database",
            "exposes_internet": False,
            "handles_pii": True,
            "auth_mechanism": "mtls",
        },
    ],
    "data_flows": [
        {
            "from_component": "Web Frontend",
            "to_component": "Product API",
            "protocol": "HTTPS",
            "encrypted": True,
            "authenticated": True,
        },
        {
            "from_component": "Product API",
            "to_component": "User Database",
            "protocol": "TCP",
            "encrypted": False,   # intentional misconfiguration for test
            "authenticated": True,
        },
    ],
    "trust_boundary": "Internet → DMZ → Internal",
}

MINIMAL_ARCH = {
    "system_name": "Minimal App",
    "components": [
        {"name": "Service", "type": "api", "exposes_internet": False, "handles_pii": False}
    ],
}


class TestSystemArchitectureInput:
    def test_valid_architecture(self):
        arch = SystemArchitectureInput(**SIMPLE_ARCH)
        assert arch.system_name == "E-Commerce Platform"
        assert len(arch.components) == 3

    def test_duplicate_component_names_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SystemArchitectureInput(
                system_name="Test",
                components=[
                    {"name": "API", "type": "api"},
                    {"name": "API", "type": "web_app"},
                ],
            )

    def test_empty_components_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SystemArchitectureInput(system_name="Test", components=[])


class TestGenerateThreatModel:
    def test_report_structure(self):
        report = generate_threat_model(SIMPLE_ARCH)
        assert "summary" in report
        assert "threat_findings" in report
        assert "stride_coverage" in report
        assert report["scan_type"] == "STRIDE Threat Model"

    def test_detects_threats_for_internet_component(self):
        report = generate_threat_model(SIMPLE_ARCH)
        frontend_threats = [
            f for f in report["threat_findings"] if f["component"] == "Web Frontend"
        ]
        assert len(frontend_threats) > 0

    def test_unencrypted_flow_warning(self):
        report = generate_threat_model(SIMPLE_ARCH)
        warnings = report["data_flow_warnings"]
        assert any("Unencrypted" in w for w in warnings)

    def test_stride_categories_covered(self):
        report = generate_threat_model(SIMPLE_ARCH)
        categories_in_findings = {f["stride_category"] for f in report["threat_findings"]}
        # Internet-exposed PII component should trigger at minimum these
        assert "Information Disclosure" in categories_in_findings
        assert "Denial of Service" in categories_in_findings

    def test_pii_component_raises_impact(self):
        report = generate_threat_model(SIMPLE_ARCH)
        pii_threats = [
            f for f in report["threat_findings"]
            if f["component"] == "Web Frontend" and f["stride_category"] == "Information Disclosure"
        ]
        assert any(t["impact"] in ("CRITICAL", "HIGH") for t in pii_threats)

    def test_minimal_architecture(self):
        report = generate_threat_model(MINIMAL_ARCH)
        assert report["components_analysed"] == 1
        assert report["summary"]["total_threats_identified"] >= 0

    def test_overall_risk_not_low_for_internet_pii(self):
        report = generate_threat_model(SIMPLE_ARCH)
        assert report["summary"]["overall_risk"] in ("CRITICAL", "HIGH", "MEDIUM")
