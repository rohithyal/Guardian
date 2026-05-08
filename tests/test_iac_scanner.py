"""
Tests for the IaC Misconfiguration Scanner (iac_scanner.py).

Covers:
  - Dockerfile rule detection (IAC-D001 through IAC-D009)
  - docker-compose rule detection (IAC-C001 through IAC-C008)
  - Directory scanning
  - Clean files produce no findings
  - Report structure
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.server.tools.iac_scanner import (
    ScanIaCInput,
    _scan_compose,
    _scan_dockerfile,
    run_iac_scan,
)

# ──────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────


def write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ──────────────────────────────────────────────────────────────────
# Dockerfile — individual rules
# ──────────────────────────────────────────────────────────────────


class TestDockerfileD001:
    """IAC-D001: No USER instruction → runs as root."""

    def test_missing_user_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            """\
            FROM python:3.11-slim
            RUN pip install flask
            CMD ["python", "app.py"]
            """,
        )
        findings = _scan_dockerfile(f)
        rule_ids = [x["rule_id"] for x in findings]
        assert "IAC-D001" in rule_ids

    def test_user_root_still_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            """\
            FROM python:3.11-slim
            USER root
            CMD ["python", "app.py"]
            """,
        )
        findings = _scan_dockerfile(f)
        rule_ids = [x["rule_id"] for x in findings]
        assert "IAC-D001" in rule_ids

    def test_non_root_user_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            """\
            FROM python:3.11-slim
            RUN useradd -u 1001 app
            USER app
            HEALTHCHECK CMD echo ok
            CMD ["python", "app.py"]
            """,
        )
        findings = _scan_dockerfile(f)
        rule_ids = [x["rule_id"] for x in findings]
        assert "IAC-D001" not in rule_ids


class TestDockerfileD002:
    """IAC-D002: Floating 'latest' tag or no tag."""

    def test_no_tag_flagged(self, tmp_path):
        f = write_file(tmp_path, "Dockerfile", 'FROM python\nCMD ["python"]\n')
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D002" for x in findings)

    def test_latest_tag_flagged(self, tmp_path):
        f = write_file(tmp_path, "Dockerfile", 'FROM python:latest\nCMD ["python"]\n')
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D002" for x in findings)

    def test_pinned_version_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11.9-slim\nUSER nobody\nHEALTHCHECK CMD echo ok\nCMD ["python"]\n',
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D002" for x in findings)

    def test_digest_pin_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            'FROM python@sha256:abcdef1234567890\nUSER nobody\nHEALTHCHECK CMD echo ok\nCMD ["python"]\n',
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D002" for x in findings)


class TestDockerfileD003:
    """IAC-D003: curl/wget pipe into shell."""

    def test_curl_pipe_bash_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11-slim\nRUN curl https://example.com/install.sh | bash\n",
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D003" for x in findings)

    def test_wget_pipe_sh_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11-slim\nRUN wget -qO- https://example.com/setup | sh\n",
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D003" for x in findings)

    def test_curl_without_pipe_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11-slim\nRUN curl -o script.sh https://example.com/script.sh\n",
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D003" for x in findings)


class TestDockerfileD004:
    """IAC-D004: ADD used instead of COPY for local files."""

    def test_add_local_flagged(self, tmp_path):
        f = write_file(tmp_path, "Dockerfile", "FROM python:3.11-slim\nADD ./app /app\n")
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D004" for x in findings)

    def test_copy_not_flagged(self, tmp_path):
        f = write_file(tmp_path, "Dockerfile", "FROM python:3.11-slim\nCOPY ./app /app\n")
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D004" for x in findings)


class TestDockerfileD005:
    """IAC-D005: apt-get install without --no-install-recommends."""

    def test_missing_flag_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM ubuntu:22.04\nRUN apt-get install -y curl\n",
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D005" for x in findings)

    def test_with_flag_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM ubuntu:22.04\nRUN apt-get install -y --no-install-recommends curl\n",
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D005" for x in findings)


class TestDockerfileD007:
    """IAC-D007: chmod 777."""

    def test_chmod_777_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11-slim\nRUN chmod 777 /app\n",
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D007" for x in findings)

    def test_chmod_755_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11-slim\nRUN chmod 755 /app/start.sh\n",
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D007" for x in findings)


class TestDockerfileD008:
    """IAC-D008: No HEALTHCHECK."""

    def test_no_healthcheck_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nUSER nobody\nCMD ["python", "app.py"]\n',
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D008" for x in findings)

    def test_healthcheck_present_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM python:3.11.9-slim\nUSER nobody\n"
            "HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n"
            'CMD ["python", "app.py"]\n',
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D008" for x in findings)


class TestDockerfileD009:
    """IAC-D009: sudo."""

    def test_sudo_in_run_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM ubuntu:22.04\nRUN sudo apt-get update\n",
        )
        findings = _scan_dockerfile(f)
        assert any(x["rule_id"] == "IAC-D009" for x in findings)

    def test_no_sudo_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            "FROM ubuntu:22.04\nRUN apt-get update\n",
        )
        findings = _scan_dockerfile(f)
        assert not any(x["rule_id"] == "IAC-D009" for x in findings)


# ──────────────────────────────────────────────────────────────────
# docker-compose — individual rules
# ──────────────────────────────────────────────────────────────────


class TestComposeC001:
    """IAC-C001: privileged: true."""

    def test_privileged_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                privileged: true
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C001" for x in findings)

    def test_not_privileged_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C001" for x in findings)


class TestComposeC002:
    """IAC-C002: network_mode: host."""

    def test_host_network_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                network_mode: host
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C002" for x in findings)


class TestComposeC003:
    """IAC-C003: Docker socket mounted."""

    def test_docker_socket_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              ci:
                image: docker:dind
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C003" for x in findings)


class TestComposeC004:
    """IAC-C004: Sensitive host path mounted."""

    @pytest.mark.parametrize("host_path", ["/etc", "/proc", "/sys", "/root", "/home", "/boot"])
    def test_sensitive_paths_flagged(self, tmp_path, host_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            f"""\
            services:
              app:
                image: myapp
                volumes:
                  - {host_path}:/mnt/data
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C004" for x in findings)

    def test_app_data_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                volumes:
                  - ./data:/app/data
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C004" for x in findings)


class TestComposeC005:
    """IAC-C005: Ports bound to 0.0.0.0."""

    def test_all_interface_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              web:
                image: nginx
                ports:
                  - "0.0.0.0:80:80"
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C005" for x in findings)

    def test_bare_port_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              web:
                image: nginx
                ports:
                  - "8080:80"
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C005" for x in findings)

    def test_localhost_bind_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              web:
                image: nginx
                ports:
                  - "127.0.0.1:8080:80"
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C005" for x in findings)


class TestComposeC006:
    """IAC-C006: No resource limits."""

    def test_no_limits_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C006" for x in findings)

    def test_deploy_limits_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                deploy:
                  resources:
                    limits:
                      memory: 512m
                      cpus: "0.5"
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C006" for x in findings)


class TestComposeC007:
    """IAC-C007: cap_add: [ALL]."""

    def test_cap_all_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                cap_add:
                  - ALL
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C007" for x in findings)

    def test_specific_cap_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                cap_add:
                  - NET_BIND_SERVICE
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C007" for x in findings)


class TestComposeC008:
    """IAC-C008: no-new-privileges not set."""

    def test_missing_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
            """,
        )
        findings = _scan_compose(f)
        assert any(x["rule_id"] == "IAC-C008" for x in findings)

    def test_set_not_flagged(self, tmp_path):
        f = write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                security_opt:
                  - no-new-privileges:true
            """,
        )
        findings = _scan_compose(f)
        assert not any(x["rule_id"] == "IAC-C008" for x in findings)


# ──────────────────────────────────────────────────────────────────
# run_iac_scan — integration tests
# ──────────────────────────────────────────────────────────────────


class TestRunIaCScan:
    def test_report_structure(self, tmp_path):
        write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nCMD ["python", "app.py"]\n',
        )
        report = run_iac_scan(str(tmp_path))
        assert report["scan_type"] == "IaC Misconfiguration Scanner"
        assert "summary" in report
        assert "findings" in report
        assert "files_scanned" in report
        assert "rules_evaluated" in report
        assert "remediation_priority" in report
        assert report["summary"]["files_scanned"] == 1

    def test_single_file_target(self, tmp_path):
        f = write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nCMD ["python", "app.py"]\n',
        )
        report = run_iac_scan(str(f))
        assert report["summary"]["files_scanned"] == 1

    def test_invalid_target_raises(self, tmp_path):
        with pytest.raises(ValueError):
            ScanIaCInput(target="/nonexistent/path/Dockerfile")

    def test_severity_breakdown_counts(self, tmp_path):
        write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nCMD ["python", "app.py"]\n',
        )
        report = run_iac_scan(str(tmp_path))
        breakdown = report["summary"]["severity_breakdown"]
        total = sum(breakdown.values())
        assert total == report["summary"]["total_findings"]

    def test_risk_rating_present(self, tmp_path):
        write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nCMD ["python", "app.py"]\n',
        )
        report = run_iac_scan(str(tmp_path))
        assert report["summary"]["risk_rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_directory_with_both_types(self, tmp_path):
        write_file(
            tmp_path,
            "Dockerfile",
            'FROM python:3.11-slim\nCMD ["python"]\n',
        )
        write_file(
            tmp_path,
            "docker-compose.yml",
            "services:\n  app:\n    image: myapp\n",
        )
        report = run_iac_scan(str(tmp_path))
        assert report["summary"]["files_scanned"] == 2

    def test_findings_sorted_by_severity(self, tmp_path):
        write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                privileged: true
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
            """,
        )
        report = run_iac_scan(str(tmp_path))
        findings = report["findings"]
        severities = [f["severity"] for f in findings]
        rank_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ranked = [rank_map.get(s, 0) for s in severities]
        assert ranked == sorted(ranked, reverse=True)

    def test_remediation_priority_only_critical_high(self, tmp_path):
        write_file(
            tmp_path,
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp
                privileged: true
            """,
        )
        report = run_iac_scan(str(tmp_path))
        for item in report["remediation_priority"]:
            assert any(sev in item for sev in ("IAC-C001", "IAC-C003", "IAC-D001", "IAC-D003"))

    def test_empty_directory_no_crash(self, tmp_path):
        report = run_iac_scan(str(tmp_path))
        assert report["summary"]["files_scanned"] == 0
        assert report["summary"]["total_findings"] == 0
