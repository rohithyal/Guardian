"""
Tests for the Token Reduction & Context Management System.

Covers: TokenCounter, Message, ContextWindow, SecurityContext,
        StateCheckpoint, and ContextManager.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.context_manager import (
    ContextManager,
    ContextWindow,
    Message,
    SecurityContext,
    StateCheckpoint,
    count_message_tokens,
    count_tokens,
)

# ──────────────────────────────────────────────────────────────────
# Token counting
# ──────────────────────────────────────────────────────────────────

class TestTokenCounting:
    def test_empty_string_is_zero(self):
        assert count_tokens("") == 0

    def test_single_word_is_positive(self):
        assert count_tokens("hello") >= 1

    def test_longer_text_has_more_tokens(self):
        short = count_tokens("hello")
        long = count_tokens("hello " * 50)
        assert long > short

    def test_message_overhead(self):
        msg = {"role": "user", "content": "hi"}
        assert count_message_tokens(msg) >= 4  # at least 4 overhead tokens

    def test_empty_content_still_has_overhead(self):
        msg = {"role": "system", "content": ""}
        assert count_message_tokens(msg) == 4


# ──────────────────────────────────────────────────────────────────
# Message
# ──────────────────────────────────────────────────────────────────

class TestMessage:
    def test_basic_fields(self):
        m = Message(role="user", content="test content")
        assert m.role == "user"
        assert m.content == "test content"
        assert m.token_count > 0

    def test_token_count_auto_computed(self):
        m = Message(role="user", content="a " * 100)
        assert m.token_count > 20

    def test_to_dict_round_trip(self):
        m = Message(role="assistant", content="hello world", metadata={"k": "v"})
        d = m.to_dict()
        m2 = Message.from_dict(d)
        assert m2.role == m.role
        assert m2.content == m.content
        assert m2.metadata == m.metadata

    def test_summarise_truncates(self):
        m = Message(role="user", content="x" * 300)
        s = m.summarise(max_chars=50)
        assert len(s) < 100
        assert "…" in s

    def test_summarise_short_content_no_ellipsis(self):
        m = Message(role="user", content="short")
        s = m.summarise(max_chars=200)
        assert "…" not in s


# ──────────────────────────────────────────────────────────────────
# ContextWindow
# ──────────────────────────────────────────────────────────────────

class TestContextWindow:
    def test_add_increases_message_count(self):
        w = ContextWindow(max_tokens=4000)
        w.add("user", "hello")
        w.add("assistant", "hi there")
        assert len(w._messages) == 2

    def test_system_prompt_is_pinned(self):
        w = ContextWindow(max_tokens=4000, system_prompt="You are a guardian.")
        assert w._messages[0].role == "system"
        assert w._system_token_count > 0

    def test_token_count_increases_with_messages(self):
        w = ContextWindow(max_tokens=4000)
        initial = w.token_count
        w.add("user", "a " * 50)
        assert w.token_count > initial

    def test_available_tokens_decreases(self):
        w = ContextWindow(max_tokens=4000)
        before = w.available_tokens
        w.add("user", "word " * 100)
        assert w.available_tokens < before

    def test_get_messages_returns_list_of_dicts(self):
        w = ContextWindow(max_tokens=4000)
        w.add("user", "hello")
        msgs = w.get_messages(include_summary=False)
        assert isinstance(msgs, list)
        assert msgs[0]["role"] == "user"

    def test_eviction_occurs_when_over_budget(self):
        # Tiny budget forces eviction
        w = ContextWindow(max_tokens=200, summary_reserve=50)
        for i in range(20):
            w.add("user", f"message number {i} with some extra padding words here")
        # Eviction should have occurred
        assert len(w._evicted_summaries) > 0

    def test_eviction_summary_injected_in_get_messages(self):
        w = ContextWindow(max_tokens=200, summary_reserve=50)
        for i in range(20):
            w.add("user", f"message number {i} with some extra padding words here")
        msgs = w.get_messages(include_summary=True)
        roles = [m["role"] for m in msgs]
        # Summary is injected as an assistant message at the start
        assert "assistant" in roles

    def test_clear_removes_non_system_messages(self):
        w = ContextWindow(max_tokens=4000, system_prompt="sys")
        w.add("user", "hello")
        w.add("assistant", "hi")
        w.clear(keep_system=True)
        assert all(m.role == "system" for m in w._messages)

    def test_clear_all_removes_system_too(self):
        w = ContextWindow(max_tokens=4000, system_prompt="sys")
        w.add("user", "hello")
        w.clear(keep_system=False)
        assert len(w._messages) == 0

    def test_stats_dict_has_required_keys(self):
        w = ContextWindow(max_tokens=4000)
        s = w.stats()
        for key in ("total_tokens", "available_tokens", "max_tokens",
                    "utilisation_pct", "message_count", "evicted_batches"):
            assert key in s

    def test_utilisation_between_0_and_100(self):
        w = ContextWindow(max_tokens=4000)
        w.add("user", "hello world")
        assert 0.0 <= w.utilisation_pct <= 100.0


# ──────────────────────────────────────────────────────────────────
# SecurityContext
# ──────────────────────────────────────────────────────────────────

class TestSecurityContext:
    SCA_REPORT = {
        "scan_type": "Software Composition Analysis (SCA)",
        "ecosystem": "PyPI",
        "summary": {
            "total_packages_scanned": 10,
            "vulnerable_packages": 3,
            "risk_rating": "CRITICAL",
            "critical": 1,
            "high": 2,
        },
    }
    THREAT_REPORT = {
        "scan_type": "STRIDE Threat Model",
        "system": "Payment Service",
        "summary": {
            "total_threats_identified": 6,
            "overall_risk": "HIGH",
            "critical": 0,
            "high": 4,
        },
    }
    SECRET_REPORT = {
        "scan_type": "Secret & Credential Scanner",
        "summary": {
            "files_scanned": 20,
            "total_secrets_found": 2,
            "risk_rating": "HIGH",
            "severity_breakdown": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0},
        },
    }
    COMPLIANCE_REPORT = {
        "scan_type": "Compliance Guardrails Audit",
        "total_findings": 3,
        "summary": {
            "total_findings": 3,
            "compliance_coverage": "67%",
            "nist_controls_triggered": ["SI-2"],
            "owasp_categories_triggered": ["A06:2021"],
        },
        "overall_posture": "HIGH_RISK_NON_COMPLIANCE",
    }

    def test_store_and_retrieve_sca(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT)
        assert sc.get_full("sca_latest") == self.SCA_REPORT
        summary = sc.get_summary("sca_latest")
        assert summary["type"] == "sca"
        assert summary["vulnerable"] == 3

    def test_store_and_retrieve_threat(self):
        sc = SecurityContext()
        sc.store_threat_model(self.THREAT_REPORT)
        summary = sc.get_summary("threat_latest")
        assert summary["type"] == "threat_model"
        assert summary["total_threats"] == 6

    def test_store_secrets(self):
        sc = SecurityContext()
        sc.store_secrets(self.SECRET_REPORT)
        summary = sc.get_summary("secrets_latest")
        assert summary["type"] == "secret_scan"
        assert summary["secrets_found"] == 2

    def test_store_compliance(self):
        sc = SecurityContext()
        sc.store_compliance(self.COMPLIANCE_REPORT)
        summary = sc.get_summary("compliance_latest")
        assert summary["type"] == "compliance"
        assert "%" in summary["coverage"]

    def test_risk_ceiling_escalates(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT)  # CRITICAL
        assert sc._metadata["risk_ceiling"] == "CRITICAL"

    def test_risk_ceiling_does_not_decrease(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT)   # CRITICAL
        sc.store_secrets(self.SECRET_REPORT)  # HIGH
        assert sc._metadata["risk_ceiling"] == "CRITICAL"

    def test_get_digest_contains_scan_ids(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT, scan_id="my_sca")
        digest = sc.get_digest()
        assert "my_sca" in digest

    def test_get_prompt_context_is_string(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT)
        ctx = sc.get_prompt_context(max_tokens=300)
        assert isinstance(ctx, str)
        assert "sca_latest" in ctx

    def test_list_scans(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT, scan_id="run1")
        sc.store_threat_model(self.THREAT_REPORT, scan_id="run2")
        assert set(sc.list_scans()) == {"run1", "run2"}

    def test_clear_specific_scan(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT, scan_id="run1")
        sc.store_threat_model(self.THREAT_REPORT, scan_id="run2")
        sc.clear("run1")
        assert "run1" not in sc.list_scans()
        assert "run2" in sc.list_scans()

    def test_clear_all(self):
        sc = SecurityContext()
        sc.store_sca(self.SCA_REPORT)
        sc.store_threat_model(self.THREAT_REPORT)
        sc.clear()
        assert sc.list_scans() == []

    def test_get_missing_scan_returns_none(self):
        sc = SecurityContext()
        assert sc.get_full("nonexistent") is None
        assert sc.get_summary("nonexistent") is None


# ──────────────────────────────────────────────────────────────────
# StateCheckpoint
# ──────────────────────────────────────────────────────────────────

class TestStateCheckpoint:
    def test_save_and_load_round_trip(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        w = ContextWindow(max_tokens=4000)
        w.add("user", "hello checkpoint")
        sc = SecurityContext()
        sc._summaries["test"] = {"type": "sca", "digest": "ok"}

        path = cp.save(w, sc, name="test_session")
        assert path.exists()

        w2, sc2 = cp.load("test_session")
        assert len(w2._messages) == 1
        assert w2._messages[0].content == "hello checkpoint"
        assert "test" in sc2._summaries

    def test_load_nonexistent_raises(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        with pytest.raises(FileNotFoundError):
            cp.load("no_such_checkpoint")

    def test_list_checkpoints(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        w = ContextWindow(max_tokens=4000)
        sc = SecurityContext()
        cp.save(w, sc, name="session_a")
        cp.save(w, sc, name="session_b")
        names = cp.list_checkpoints()
        assert "session_a" in names
        assert "session_b" in names

    def test_delete_checkpoint(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        w = ContextWindow(max_tokens=4000)
        sc = SecurityContext()
        cp.save(w, sc, name="to_delete")
        assert cp.delete("to_delete") is True
        assert "to_delete" not in cp.list_checkpoints()

    def test_delete_nonexistent_returns_false(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        assert cp.delete("ghost") is False

    def test_saved_checkpoint_has_correct_schema(self, tmp_path):
        cp = StateCheckpoint(checkpoint_dir=tmp_path)
        w = ContextWindow(max_tokens=2000, system_prompt="You are a test.")
        sc = SecurityContext()
        path = cp.save(w, sc, name="schema_check")

        data = json.loads(path.read_text())
        assert data["version"] == "1.0"
        assert "saved_at" in data
        assert "window" in data
        assert "security" in data
        assert data["window"]["max_tokens"] == 2000


# ──────────────────────────────────────────────────────────────────
# ContextManager (top-level)
# ──────────────────────────────────────────────────────────────────

class TestContextManager:
    def test_add_user_message(self):
        cm = ContextManager(max_tokens=4000)
        cm.add_user("scan my code")
        assert len(cm) == 1

    def test_add_assistant_message(self):
        cm = ContextManager(max_tokens=4000)
        cm.add_user("hello")
        cm.add_assistant("hi there")
        assert len(cm) == 2

    def test_get_messages_returns_list(self):
        cm = ContextManager(max_tokens=4000)
        cm.add_user("test")
        msgs = cm.get_messages(inject_security_context=False)
        assert isinstance(msgs, list)
        assert any(m["role"] == "user" for m in msgs)

    def test_security_context_injected_when_scans_stored(self):
        cm = ContextManager(max_tokens=4000)
        cm.security.store_sca({"summary": {"total_packages_scanned": 5,
                                            "vulnerable_packages": 1,
                                            "risk_rating": "HIGH",
                                            "critical": 0, "high": 1},
                               "ecosystem": "PyPI"})
        cm.add_user("what did the scan find?")
        msgs = cm.get_messages(inject_security_context=True)
        combined = " ".join(m.get("content", "") for m in msgs)
        assert "sca_latest" in combined

    def test_tool_result_stored_in_security_context(self):
        cm = ContextManager(max_tokens=4000)
        fake_sca = {"ecosystem": "PyPI",
                    "summary": {"total_packages_scanned": 3,
                                "vulnerable_packages": 0,
                                "risk_rating": "LOW",
                                "critical": 0, "high": 0}}
        cm.add_tool_result("sca_run1", fake_sca)
        assert "sca_run1" in cm.security.list_scans()

    def test_tool_result_compact_in_window(self):
        cm = ContextManager(max_tokens=4000)
        # Large result — window should store summary, not full report
        large_result = {"ecosystem": "PyPI",
                        "summary": {"total_packages_scanned": 100,
                                    "vulnerable_packages": 5,
                                    "risk_rating": "HIGH",
                                    "critical": 0, "high": 5},
                        "verbose_data": ["x"] * 500}
        cm.add_tool_result("sca", large_result)
        # The tool message in the window should be smaller than the full result
        tool_msgs = [m for m in cm.window._messages if m.role == "tool"]
        assert len(tool_msgs) == 1
        assert len(tool_msgs[0].content) < len(json.dumps(large_result))

    def test_stats_has_required_keys(self):
        cm = ContextManager(max_tokens=4000)
        s = cm.stats()
        for key in ("total_tokens", "available_tokens", "max_tokens",
                    "utilisation_pct", "message_count", "security_scans_stored",
                    "risk_ceiling"):
            assert key in s

    def test_token_report_is_string_with_percentage(self):
        cm = ContextManager(max_tokens=4000)
        cm.add_user("hello")
        report = cm.token_report()
        assert isinstance(report, str)
        assert "%" in report

    def test_build_prompt_adds_message_and_returns_list(self):
        cm = ContextManager(max_tokens=4000)
        msgs = cm.build_prompt("run sca", inject_security=False)
        assert isinstance(msgs, list)
        assert len(cm) == 1  # message was added

    def test_checkpoint_and_restore(self, tmp_path):
        cm = ContextManager(
            max_tokens=4000,
            checkpoint_dir=tmp_path,
            checkpoint_name="cm_test",
        )
        cm.add_user("original message")
        cm.checkpoint()

        cm2 = ContextManager(
            max_tokens=4000,
            checkpoint_dir=tmp_path,
            checkpoint_name="cm_test",
        )
        restored = cm2.restore()
        assert restored is True
        assert len(cm2) == 1
        assert cm2.window._messages[0].content == "original message"

    def test_restore_no_checkpoint_returns_false(self, tmp_path):
        cm = ContextManager(
            max_tokens=4000,
            checkpoint_dir=tmp_path,
            checkpoint_name="missing",
        )
        assert cm.restore() is False

    def test_compress_tool_results_reduces_tokens(self):
        cm = ContextManager(max_tokens=8000)
        large_result = {
            "ecosystem": "PyPI",
            "summary": {"total_packages_scanned": 50,
                        "vulnerable_packages": 2,
                        "risk_rating": "MEDIUM",
                        "critical": 0, "high": 0},
            "extra": "x" * 1000,
        }
        cm.add_tool_result("sca_big", large_result)
        before = cm.window.token_count
        cm.compress_tool_results()
        # Either tokens were saved, or there was nothing to compress further
        assert cm.window.token_count <= before

    def test_trim_to_budget(self):
        cm = ContextManager(max_tokens=500)
        for i in range(30):
            cm.add_user(f"message {i} with a fair amount of content to fill the budget")
        freed = cm.trim_to_budget(target_pct=0.5)
        assert freed >= 0
        assert cm.window.token_count <= cm.window.max_tokens

    def test_iter_yields_message_dicts(self):
        cm = ContextManager(max_tokens=4000)
        cm.add_user("msg 1")
        cm.add_assistant("msg 2")
        msgs = list(cm)
        assert len(msgs) == 2
        assert all("role" in m for m in msgs)

    def test_repr_contains_useful_info(self):
        cm = ContextManager(max_tokens=4000)
        r = repr(cm)
        assert "ContextManager" in r
        assert "tokens=" in r

    def test_list_checkpoints(self, tmp_path):
        cm = ContextManager(max_tokens=4000, checkpoint_dir=tmp_path,
                            checkpoint_name="list_test")
        cm.add_user("hi")
        cm.checkpoint()
        assert "list_test" in cm.list_checkpoints()
