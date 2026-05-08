"""
guardian-ssdlc · utils/context_manager.py
──────────────────────────────────────────
Token Reduction & Context Management System.

Manages LLM context windows to stay within token budgets by:
  - Counting tokens (char-based estimate; swap for tiktoken in production)
  - Maintaining a rolling message window with configurable budget
  - Summarising evicted messages so no history is fully lost
  - Checkpointing conversation state to disk for session persistence
  - Providing a SecurityContext that carries scan results across turns
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("guardian.context_manager")

# ──────────────────────────────────────────────────────────────────
# 1. TOKEN COUNTING
# ──────────────────────────────────────────────────────────────────

# 1 token ≈ 4 chars for English prose (GPT/Gemini rule of thumb).
_CHARS_PER_TOKEN: float = 4.0

# Try to import tiktoken for accurate OpenAI-style token counting.
try:
    import tiktoken as _tiktoken  # type: ignore[import]

    _ENCODER = _tiktoken.get_encoding("cl100k_base")
    _USE_TIKTOKEN = True
except Exception:
    _ENCODER = None
    _USE_TIKTOKEN = False


def count_tokens(text: str) -> int:
    """Return an estimated token count for *text*."""
    if not text:
        return 0
    if _USE_TIKTOKEN and _ENCODER is not None:
        return len(_ENCODER.encode(text))
    # Fallback: char-based estimate, minimum 1 per word
    words = len(text.split())
    char_estimate = math.ceil(len(text) / _CHARS_PER_TOKEN)
    return max(words, char_estimate)


def count_message_tokens(message: dict[str, Any]) -> int:
    """Count tokens in a single chat message dict {role, content}."""
    # 4 overhead tokens per message (role + formatting)
    return 4 + count_tokens(str(message.get("content", "")))


# ──────────────────────────────────────────────────────────────────
# 2. MESSAGE MODEL
# ──────────────────────────────────────────────────────────────────


@dataclass
class Message:
    """A single conversation turn."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    token_count: int = field(init=False)

    def __post_init__(self) -> None:
        self.token_count = count_tokens(self.content) + 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "token_count": self.token_count,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Message:
        m = cls(role=d["role"], content=d["content"], timestamp=d.get("timestamp", 0.0))
        m.metadata = d.get("metadata", {})
        m.token_count = d.get("token_count", count_tokens(d["content"]) + 4)
        return m

    def summarise(self, max_chars: int = 200) -> str:
        """Return a truncated summary of this message."""
        body = self.content[:max_chars].replace("\n", " ")
        if len(self.content) > max_chars:
            body += "…"
        return f"[{self.role}] {body}"


# ──────────────────────────────────────────────────────────────────
# 3. ROLLING CONTEXT WINDOW
# ──────────────────────────────────────────────────────────────────


class ContextWindow:
    """
    Fixed-token-budget window of messages.

    Strategy:
    1. System prompt is always retained (pinned).
    2. When the budget is exceeded, the oldest non-system messages are
       evicted and replaced by a condensed summary injected as a
       synthetic assistant message.
    3. The summary carries enough signal for the model to maintain
       coherent reasoning without the full history.
    """

    def __init__(
        self,
        max_tokens: int = 8_000,
        summary_reserve: int = 500,
        system_prompt: str = "",
    ) -> None:
        self.max_tokens = max_tokens
        self.summary_reserve = summary_reserve
        self._messages: list[Message] = []
        self._evicted_summaries: list[str] = []
        self._system_token_count: int = 0

        if system_prompt:
            self._pin_system(system_prompt)

    # ── public API ────────────────────────────────────────────────

    def add(self, role: str, content: str, metadata: dict[str, Any] | None = None) -> Message:
        """Append a new message, evicting old ones if over budget."""
        msg = Message(role=role, content=content, metadata=metadata or {})
        self._messages.append(msg)
        self._enforce_budget()
        logger.debug("Window: %d msgs | %d tokens used", len(self._messages), self.token_count)
        return msg

    def get_messages(self, include_summary: bool = True) -> list[dict[str, Any]]:
        """Return messages formatted for an LLM API call."""
        out: list[dict[str, Any]] = []
        if include_summary and self._evicted_summaries:
            # Inject a compact history summary as the first non-system message
            summary_text = "Previous context (summarised):\n" + "\n".join(self._evicted_summaries)
            out.append({"role": "assistant", "content": summary_text})
        out.extend(m.to_dict() for m in self._messages)
        return out

    @property
    def token_count(self) -> int:
        return self._system_token_count + sum(m.token_count for m in self._messages)

    @property
    def available_tokens(self) -> int:
        return self.max_tokens - self.token_count

    @property
    def utilisation_pct(self) -> float:
        return round(self.token_count / self.max_tokens * 100, 1)

    def clear(self, keep_system: bool = True) -> None:
        """Reset the window, optionally preserving system messages."""
        if keep_system:
            self._messages = [m for m in self._messages if m.role == "system"]
        else:
            self._messages = []
            self._system_token_count = 0
        self._evicted_summaries.clear()

    def stats(self) -> dict[str, Any]:
        return {
            "total_tokens": self.token_count,
            "available_tokens": self.available_tokens,
            "max_tokens": self.max_tokens,
            "utilisation_pct": self.utilisation_pct,
            "message_count": len(self._messages),
            "evicted_batches": len(self._evicted_summaries),
        }

    # ── internals ─────────────────────────────────────────────────

    def _pin_system(self, prompt: str) -> None:
        sys_msg = Message(role="system", content=prompt)
        self._messages.insert(0, sys_msg)
        self._system_token_count = sys_msg.token_count

    def _enforce_budget(self) -> None:
        """Evict oldest non-system messages until within budget."""
        budget = self.max_tokens - self.summary_reserve
        while self.token_count > budget:
            evictable = [m for m in self._messages if m.role != "system"]
            if not evictable:
                break
            batch_size = max(1, len(evictable) // 4)
            to_evict = evictable[:batch_size]
            summary = self._summarise_batch(to_evict)
            self._evicted_summaries.append(summary)
            for msg in to_evict:
                self._messages.remove(msg)
            logger.info(
                "Evicted %d messages (freed ~%d tokens). Summary: %s",
                len(to_evict),
                sum(m.token_count for m in to_evict),
                summary[:80],
            )

    @staticmethod
    def _summarise_batch(messages: list[Message]) -> str:
        """Produce a compact summary string for a batch of messages."""
        parts: list[str] = []
        for m in messages:
            parts.append(m.summarise(max_chars=150))
        header = f"[{len(messages)} messages, ~{sum(m.token_count for m in messages)} tokens]"
        return header + "\n" + "\n".join(parts)


# ──────────────────────────────────────────────────────────────────
# 4. SECURITY CONTEXT  (scan result state across turns)
# ──────────────────────────────────────────────────────────────────


class SecurityContext:
    """
    Holds the results of security scans so subsequent LLM turns can
    reference them without re-scanning or re-sending full reports.

    Implements a tiered reference system:
      tier-1  full result   (in-memory, fast)
      tier-2  summary dict  (small, included in prompts)
      tier-3  digest string (minimal, fits in system prompt)
    """

    def __init__(self) -> None:
        self._scans: dict[str, dict[str, Any]] = {}  # scan_id → full result
        self._summaries: dict[str, dict[str, Any]] = {}  # scan_id → summary
        self._metadata: dict[str, Any] = {
            "session_start": time.time(),
            "total_scans": 0,
            "risk_ceiling": "CLEAN",
        }

    # ── storing results ───────────────────────────────────────────

    def store_sca(self, result: dict[str, Any], scan_id: str = "sca_latest") -> None:
        self._scans[scan_id] = result
        self._summaries[scan_id] = self._summarise_sca(result)
        self._update_risk(result.get("summary", {}).get("risk_rating", "LOW"))
        self._metadata["total_scans"] += 1
        logger.info("Stored SCA result under '%s'", scan_id)

    def store_threat_model(self, result: dict[str, Any], scan_id: str = "threat_latest") -> None:
        self._scans[scan_id] = result
        self._summaries[scan_id] = self._summarise_threat(result)
        overall = result.get("summary", {}).get("overall_risk", "LOW")
        self._update_risk(overall)
        self._metadata["total_scans"] += 1
        logger.info("Stored Threat Model result under '%s'", scan_id)

    def store_compliance(self, result: dict[str, Any], scan_id: str = "compliance_latest") -> None:
        self._scans[scan_id] = result
        self._summaries[scan_id] = self._summarise_compliance(result)
        self._metadata["total_scans"] += 1
        logger.info("Stored Compliance result under '%s'", scan_id)

    def store_secrets(self, result: dict[str, Any], scan_id: str = "secrets_latest") -> None:
        self._scans[scan_id] = result
        self._summaries[scan_id] = self._summarise_secrets(result)
        risk = result.get("summary", {}).get("risk_rating", "CLEAN")
        self._update_risk(risk)
        self._metadata["total_scans"] += 1
        logger.info("Stored Secret Scan result under '%s'", scan_id)

    # ── retrieval ─────────────────────────────────────────────────

    def get_full(self, scan_id: str) -> dict[str, Any] | None:
        return self._scans.get(scan_id)

    def get_summary(self, scan_id: str) -> dict[str, Any] | None:
        return self._summaries.get(scan_id)

    def get_digest(self) -> str:
        """Return a compact one-line digest of all stored scan results."""
        parts: list[str] = [f"[SecurityContext | risk_ceiling={self._metadata['risk_ceiling']}]"]
        for sid, summary in self._summaries.items():
            parts.append(f"  {sid}: {summary.get('digest', '?')}")
        return "\n".join(parts)

    def get_prompt_context(self, max_tokens: int = 600) -> str:
        """Return a token-budget-aware summary block for injection into prompts."""
        lines: list[str] = ["=== Security Scan Context ==="]
        budget = max_tokens
        for sid, summary in self._summaries.items():
            entry = json.dumps(summary, indent=2)
            entry_tokens = count_tokens(entry)
            if budget - entry_tokens < 50:
                lines.append(f"[{sid}: truncated — over token budget]")
                break
            lines.append(f"--- {sid} ---")
            lines.append(entry)
            budget -= entry_tokens
        lines.append("=== End Context ===")
        return "\n".join(lines)

    def list_scans(self) -> list[str]:
        return list(self._scans.keys())

    def clear(self, scan_id: str | None = None) -> None:
        if scan_id:
            self._scans.pop(scan_id, None)
            self._summaries.pop(scan_id, None)
        else:
            self._scans.clear()
            self._summaries.clear()
            self._metadata["risk_ceiling"] = "CLEAN"

    # ── summarisers ───────────────────────────────────────────────

    @staticmethod
    def _summarise_sca(result: dict[str, Any]) -> dict[str, Any]:
        s = result.get("summary", {})
        return {
            "type": "sca",
            "ecosystem": result.get("ecosystem", "?"),
            "total_packages": s.get("total_packages_scanned", 0),
            "vulnerable": s.get("vulnerable_packages", 0),
            "risk_rating": s.get("risk_rating", "?"),
            "critical": s.get("critical", 0),
            "high": s.get("high", 0),
            "digest": (
                f"SCA {result.get('ecosystem', '?')}: "
                f"{s.get('vulnerable_packages', 0)}/{s.get('total_packages_scanned', 0)} "
                f"vulnerable, risk={s.get('risk_rating', '?')}"
            ),
        }

    @staticmethod
    def _summarise_threat(result: dict[str, Any]) -> dict[str, Any]:
        s = result.get("summary", {})
        return {
            "type": "threat_model",
            "system": result.get("system", "?"),
            "total_threats": s.get("total_threats_identified", result.get("total_threats", 0)),
            "overall_risk": s.get("overall_risk", "?"),
            "critical": s.get("critical", 0),
            "high": s.get("high", 0),
            "digest": (
                f"Threat Model '{result.get('system', '?')}': "
                f"{s.get('total_threats_identified', result.get('total_threats', 0))} threats, "
                f"overall={s.get('overall_risk', '?')}"
            ),
        }

    @staticmethod
    def _summarise_compliance(result: dict[str, Any]) -> dict[str, Any]:
        s = result.get("summary", {})
        return {
            "type": "compliance",
            "frameworks": result.get("frameworks_evaluated", []),
            "total_findings": s.get("total_findings", result.get("total_findings", 0)),
            "nist_controls": len(s.get("nist_controls_triggered", [])),
            "owasp_categories": len(s.get("owasp_categories_triggered", [])),
            "coverage": s.get("compliance_coverage", "?"),
            "overall_posture": result.get("overall_posture", "?"),
            "digest": (
                f"Compliance: {s.get('total_findings', 0)} findings, "
                f"coverage={s.get('compliance_coverage', '?')}"
            ),
        }

    @staticmethod
    def _summarise_secrets(result: dict[str, Any]) -> dict[str, Any]:
        s = result.get("summary", {})
        return {
            "type": "secret_scan",
            "files_scanned": s.get("files_scanned", result.get("files_scanned", 0)),
            "secrets_found": s.get("total_secrets_found", 0),
            "risk_rating": s.get("risk_rating", "?"),
            "critical": s.get("severity_breakdown", {}).get("CRITICAL", 0),
            "digest": (
                f"Secrets: {s.get('total_secrets_found', 0)} found in "
                f"{s.get('files_scanned', 0)} files, risk={s.get('risk_rating', '?')}"
            ),
        }

    def _update_risk(self, new_risk: str) -> None:
        order = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        current = self._metadata.get("risk_ceiling", "CLEAN")
        if order.get(new_risk, 0) > order.get(current, 0):
            self._metadata["risk_ceiling"] = new_risk


# ──────────────────────────────────────────────────────────────────
# 5. STATE CHECKPOINT  (persistence)
# ──────────────────────────────────────────────────────────────────


class StateCheckpoint:
    """
    Serialises and restores ContextWindow + SecurityContext to disk.

    Checkpoint format: JSON file with:
      - version     schema version
      - saved_at    Unix timestamp
      - window      message list
      - security    security context summaries
      - metadata    session metadata
    """

    VERSION = "1.0"

    def __init__(self, checkpoint_dir: str | Path = ".guardian_state") -> None:
        self._dir = Path(checkpoint_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        window: ContextWindow,
        security_ctx: SecurityContext,
        name: str = "session",
    ) -> Path:
        """Serialise current state to a JSON checkpoint file."""
        payload: dict[str, Any] = {
            "version": self.VERSION,
            "saved_at": time.time(),
            "window": {
                "max_tokens": window.max_tokens,
                "summary_reserve": window.summary_reserve,
                "messages": [m.to_dict() for m in window._messages],
                "evicted_summaries": window._evicted_summaries,
            },
            "security": {
                "summaries": security_ctx._summaries,
                "metadata": security_ctx._metadata,
            },
        }
        path = self._dir / f"{name}.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        logger.info("Checkpoint saved → %s (%d bytes)", path, path.stat().st_size)
        return path

    def load(self, name: str = "session") -> tuple[ContextWindow, SecurityContext]:
        """Restore a previously saved checkpoint."""
        path = self._dir / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"No checkpoint found at: {path}")

        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != self.VERSION:
            logger.warning("Checkpoint version mismatch; loading anyway.")

        # Restore window
        w_data = data["window"]
        window = ContextWindow(
            max_tokens=w_data["max_tokens"],
            summary_reserve=w_data["summary_reserve"],
        )
        window._messages = [Message.from_dict(m) for m in w_data["messages"]]
        window._evicted_summaries = w_data["evicted_summaries"]
        # Recalculate system token count
        window._system_token_count = sum(
            m.token_count for m in window._messages if m.role == "system"
        )

        # Restore security context
        sec = SecurityContext()
        s_data = data["security"]
        sec._summaries = s_data.get("summaries", {})
        sec._metadata = s_data.get("metadata", sec._metadata)

        logger.info("Checkpoint loaded ← %s", path)
        return window, sec

    def list_checkpoints(self) -> list[str]:
        return [p.stem for p in self._dir.glob("*.json")]

    def delete(self, name: str) -> bool:
        path = self._dir / f"{name}.json"
        if path.exists():
            path.unlink()
            logger.info("Deleted checkpoint: %s", name)
            return True
        return False


# ──────────────────────────────────────────────────────────────────
# 6. CONTEXT MANAGER  (top-level orchestrator)
# ──────────────────────────────────────────────────────────────────


class ContextManager:
    """
    Top-level orchestrator for token-efficient LLM interactions.

    Usage::

        cm = ContextManager(max_tokens=8000)
        cm.add_user("Scan requirements.txt for CVEs")
        cm.add_tool_result("sca", sca_report)
        cm.add_assistant("Found 3 critical vulnerabilities in pyyaml…")

        messages = cm.get_messages()   # ready for LLM API
        cm.checkpoint()                # persist to disk

    Token budget is automatically enforced; old messages are evicted
    and summarised to stay within the configured limit.
    """

    def __init__(
        self,
        max_tokens: int = 8_000,
        system_prompt: str = "",
        checkpoint_dir: str | Path = ".guardian_state",
        checkpoint_name: str = "session",
        summary_reserve: int = 500,
    ) -> None:
        self.window = ContextWindow(
            max_tokens=max_tokens,
            summary_reserve=summary_reserve,
            system_prompt=system_prompt,
        )
        self.security = SecurityContext()
        self._checkpointer = StateCheckpoint(checkpoint_dir)
        self._checkpoint_name = checkpoint_name

    # ── message helpers ───────────────────────────────────────────

    def add_user(self, content: str, metadata: dict[str, Any] | None = None) -> None:
        self.window.add("user", content, metadata)

    def add_assistant(self, content: str, metadata: dict[str, Any] | None = None) -> None:
        self.window.add("assistant", content, metadata)

    def add_system(self, content: str) -> None:
        self.window.add("system", content)

    def add_tool_result(
        self,
        tool_name: str,
        result: dict[str, Any],
        store_in_security_ctx: bool = True,
    ) -> None:
        """
        Add a tool result, optionally storing it in the SecurityContext
        so full reports don't need to be re-sent in future turns.
        """
        if store_in_security_ctx:
            if "sca" in tool_name or "dependency" in tool_name:
                self.security.store_sca(result, scan_id=tool_name)
            elif "threat" in tool_name:
                self.security.store_threat_model(result, scan_id=tool_name)
            elif "compliance" in tool_name or "audit" in tool_name:
                self.security.store_compliance(result, scan_id=tool_name)
            elif "secret" in tool_name or "scan" in tool_name:
                self.security.store_secrets(result, scan_id=tool_name)

        # Only put the compact summary (not full report) into the window
        summary = self.security.get_summary(tool_name)
        content = json.dumps(summary or result, indent=2)
        self.window.add("tool", content, metadata={"tool_name": tool_name})

    # ── retrieval ─────────────────────────────────────────────────

    def get_messages(self, inject_security_context: bool = True) -> list[dict[str, Any]]:
        """Return messages ready for an LLM API call."""
        msgs = self.window.get_messages()
        if inject_security_context and self.security.list_scans():
            # Prepend compact security digest as a synthetic system message
            digest = self.security.get_prompt_context(max_tokens=400)
            msgs = [{"role": "system", "content": digest}] + msgs
        return msgs

    def build_prompt(self, user_message: str, inject_security: bool = True) -> list[dict[str, Any]]:
        """Convenience: add a user message and return the full message list."""
        self.add_user(user_message)
        return self.get_messages(inject_security_context=inject_security)

    # ── token stats ───────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        w = self.window.stats()
        w["security_scans_stored"] = len(self.security.list_scans())
        w["risk_ceiling"] = self.security._metadata.get("risk_ceiling", "CLEAN")
        return w

    def token_report(self) -> str:
        s = self.stats()
        bar_width = 30
        filled = round(bar_width * s["utilisation_pct"] / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        return (
            f"Token budget: [{bar}] {s['utilisation_pct']}% "
            f"({s['total_tokens']:,}/{s['max_tokens']:,} tokens) | "
            f"{s['message_count']} msgs | "
            f"{s['evicted_batches']} eviction(s) | "
            f"risk={s['risk_ceiling']}"
        )

    # ── persistence ───────────────────────────────────────────────

    def checkpoint(self) -> Path:
        """Persist current window and security context to disk."""
        return self._checkpointer.save(self.window, self.security, self._checkpoint_name)

    def restore(self) -> bool:
        """Restore from the last checkpoint. Returns True on success."""
        try:
            self.window, self.security = self._checkpointer.load(self._checkpoint_name)
            return True
        except FileNotFoundError:
            logger.info("No checkpoint found; starting fresh.")
            return False

    def list_checkpoints(self) -> list[str]:
        return self._checkpointer.list_checkpoints()

    # ── context compression utilities ─────────────────────────────

    def compress_tool_results(self) -> int:
        """
        Replace full tool-result messages with their summaries in-place.
        Returns the number of tokens saved.
        """
        saved = 0
        for msg in self.window._messages:
            if msg.role != "tool":
                continue
            tool_name = msg.metadata.get("tool_name", "")
            summary = self.security.get_summary(tool_name) if tool_name else None
            if summary:
                compressed = json.dumps(summary)
                old_tokens = msg.token_count
                msg.content = compressed
                msg.token_count = count_tokens(compressed) + 4
                saved += old_tokens - msg.token_count
        if saved:
            logger.info("Compression saved %d tokens from tool messages.", saved)
        return saved

    def trim_to_budget(self, target_pct: float = 0.75) -> int:
        """Force-trim messages until utilisation ≤ target_pct. Returns tokens freed."""
        target = int(self.window.max_tokens * target_pct)
        freed = self.compress_tool_results()
        while self.window.token_count > target:
            evictable = [m for m in self.window._messages if m.role not in ("system",)]
            if not evictable:
                break
            oldest = evictable[0]
            freed += oldest.token_count
            self.window._evicted_summaries.append(oldest.summarise())
            self.window._messages.remove(oldest)
        return freed

    # ── iterator ──────────────────────────────────────────────────

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.window.get_messages())

    def __len__(self) -> int:
        return len(self.window._messages)

    def __repr__(self) -> str:
        return (
            f"ContextManager("
            f"tokens={self.window.token_count}/{self.window.max_tokens}, "
            f"msgs={len(self.window._messages)}, "
            f"scans={len(self.security.list_scans())})"
        )
