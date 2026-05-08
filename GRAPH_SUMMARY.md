# Guardian S-SDLC — Project Graph Summary
> Auto-generated 2026-05-08 | 137 tests passing

Load this file at the start of a Claude session to bootstrap full project
understanding without reading every source file (~800 tokens).

---

## Module Map

| File | Lines | Purpose | Key Exports |
|------|-------|---------|-------------|
| `src/client/consultant.py` | 394 | guardian-ssdlc · client/consultant.py | print_banner, print_examples, print_tools, stream_agent_response, GUARDIAN_THEME, SYSTEM_PROMPT… |
| `src/server/main.py` | 310 | guardian-ssdlc · server/main.py | check_dependencies, generate_threat_model_tool, audit_compliance, scan_secrets |
| `src/server/tools/compliance.py` | 412 | guardian-ssdlc · tools/compliance.py | _load_yaml, _get_nist, _get_owasp, _normalize_finding_dict, FindingInput, AuditComplianceInput… |
| `src/server/tools/sca.py` | 374 | guardian-ssdlc · tools/sca.py | _parse_osv_response, _query_osv, _load_packages, run_sca, CheckDependenciesInput, _OSV_API_URL… |
| `src/server/tools/secret_scanner.py` | 564 | guardian-ssdlc · tools/secret_scanner.py | _calculate_entropy, _iter_files, _scan_content, run_secret_scan, ScanSecretsInput, MAX_FILE_SIZE_BYTES… |
| `src/server/tools/threat_model.py` | 459 | guardian-ssdlc · tools/threat_model.py | _calculate_impact, _risk_level, generate_threat_model, run_threat_model, ComponentModel, DataFlowModel… |
| `src/utils/context_manager.py` | 671 | guardian-ssdlc · utils/context_manager.py | count_tokens, count_message_tokens, Message, ContextWindow, SecurityContext, StateCheckpoint… |
| `src/utils/helpers.py` | 497 | guardian-ssdlc · utils/helpers.py | severity_rank, normalize_package_name, parse_requirements_txt, parse_package_json, Severity, SECRET_PATTERNS… |

---

## Internal Dependency Graph

```
src/utils/helpers.py          ← imported by sca, secret_scanner, compliance
src/utils/context_manager.py  ← standalone, used by client
src/server/tools/sca.py       ← main.py → check_dependencies
src/server/tools/threat_model.py ← main.py → generate_threat_model
src/server/tools/compliance.py   ← main.py → audit_compliance
src/server/tools/secret_scanner.py ← main.py → scan_secrets, scan_git_history
src/server/main.py            ← spawned by consultant.py via stdio MCP
src/client/consultant.py      ← entry-point, LangGraph ReAct agent
```

---

## MCP Tools Registry

| MCP Tool Name | Entry Point | Source Module | Tests |
|---------------|-------------|---------------|-------|
| `check_dependencies` | `check_dependencies` | `src/server/tools/sca.py` | tests/test_sca.py, tests/test_tools.py |
| `generate_threat_model` | `generate_threat_model_tool` | `src/server/tools/threat_model.py` | tests/test_threat_model.py, tests/test_tools.py |
| `audit_compliance` | `audit_compliance` | `src/server/tools/compliance.py` | tests/test_compliance.py, tests/test_tools.py |
| `scan_secrets` | `scan_secrets` | `src/server/tools/secret_scanner.py` | tests/test_secret_scanner.py, tests/test_tools.py |
| `scan_git_history` | `scan_git_history_tool` | `src/server/tools/secret_scanner.py` | — |

---

## Task → Files Quick Reference

| Task | Read First | Edit |
|------|-----------|------|
| Add a secret detection pattern | `src/utils/helpers.py:SECRET_PATTERNS` | `src/utils/helpers.py` |
| Add a vulnerability to mock DB | `src/utils/helpers.py:OSV_MOCK_DB` | `src/utils/helpers.py` |
| Add/change NIST mapping | `data/policies/nist_800_53.yaml` | `data/policies/nist_800_53.yaml` |
| Add/change OWASP mapping | `data/policies/owasp_top10.yaml` | `data/policies/owasp_top10.yaml` |
| Add a new MCP tool | `src/server/main.py + any tool file for pattern` | `src/server/main.py + new src/server/tools/xxx.py` |
| Fix SCA/dependency logic | `src/server/tools/sca.py` | `src/server/tools/sca.py` |
| Fix threat model logic | `src/server/tools/threat_model.py:STRIDE_CATALOGUE` | `src/server/tools/threat_model.py` |
| Fix compliance logic | `src/server/tools/compliance.py + data/policies/` | `src/server/tools/compliance.py` |
| Fix secret scanner | `src/server/tools/secret_scanner.py` | `src/server/tools/secret_scanner.py` |
| Adjust token budget/eviction | `src/utils/context_manager.py:ContextWindow` | `src/utils/context_manager.py` |
| Add/fix a test | `tests/test_tools.py for integration pattern` | `relevant tests/ file` |
| Change OSV to live API | `src/server/tools/sca.py:_query_osv` | `src/server/tools/sca.py + .env GUARDIAN_LIVE_OSV=true` |

---

## Key Data Structures

| Symbol | Location | Shape |
|--------|----------|-------|
| `SECRET_PATTERNS` | helpers.py | `list[tuple[label, regex, severity, description]]` |
| `OSV_MOCK_DB` | helpers.py | `dict[package_name, list[vuln_dict]]` |
| `STRIDE_CATALOGUE` | threat_model.py | `dict[stride_key, {code, triggers, mitigations, …}]` |
| `FINDING_TYPE_ALIASES` | compliance.py | `dict[informal_name, canonical_type]` |
| `ContextWindow` | context_manager.py | rolling token-budgeted message list |
| `SecurityContext` | context_manager.py | scan result store with tiered summaries |
| `StateCheckpoint` | context_manager.py | JSON serializer to `.guardian_state/` |

---

## Config & Environment

| Variable | Default | Effect |
|----------|---------|--------|
| `GOOGLE_API_KEY` | required | Gemini access |
| `GEMINI_MODEL` | `gemini-1.5-pro` | LLM model |
| `GUARDIAN_LIVE_OSV` | unset (mock) | Set `true` to query osv.dev API live |
| `TEMPERATURE` | `0.2` | LLM temperature |
| `MAX_TOKENS` | `8192` | LLM max output tokens |

---

## Test File Map

| Test File | Covers |
|-----------|--------|
| `tests/test_sca.py` | `run_sca()` internals, mock DB queries |
| `tests/test_threat_model.py` | `generate_threat_model()` STRIDE logic |
| `tests/test_compliance.py` | `run_compliance_audit()` YAML policy loading |
| `tests/test_secret_scanner.py` | regex patterns, `_scan_content`, entropy |
| `tests/test_context_manager.py` | all 6 context manager classes, 55 tests |
| `tests/test_tools.py` | public wrapper API: `run_dependency_check`, `run_threat_model`, `run_compliance_audit`, `run_secret_scan` |

**Run all tests:** `python -m pytest`
**Run one file:** `python -m pytest tests/test_sca.py -v`