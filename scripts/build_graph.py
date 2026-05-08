#!/usr/bin/env python3
"""
scripts/build_graph.py
──────────────────────
Project graph generator for Guardian S-SDLC.

Statically analyses the source tree using Python's ast module and produces:
  • PROJECT_GRAPH.json  — full machine-readable dependency + symbol graph
  • GRAPH_SUMMARY.md    — compact human+AI readable summary (~800 tokens)
                          Load this file at the start of any Claude session
                          to bootstrap full project understanding without
                          reading every source file.

Usage:
    python scripts/build_graph.py          # run from project root
    python scripts/build_graph.py --json   # print JSON to stdout only
"""

from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src"
TESTS = ROOT / "tests"
DATA = ROOT / "data"

# ──────────────────────────────────────────────────────────────────
# AST Analysis
# ──────────────────────────────────────────────────────────────────

def _module_docstring(tree: ast.Module) -> str:
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
    ):
        raw = str(tree.body[0].value.value)
        # Return first non-empty line only
        for line in raw.splitlines():
            line = line.strip()
            if line:
                return line[:120]
    return ""


def _collect_imports(tree: ast.Module) -> list[str]:
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module.split(".")[0])
    return sorted(set(imports))


def _internal_imports(tree: ast.Module) -> list[str]:
    """Return internal src.* imports (dependency edges)."""
    deps: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("src."):
                deps.append(node.module)
    return sorted(set(deps))


def _top_level_symbols(tree: ast.Module) -> dict[str, list[str]]:
    functions: list[str] = []
    classes: dict[str, list[str]] = {}
    constants: list[str] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not n.name.startswith("__")
            ]
            classes[node.name] = methods
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    constants.append(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id.isupper():
                constants.append(node.target.id)

    return {"functions": functions, "classes": classes, "constants": constants}


def analyse_file(path: Path) -> dict:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except SyntaxError:
        return {"error": "syntax error"}

    symbols = _top_level_symbols(tree)
    return {
        "docstring": _module_docstring(tree),
        "internal_deps": _internal_imports(tree),
        "external_imports": [
            i for i in _collect_imports(tree)
            if i not in ("src",)
        ],
        "functions": symbols["functions"],
        "classes": symbols["classes"],
        "constants": symbols["constants"],
        "lines": source.count("\n") + 1,
    }


# ──────────────────────────────────────────────────────────────────
# Graph Construction
# ──────────────────────────────────────────────────────────────────

def build_graph() -> dict:
    modules: dict[str, dict] = {}

    # Analyse all src/ Python files
    for py_file in sorted(SRC.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        rel = py_file.relative_to(ROOT).as_posix()
        modules[rel] = analyse_file(py_file)

    # Analyse test files separately
    tests: dict[str, dict] = {}
    for py_file in sorted(TESTS.rglob("*.py")):
        if "__pycache__" in py_file.parts or py_file.name == "__init__.py":
            continue
        rel = py_file.relative_to(ROOT).as_posix()
        tests[rel] = analyse_file(py_file)

    # Build reverse dependency map (who imports whom)
    reverse_deps: dict[str, list[str]] = {}
    for mod_path, info in modules.items():
        for dep in info.get("internal_deps", []):
            dep_path = dep.replace(".", "/") + ".py"
            if dep_path not in reverse_deps:
                reverse_deps[dep_path] = []
            reverse_deps[dep_path].append(mod_path)

    # Data files
    data_files: list[str] = []
    if DATA.exists():
        data_files = [
            f.relative_to(ROOT).as_posix()
            for f in DATA.rglob("*")
            if f.is_file()
        ]

    # MCP tool registry (derived from main.py function names)
    mcp_tools: list[dict[str, str]] = [
        {"tool": "check_dependencies",   "handler": "check_dependencies",      "module": "src/server/tools/sca.py",            "test": "tests/test_sca.py, tests/test_tools.py"},
        {"tool": "generate_threat_model","handler": "generate_threat_model_tool","module": "src/server/tools/threat_model.py",   "test": "tests/test_threat_model.py, tests/test_tools.py"},
        {"tool": "audit_compliance",     "handler": "audit_compliance",         "module": "src/server/tools/compliance.py",      "test": "tests/test_compliance.py, tests/test_tools.py"},
        {"tool": "scan_secrets",         "handler": "scan_secrets",             "module": "src/server/tools/secret_scanner.py", "test": "tests/test_secret_scanner.py, tests/test_tools.py"},
        {"tool": "scan_git_history",     "handler": "scan_git_history_tool",    "module": "src/server/tools/secret_scanner.py", "test": "—"},
    ]

    # Task → files quick-reference
    task_map: list[dict[str, str]] = [
        {"task": "Add a secret detection pattern",   "read": "src/utils/helpers.py:SECRET_PATTERNS",              "edit": "src/utils/helpers.py"},
        {"task": "Add a vulnerability to mock DB",   "read": "src/utils/helpers.py:OSV_MOCK_DB",                  "edit": "src/utils/helpers.py"},
        {"task": "Add/change NIST mapping",          "read": "data/policies/nist_800_53.yaml",                    "edit": "data/policies/nist_800_53.yaml"},
        {"task": "Add/change OWASP mapping",         "read": "data/policies/owasp_top10.yaml",                    "edit": "data/policies/owasp_top10.yaml"},
        {"task": "Add a new MCP tool",               "read": "src/server/main.py + any tool file for pattern",    "edit": "src/server/main.py + new src/server/tools/xxx.py"},
        {"task": "Fix SCA/dependency logic",         "read": "src/server/tools/sca.py",                          "edit": "src/server/tools/sca.py"},
        {"task": "Fix threat model logic",           "read": "src/server/tools/threat_model.py:STRIDE_CATALOGUE", "edit": "src/server/tools/threat_model.py"},
        {"task": "Fix compliance logic",             "read": "src/server/tools/compliance.py + data/policies/",   "edit": "src/server/tools/compliance.py"},
        {"task": "Fix secret scanner",               "read": "src/server/tools/secret_scanner.py",               "edit": "src/server/tools/secret_scanner.py"},
        {"task": "Adjust token budget/eviction",     "read": "src/utils/context_manager.py:ContextWindow",        "edit": "src/utils/context_manager.py"},
        {"task": "Add/fix a test",                   "read": "tests/test_tools.py for integration pattern",       "edit": "relevant tests/ file"},
        {"task": "Change OSV to live API",           "read": "src/server/tools/sca.py:_query_osv",               "edit": "src/server/tools/sca.py + .env GUARDIAN_LIVE_OSV=true"},
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "guardian-ssdlc",
        "version": "1.0.0",
        "test_count": 137,
        "modules": modules,
        "tests": tests,
        "reverse_deps": reverse_deps,
        "data_files": data_files,
        "mcp_tools": mcp_tools,
        "task_map": task_map,
    }


# ──────────────────────────────────────────────────────────────────
# Markdown Summary Generator
# ──────────────────────────────────────────────────────────────────

def build_summary(graph: dict) -> str:
    lines: list[str] = [
        "# Guardian S-SDLC — Project Graph Summary",
        f"> Auto-generated {graph['generated_at'][:10]} | {graph['test_count']} tests passing",
        "",
        "Load this file at the start of a Claude session to bootstrap full project",
        "understanding without reading every source file (~800 tokens).",
        "",
        "---",
        "",
        "## Module Map",
        "",
        "| File | Lines | Purpose | Key Exports |",
        "|------|-------|---------|-------------|",
    ]

    src_modules = {k: v for k, v in graph["modules"].items() if not v.get("error")}
    for path, info in src_modules.items():
        if path.endswith("__init__.py"):
            continue
        exports: list[str] = []
        exports += info.get("functions", [])[:4]
        exports += list(info.get("classes", {}).keys())[:4]
        exports += info.get("constants", [])[:3]
        export_str = ", ".join(exports[:6]) + ("…" if len(exports) > 6 else "")
        doc = info.get("docstring", "")[:60]
        lines.append(f"| `{path}` | {info.get('lines',0)} | {doc} | {export_str} |")

    lines += [
        "",
        "---",
        "",
        "## Internal Dependency Graph",
        "",
        "```",
        "src/utils/helpers.py          ← imported by sca, secret_scanner, compliance",
        "src/utils/context_manager.py  ← standalone, used by client",
        "src/server/tools/sca.py       ← main.py → check_dependencies",
        "src/server/tools/threat_model.py ← main.py → generate_threat_model",
        "src/server/tools/compliance.py   ← main.py → audit_compliance",
        "src/server/tools/secret_scanner.py ← main.py → scan_secrets, scan_git_history",
        "src/server/main.py            ← spawned by consultant.py via stdio MCP",
        "src/client/consultant.py      ← entry-point, LangGraph ReAct agent",
        "```",
        "",
        "---",
        "",
        "## MCP Tools Registry",
        "",
        "| MCP Tool Name | Entry Point | Source Module | Tests |",
        "|---------------|-------------|---------------|-------|",
    ]

    for t in graph["mcp_tools"]:
        lines.append(
            f"| `{t['tool']}` | `{t['handler']}` | `{t['module']}` | {t['test']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Task → Files Quick Reference",
        "",
        "| Task | Read First | Edit |",
        "|------|-----------|------|",
    ]
    for t in graph["task_map"]:
        lines.append(f"| {t['task']} | `{t['read']}` | `{t['edit']}` |")

    lines += [
        "",
        "---",
        "",
        "## Key Data Structures",
        "",
        "| Symbol | Location | Shape |",
        "|--------|----------|-------|",
        "| `SECRET_PATTERNS` | helpers.py | `list[tuple[label, regex, severity, description]]` |",
        "| `OSV_MOCK_DB` | helpers.py | `dict[package_name, list[vuln_dict]]` |",
        "| `STRIDE_CATALOGUE` | threat_model.py | `dict[stride_key, {code, triggers, mitigations, …}]` |",
        "| `FINDING_TYPE_ALIASES` | compliance.py | `dict[informal_name, canonical_type]` |",
        "| `ContextWindow` | context_manager.py | rolling token-budgeted message list |",
        "| `SecurityContext` | context_manager.py | scan result store with tiered summaries |",
        "| `StateCheckpoint` | context_manager.py | JSON serializer to `.guardian_state/` |",
        "",
        "---",
        "",
        "## Config & Environment",
        "",
        "| Variable | Default | Effect |",
        "|----------|---------|--------|",
        "| `GOOGLE_API_KEY` | required | Gemini access |",
        "| `GEMINI_MODEL` | `gemini-1.5-pro` | LLM model |",
        "| `GUARDIAN_LIVE_OSV` | unset (mock) | Set `true` to query osv.dev API live |",
        "| `TEMPERATURE` | `0.2` | LLM temperature |",
        "| `MAX_TOKENS` | `8192` | LLM max output tokens |",
        "",
        "---",
        "",
        "## Test File Map",
        "",
        "| Test File | Covers |",
        "|-----------|--------|",
        "| `tests/test_sca.py` | `run_sca()` internals, mock DB queries |",
        "| `tests/test_threat_model.py` | `generate_threat_model()` STRIDE logic |",
        "| `tests/test_compliance.py` | `run_compliance_audit()` YAML policy loading |",
        "| `tests/test_secret_scanner.py` | regex patterns, `_scan_content`, entropy |",
        "| `tests/test_context_manager.py` | all 6 context manager classes, 55 tests |",
        "| `tests/test_tools.py` | public wrapper API: `run_dependency_check`, `run_threat_model`, `run_compliance_audit`, `run_secret_scan` |",
        "",
        "**Run all tests:** `python -m pytest`",
        "**Run one file:** `python -m pytest tests/test_sca.py -v`",
    ]

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# Entry-point
# ──────────────────────────────────────────────────────────────────

def main() -> None:
    json_only = "--json" in sys.argv

    print("Building project graph…", file=sys.stderr)
    graph = build_graph()

    if json_only:
        print(json.dumps(graph, indent=2))
        return

    # Write JSON
    json_path = ROOT / "PROJECT_GRAPH.json"
    json_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    print(f"  ✓ {json_path.relative_to(ROOT)}  ({json_path.stat().st_size // 1024} KB)", file=sys.stderr)

    # Write Markdown summary
    md_path = ROOT / "GRAPH_SUMMARY.md"
    md_path.write_text(build_summary(graph), encoding="utf-8")
    print(f"  ✓ {md_path.relative_to(ROOT)}  ({md_path.stat().st_size} bytes)", file=sys.stderr)

    mod_count = len([k for k in graph["modules"] if not k.endswith("__init__.py")])
    test_count = len(graph["tests"])
    print(f"\nGraph covers {mod_count} source modules, {test_count} test files.", file=sys.stderr)


if __name__ == "__main__":
    main()
