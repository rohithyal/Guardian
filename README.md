# Guardian S-SDLC

An AI-powered security automation tool that catches vulnerabilities, hardcoded secrets, compliance gaps, and architectural threats — before they reach production.

---

## The problem it solves

Security reviews happen too late. By the time a pen tester or a security team audits your application, the code is already in main, the sprint is closed, and fixing things costs ten times what it would have during development. The industry calls this "shifting right" and it's expensive.

Guardian shifts security left — it runs inside your development workflow, at your terminal, during the sprint. You ask it questions in plain English and it runs real analysis: scanning your `requirements.txt` against a vulnerability database, modeling threats against your system architecture, checking your findings against NIST and OWASP controls, hunting for hardcoded secrets in your source tree. Then it explains what it found and what to do about it.

It's not a linter. It's not a SAST scanner that produces a CSV you have to manually triage. It's an interactive AI that has read the NIST 800-53 controls, knows STRIDE inside out, and can walk you through a complete security review in a conversation.

---

## What it can do

**Dependency Scanning (SCA)**  
Point it at a `requirements.txt` or `package.json`. It queries the vulnerability database, surfaces CVEs with CVSS scores, tells you which packages to upgrade first, and ranks them by risk.

**Threat Modeling**  
Give it a JSON description of your system — components, data flows, which services touch the internet, which ones handle PII. It applies the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to every component and produces a prioritized risk inventory with DREAD scoring and concrete mitigations.

**Compliance Mapping**  
Feed it a list of security findings. It maps each one to the specific NIST SP 800-53 Rev 5 controls and OWASP Top 10 2021 categories that are triggered. The output tells you not just "you have a SQL injection" but "this triggers A03:2021 and SI-10, your remediation timeline is 4 hours."

**Secret Scanning**  
Point it at a directory. It walks your source tree, applies 16 regex patterns (AWS keys, GitHub tokens, Google API keys, Stripe keys, database connection strings, JWT tokens, PEM private keys, and more), runs Shannon entropy analysis to cut false positives, and tells you exactly which file and line number the problem is on — with the credential redacted so the report itself doesn't become a liability.

---

## Architecture

Guardian is two processes that communicate over the Model Context Protocol (MCP):

```
You (terminal)
    ↓
consultant.py       ← Google Gemini via LangChain, ReAct agent loop
    ↓  stdio
main.py             ← FastMCP server, 4 registered tools
    ↓
sca.py  threat_model.py  compliance.py  secret_scanner.py
    ↓
helpers.py          ← shared patterns, OSV mock database
context_manager.py  ← token budget, state persistence
```

The client spawns the server as a subprocess. They talk in JSON over stdin/stdout — no network, no sockets. The LLM decides which tools to call based on your question, calls them through the MCP client, and weaves the results into its response.

The token reduction system (`context_manager.py`) keeps the LLM context efficient across long sessions. Full scan reports are stored separately from the conversation window; only compact summaries get injected into prompts. Old messages are evicted and summarized automatically when the token budget fills up. Sessions can be checkpointed to disk and restored.

---

## Getting started

**Requirements**: Python 3.11+, a Google API key (for Gemini)

```bash
# Clone and set up
git clone https://github.com/your-username/guardian-ssdlc
cd guardian-ssdlc
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Mac/Linux

# Install everything including dev tools
pip install -e ".[dev]"

# Configure your API key
copy .env.example .env        # Windows
cp .env.example .env          # Mac/Linux
# then open .env and set GOOGLE_API_KEY=your_key_here

# Verify the setup runs clean
python -m pytest
```

**Start the interactive consultant**

```bash
python -m src.client.consultant
# or if you installed via pip:
guardian
```

You'll see the Guardian banner and a prompt. Try:

```
🛡 You: scan ./requirements.txt for vulnerabilities
🛡 You: generate a threat model for a REST API with PostgreSQL, exposed to the internet
🛡 You: scan the ./src directory for hardcoded secrets
🛡 You: run a full security review — deps, threats, and compliance
```

**Run the server standalone** (useful for debugging or integrating with other MCP clients):

```bash
python -m src.server.main
```

---

## Docker

```bash
docker build -t guardian-ssdlc .
docker run -it -e GOOGLE_API_KEY=your_key guardian-ssdlc
```

---

## Running tests

```bash
# Full suite
python -m pytest

# Specific module
python -m pytest tests/test_sca.py -v
python -m pytest tests/test_context_manager.py -v

# With coverage
python -m pytest --cov=src --cov-report=term-missing
```

137 tests, 6 test files. No external services required — the vulnerability database is mocked, the YAML policy files are local.

---

## Project structure

```
src/
├── server/
│   ├── main.py                  FastMCP server, tool registrations
│   └── tools/
│       ├── sca.py               Dependency vulnerability scanning
│       ├── threat_model.py      STRIDE/DREAD threat modeling engine
│       ├── compliance.py        NIST 800-53 + OWASP Top 10 mapper
│       └── secret_scanner.py    Regex + entropy credential detection
├── utils/
│   ├── helpers.py               Secret patterns, OSV mock DB, shared utilities
│   └── context_manager.py       Token budget management, state persistence
└── client/
    └── consultant.py            Interactive CLI, LangGraph ReAct agent

data/
└── policies/
    ├── nist_800_53.yaml          NIST control → finding type mappings
    └── owasp_top10.yaml          OWASP category → finding type triggers

tests/                           137 tests, zero external dependencies
```

---

## Configuration

Copy `.env.example` to `.env` and set these variables:

| Variable | Default | Description |
|---|---|---|
| `GOOGLE_API_KEY` | required | Your Google AI Studio key |
| `GEMINI_MODEL` | `gemini-1.5-pro` | Model to use |
| `TEMPERATURE` | `0.2` | Lower = more deterministic |
| `MAX_TOKENS` | `8192` | Max tokens per LLM response |

---

## Security decisions worth knowing

**The OSV database is mocked.** `helpers.py` contains a hand-curated set of real CVEs for common packages (requests, flask, django, pyyaml, lodash, webpack, etc.). In a production deployment you'd replace the `_query_osv` function with a real POST to `https://api.osv.dev/v1/query`. The mock is there so everything works offline and tests don't make network calls.

**Secrets are redacted in reports.** When the scanner finds a credential, it shows `AKIAT1***B7X` — the first 6 characters and last 3, with the middle replaced. The file path and line number are reported so you can locate and rotate the credential, but the report itself won't contain anything you'd regret sharing.

**Comment lines are skipped.** A line like `# AWS_KEY = "AKIA..."  # example only` won't be flagged. The scanner checks whether a match sits on a comment line and skips it, which significantly reduces false positives in documentation and example files.

**The LLM never sees your raw source code.** The secret scanner reads your files locally and returns a structured report. The LLM only sees the report. Your source code stays on your machine.

---

## Extending the project

**Add a new secret pattern**: Open `src/utils/helpers.py` and add a tuple to `SECRET_PATTERNS`. The format is `(label, compiled_regex, severity, description)`. The scanner picks it up automatically.

**Add a new vulnerability to the mock database**: Add an entry to `OSV_MOCK_DB` in `helpers.py` following the existing structure. The key is the lowercase package name.

**Add a new compliance mapping**: Edit `data/policies/nist_800_53.yaml` or `owasp_top10.yaml`. No code changes required.

**Swap the LLM**: In `consultant.py`, replace `ChatGoogleGenerativeAI` with any LangChain-compatible model. The rest of the agent logic is model-agnostic.

**Add a new MCP tool**: Write the business logic function, add a Pydantic input model, then register it with `@mcp.tool()` in `main.py`. The MCP client will discover it automatically.

---

## Tech stack

| Layer | Technology |
|---|---|
| MCP Server | FastMCP |
| LLM | Google Gemini 1.5 Pro (via LangChain) |
| Agent Loop | LangGraph ReAct |
| Input Validation | Pydantic v2 |
| Terminal UI | Rich |
| Compliance Data | YAML (NIST 800-53, OWASP Top 10) |
| Vulnerability Data | OSV mock (production: osv.dev API) |
| Testing | pytest, 137 tests |
| Build | Hatchling |
| Python | 3.11+ |

---

## License

MIT
