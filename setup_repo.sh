#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Guardian S-SDLC — One-Shot Repository Setup Script
#
# Run once after cloning:  bash setup_repo.sh
#
# What this does:
#   1. Creates and activates a virtual environment
#   2. Installs the project + dev dependencies
#   3. Copies .env.example → .env (prompts for API key)
#   4. Installs pre-commit hooks
#   5. Initialises detect-secrets baseline
#   6. Runs the full test suite to validate the install
#   7. Prints the "Ready" banner
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[guardian]${RESET} $*"; }
success() { echo -e "${GREEN}[  ok   ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ warn  ]${RESET} $*"; }
error()   { echo -e "${RED}[ error ]${RESET} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo " ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗"
echo "██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║"
echo "██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║"
echo "╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║"
echo " ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝"
echo -e "${RESET}"
echo -e "${BOLD}  Repository Setup Script${RESET}"
echo ""

# ── Prerequisites check ──────────────────────────────────────────
info "Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || error "python3 not found. Install Python 3.11+"
command -v git >/dev/null 2>&1     || error "git not found."

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED="3.11"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"; then
    success "Python $PY_VERSION ✓"
else
    error "Python 3.11+ required. Found $PY_VERSION."
fi

# ── Virtual environment ──────────────────────────────────────────
if [ ! -d ".venv" ]; then
    info "Creating virtual environment (.venv)..."
    python3 -m venv .venv
    success "Virtual environment created."
else
    info "Virtual environment already exists."
fi

# Activate
source .venv/bin/activate
success "Activated .venv (Python $(python --version))"

# ── Install dependencies ─────────────────────────────────────────
info "Installing Guardian + dev dependencies..."
pip install --upgrade pip -q
pip install -e ".[dev]" -q
success "Dependencies installed."

# ── Environment file ─────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ""
    warn "Created .env from template."
    echo -e "${YELLOW}  You need to set your Google AI API key:${RESET}"
    read -rp "  Enter GOOGLE_API_KEY (or press Enter to skip): " API_KEY
    if [ -n "$API_KEY" ]; then
        # Safe sed that works on both GNU and BSD (macOS)
        sed -i.bak "s/your_google_api_key_here/$API_KEY/" .env && rm -f .env.bak
        success "GOOGLE_API_KEY saved to .env"
    else
        warn "Skipped. Edit .env manually before running the consultant."
    fi
else
    success ".env already exists."
fi

# ── Pre-commit hooks ─────────────────────────────────────────────
if command -v pre-commit >/dev/null 2>&1; then
    info "Installing pre-commit hooks..."
    pre-commit install --install-hooks
    success "Pre-commit hooks installed."

    info "Initialising detect-secrets baseline..."
    detect-secrets scan --exclude-files '\.env\.example' \
        --exclude-files 'tests/' > .secrets.baseline 2>/dev/null || true
    success "Secrets baseline created (.secrets.baseline)"
else
    warn "pre-commit not found — skipping hook install. Run: pip install pre-commit"
fi

# ── Test suite ───────────────────────────────────────────────────
echo ""
info "Running test suite to validate installation..."
echo ""
if pytest tests/ -v --tb=short -q 2>&1; then
    echo ""
    success "All tests passed."
else
    echo ""
    warn "Some tests failed. Check output above. The tool may still work."
fi

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  Guardian is ready!${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${CYAN}Start the AI consultant:${RESET}"
echo -e "  ${BOLD}  python -m src.client.consultant${RESET}"
echo ""
echo -e "  ${CYAN}Run tests:${RESET}"
echo -e "  ${BOLD}  pytest tests/ -v${RESET}"
echo ""
echo -e "  ${CYAN}Run a direct tool scan (no LLM required):${RESET}"
echo -e "  ${BOLD}  python -c \"from src.server.tools.sca import run_sca; import json; print(json.dumps(run_sca('CONTENT:requests==2.28.0\\\\n'), indent=2))\"${RESET}"
echo ""
