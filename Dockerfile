# ─────────────────────────────────────────────────────────────────────────────
# Guardian S-SDLC — Multi-stage Dockerfile
# Security best practices:
#   • Minimal base image (python:3.11-slim)
#   • Non-root user execution
#   • No secrets baked into layers
#   • Explicit COPY to minimise attack surface
#   • Read-only filesystem hints via labels
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install build toolchain — only in this layer, not in final image
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Create an isolated venv — cleaner than --prefix and works correctly
# with compiled extensions at any path.
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy only what pip needs to resolve and build the package.
# pyproject.toml first so dependency-only layers can be cached separately.
COPY pyproject.toml ./
COPY src/ ./src/

# Install runtime dependencies into the venv.
RUN pip install --upgrade pip \
    && pip install --no-cache-dir .


# ── Stage 2: Production Runtime ─────────────────────────────────────────────
FROM python:3.11-slim AS production

# Security metadata
LABEL org.opencontainers.image.title="Guardian S-SDLC Orchestrator" \
      org.opencontainers.image.description="Shift-Left Security Automation via MCP" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="MIT" \
      security.non-root="true"

# Create non-root user — never run application code as root
RUN groupadd --gid 1001 guardian \
    && useradd --uid 1001 --gid guardian --shell /bin/bash --create-home guardian

# Copy the venv from builder stage
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

WORKDIR /app

# Copy application source (explicitly list to avoid copying .env, secrets, etc.)
COPY src/        ./src/
COPY data/       ./data/
COPY pyproject.toml ./

# Fix ownership — all files belong to the non-root user
RUN chown -R guardian:guardian /app

# Switch to non-root user
USER guardian

# Health check — verify the MCP server can be imported without errors
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.server.main import mcp; print('OK')" || exit 1

# Environment defaults (override at runtime with --env-file or -e)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO \
    TEMPERATURE=0.2 \
    MAX_TOKENS=8192

# Default: run the interactive AI consultant
# Override CMD at runtime: docker run guardian python -m src.server.main
CMD ["python", "-m", "src.client.consultant"]


# ── Stage 3: Development / Testing ──────────────────────────────────────────
FROM production AS development

USER root

# Install dev dependencies into the same venv
COPY pyproject.toml ./
RUN pip install --no-cache-dir ".[dev]"  # PATH already includes /venv/bin

# Install additional dev tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy test suite
COPY tests/ ./tests/

RUN chown -R guardian:guardian /app
USER guardian

# Default command in dev stage: run the test suite
CMD ["python", "-m", "pytest", "tests/", "-v", "--cov=src", "--cov-report=term-missing"]
