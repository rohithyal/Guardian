"""
guardian-ssdlc · client/consultant.py
───────────────────────────────────────
Guardian AI Security Consultant — Interactive CLI

Connects to the Guardian MCP server over stdio and exposes an interactive
REPL powered by Google Gemini via LangChain.  The agent uses visible
"Thought →" chains to explain its security reasoning before surfacing
findings, making the analysis transparent and educational.

Usage:
    python -m src.client.consultant
    python -m src.client.consultant --no-banner
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any

# ── Load .env before any library imports that read env vars ──────
from dotenv import load_dotenv

_env_path = Path(__file__).parents[2] / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    load_dotenv()  # fallback: search CWD

from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: E402
from langchain_mcp_adapters.client import MultiServerMCPClient  # noqa: E402
from langgraph.prebuilt import create_react_agent  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.markdown import Markdown  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.prompt import Prompt  # noqa: E402
from rich.rule import Rule  # noqa: E402
from rich.theme import Theme  # noqa: E402

# ──────────────────────────────────────────────────────────────────
# Rich Console
# ──────────────────────────────────────────────────────────────────
GUARDIAN_THEME = Theme(
    {
        "guardian.banner": "bold bright_cyan",
        "guardian.thought": "italic dim cyan",
        "guardian.tool": "bold yellow",
        "guardian.risk.critical": "bold bright_red on red",
        "guardian.risk.high": "bold red",
        "guardian.risk.medium": "bold yellow",
        "guardian.risk.low": "dim green",
        "guardian.ok": "bold bright_green",
        "guardian.prompt": "bold bright_white",
        "guardian.divider": "dim cyan",
    }
)
console = Console(theme=GUARDIAN_THEME, highlight=True)


# ──────────────────────────────────────────────────────────────────
# System Prompt
# ──────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = dedent(
    """
    # Guardian S-SDLC AI Security Consultant

    You are **Guardian**, an elite Principal Cybersecurity Consultant and Lead
    Security Engineer embedded in a Secure Software Development Life Cycle
    (S-SDLC) pipeline.  Your mission is to help developers and security teams
    **shift security left** — catching vulnerabilities at design and coding time
    rather than in production.

    ## Your Persona
    - You think like an adversary (red-team mindset) but communicate like a
      trusted advisor (blue-team delivery).
    - You are methodical, precise, and evidence-based.  Every risk statement
      you make is grounded in a specific tool finding.
    - You are never alarmist, but you are unambiguously clear about CRITICAL
      and HIGH severity issues.

    ## Reasoning Protocol ("Thought Chains")
    Before every tool call and before delivering a final answer, you MUST show
    your reasoning using the following format:

    ```
    🔍 Thought: <one-sentence hypothesis or next-step rationale>
    ⚙  Action:  <tool name and parameters>
    📋 Result:  <brief summary of what the tool returned>
    💡 Insight: <what this means for the security posture>
    ```

    This transparency is non-negotiable — it builds trust and teaches
    developers the "why" behind each security decision.

    ## Available Tools
    | Tool | Purpose |
    |------|---------|
    | `check_dependencies` | SCA — finds CVEs in requirements.txt / package.json |
    | `generate_threat_model` | STRIDE threat analysis from system architecture JSON |
    | `audit_compliance` | Maps findings → NIST 800-53 + OWASP Top 10 controls |
    | `scan_secrets` | Detects hardcoded credentials, API keys, tokens in code |

    ## Workflow Heuristics
    1. **SCA first** — supply-chain vulnerabilities are the fastest path to
       exploitation. Always start with `check_dependencies` if a manifest is
       mentioned.
    2. **Secrets are P0** — a hardcoded credential overrides all other risk
       priorities. If `scan_secrets` returns CRITICAL findings, escalate
       immediately.
    3. **Threat model before architecture review** — use `generate_threat_model`
       to anchor design discussions in STRIDE categories.
    4. **Chain compliance last** — once findings exist, run `audit_compliance`
       to translate them into auditable control gaps (NIST / OWASP).
    5. **Quantify, don't qualify** — always report CVSS scores, severity
       counts, and control IDs.  "Some vulnerabilities" is not acceptable.

    ## Output Format
    - Use Markdown with clear section headers.
    - Use severity badges: 🔴 CRITICAL  🟠 HIGH  🟡 MEDIUM  🟢 LOW
    - Always end responses with a **"Security Debt Reduction Plan"** section
      that lists the top 3 actionable remediation steps in priority order.
    - For compliance findings, list control IDs explicitly (e.g. SI-2, RA-5).

    ## Boundaries
    - You ONLY discuss security topics related to S-SDLC.
    - You do NOT generate exploit code, payloads, or offensive tools.
    - You DO explain attack vectors conceptually to help developers understand
      the risk they are accepting.
    - If asked something outside your remit, redirect politely to your tools.
    """
).strip()


# ──────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────
BANNER = """
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

SUBTITLE = "S-SDLC Orchestrator  ·  Shift-Left Security AI  ·  v1.0.0"


def print_banner() -> None:
    console.print(BANNER, style="guardian.banner", justify="center")
    console.print(SUBTITLE, style="dim cyan", justify="center")
    console.print()
    console.print(
        Panel(
            dedent("""
            [bold]Available Commands[/bold]
              [cyan]help[/cyan]          Show this help panel
              [cyan]tools[/cyan]         List available MCP security tools
              [cyan]examples[/cyan]      Show example prompts
              [cyan]clear[/cyan]         Clear the conversation history
              [cyan]exit[/cyan] / [cyan]quit[/cyan]  Exit Guardian

            [dim]Type any natural-language security question to begin.[/dim]
            """).strip(),
            title="[bold cyan]Guardian Security Consultant[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    console.print()


def print_examples() -> None:
    examples = [
        "Scan ./requirements.txt for vulnerabilities",
        "Generate a threat model for a REST API with a PostgreSQL database exposed to the internet",
        "Scan the ./src directory for hardcoded secrets",
        "Audit compliance for a CRITICAL SQL injection finding in the auth service",
        (
            "Run a full security review: scan deps from requirements.txt, "
            "then model threats for a web app with user auth, then map to OWASP"
        ),
    ]
    console.print(
        Panel(
            "\n".join(f"  [cyan]{i + 1}.[/cyan] {e}" for i, e in enumerate(examples)),
            title="[bold yellow]Example Prompts[/bold yellow]",
            border_style="yellow",
        )
    )


def print_tools() -> None:
    tools_info = [
        ("check_dependencies", "SCA / OSV", "Parses dependency manifests and queries OSV for CVEs"),
        ("generate_threat_model", "STRIDE", "Analyses system architecture for STRIDE threats"),
        ("audit_compliance", "NIST / OWASP", "Maps findings to NIST 800-53 & OWASP Top 10"),
        ("scan_secrets", "SAST / Secrets", "Detects hardcoded credentials with regex patterns"),
    ]
    table_lines = ["[bold]Tool Name             Framework     Description[/bold]", "─" * 70]
    for name, fw, desc in tools_info:
        table_lines.append(f"[yellow]{name:<22}[/yellow][cyan]{fw:<14}[/cyan]{desc}")
    console.print(
        Panel(
            "\n".join(table_lines),
            title="[bold cyan]MCP Security Tools[/bold cyan]",
            border_style="cyan",
        )
    )


# ──────────────────────────────────────────────────────────────────
# Agent Interaction
# ──────────────────────────────────────────────────────────────────


async def stream_agent_response(agent: Any, user_input: str, history: list) -> list:
    """
    Invoke the agent and stream its response to the console.
    Returns updated history.
    """
    history.append({"role": "user", "content": user_input})

    console.print()
    console.print(Rule(style="guardian.divider"))
    console.print("[guardian.thought]⏳  Guardian is analysing...[/guardian.thought]")
    console.print()

    try:
        response = await agent.ainvoke({"messages": history})
        messages = response.get("messages", [])

        # Extract and render the final AI message
        final_content = ""
        for msg in reversed(messages):
            if (
                hasattr(msg, "content")
                and isinstance(msg.content, str)
                and msg.content.strip()
                and (not hasattr(msg, "type") or msg.type == "ai")
            ):
                final_content = msg.content
                break

        if final_content:
            console.print(
                Panel(
                    Markdown(final_content),
                    title="[bold cyan]🛡  Guardian Analysis[/bold cyan]",
                    border_style="cyan",
                    padding=(1, 2),
                )
            )
            history.append({"role": "assistant", "content": final_content})
        else:
            console.print("[dim]No response generated.[/dim]")

    except Exception as exc:
        console.print(
            Panel(
                f"[red]Agent error:[/red] {exc}\n\n"
                "[dim]Ensure GOOGLE_API_KEY is set and the MCP server is reachable.[/dim]",
                title="[bold red]Error[/bold red]",
                border_style="red",
            )
        )

    console.print()
    return history


# ──────────────────────────────────────────────────────────────────
# Main REPL
# ──────────────────────────────────────────────────────────────────


async def run_consultant(show_banner: bool = True) -> None:
    """Main async entry-point for the interactive security consultant."""
    if show_banner:
        print_banner()

    # Validate environment
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] GOOGLE_API_KEY is not set. "
            "Copy .env.example to .env and add your key.",
        )
        sys.exit(1)

    console.print("[dim]Connecting to Guardian MCP server...[/dim]")

    # Server command — resolves to python -m src.server.main from project root
    server_cmd = [sys.executable, "-m", "src.server.main"]

    try:
        async with MultiServerMCPClient(
            {
                "guardian": {
                    "command": server_cmd[0],
                    "args": server_cmd[1:],
                    "transport": "stdio",
                }
            }
        ) as mcp_client:
            tools = mcp_client.get_tools()
            console.print(
                f"[guardian.ok]✓  Connected.[/guardian.ok] "
                f"[dim]{len(tools)} security tool(s) available.[/dim]"
            )
            console.print()

            # Initialise LLM
            llm = ChatGoogleGenerativeAI(
                model=os.getenv("GEMINI_MODEL", "gemini-1.5-pro"),
                google_api_key=api_key,
                temperature=float(os.getenv("TEMPERATURE", "0.2")),
                max_output_tokens=int(os.getenv("MAX_TOKENS", "8192")),
            )

            agent = create_react_agent(
                llm,
                tools,
                prompt=SYSTEM_PROMPT,
            )

            history: list[dict[str, str]] = []

            # REPL
            while True:
                try:
                    user_input = Prompt.ask(
                        "\n[guardian.prompt]🛡  You[/guardian.prompt]",
                        console=console,
                    ).strip()
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[dim]Exiting Guardian. Stay secure.[/dim]")
                    break

                if not user_input:
                    continue

                # Built-in commands
                lower = user_input.lower()
                if lower in ("exit", "quit", "q"):
                    console.print("[dim]Exiting Guardian. Stay secure.[/dim]")
                    break
                if lower == "clear":
                    history = []
                    console.clear()
                    if show_banner:
                        print_banner()
                    console.print("[dim]Conversation history cleared.[/dim]")
                    continue
                if lower == "help":
                    print_banner()
                    continue
                if lower == "tools":
                    print_tools()
                    continue
                if lower == "examples":
                    print_examples()
                    continue

                history = await stream_agent_response(agent, user_input, history)

    except Exception as exc:
        console.print(
            Panel(
                f"[red]Failed to start Guardian MCP server:[/red]\n{exc}\n\n"
                "[dim]Run: pip install -e . && python -m src.server.main (to test server alone)[/dim]",
                title="[bold red]Startup Error[/bold red]",
                border_style="red",
            )
        )
        sys.exit(1)


def main() -> None:
    import asyncio

    parser = argparse.ArgumentParser(description="Guardian S-SDLC AI Security Consultant")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII art banner")
    args = parser.parse_args()

    asyncio.run(run_consultant(show_banner=not args.no_banner))


if __name__ == "__main__":
    main()
