"""
AEGIX — Agentic Event Graph Intelligence System
Main Entry Point — CLI Interface to The Brain

Usage:
  python main.py              → Interactive mode (chat with the Brain)
  python main.py --demo       → Run full attack demo scenario
  python main.py --analyze <file>  → Analyze a specific log file
  python main.py --live       → Monitor live network traffic
  python main.py --status     → Show system status and exit
"""
import sys
import os
import argparse
import logging

# Ensure UTF-8 output across Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler


def setup_logging(verbose: bool = False):
    """Configure logging with Rich formatting."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def print_banner(console: Console):
    """Print the AEGIX startup banner."""
    banner_text = (
        "+==========================================================+\n"
        "|     ___   ______ _____ _____ _  __                       |\n"
        "|    /   | / ____// ____//  _/| |/ /                       |\n"
        "|   / /| |/ __/  / / __  / /  |   /                        |\n"
        "|  / ___ / /___ / /_/ /_/ /  /   |                         |\n"
        "| /_/  |_\\____/ \\____//___/ /_/|_|                         |\n"
        "|                                                          |\n"
        "|    Agentic Event Graph Intelligence System               |\n"
        "|    Autonomous Cybersecurity Brain -- SIH26-S01           |\n"
        "+==========================================================+"
    )
    try:
        console.print(banner_text, style="bold cyan")
    except Exception:
        print(banner_text)



def run_interactive(brain, console: Console):
    """Run the interactive CLI loop."""
    console.print("\n[bold green]Brain is ready. Type 'help' for commands, or chat naturally.[/bold green]\n")

    while True:
        try:
            user_input = console.input("[bold cyan]AEGIX>[/bold cyan] ").strip()
            if not user_input:
                continue

            response = brain.chat(user_input)

            if response == "SHUTDOWN":
                console.print("\n[bold yellow]Brain shutting down...[/bold yellow]")
                # Verify audit chain on exit
                audit = brain.audit
                is_valid, broken_at = audit.verify_chain_integrity()
                if is_valid:
                    console.print("[green]✓ Audit chain integrity verified — no tampering detected[/green]")
                else:
                    console.print(f"[red]✗ Audit chain BROKEN at entry {broken_at}![/red]")
                console.print("[dim]Goodbye.[/dim]\n")
                break

            console.print(f"\n{response}\n")

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Type 'exit' to shut down properly.[/yellow]")
        except EOFError:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def run_live_monitor(brain, console: Console):
    """Run live network traffic monitoring."""
    from ingestion.live_capture import start_live_capture, on_event, get_current_connections
    from core.network_monitor import is_online

    if not is_online():
        console.print("[yellow]Network is OFFLINE. Live capture requires network access.[/yellow]")
        console.print("[yellow]Falling back to synthetic demo mode...[/yellow]\n")
        result = brain.run_demo("full_attack")
        console.print(brain._format_pipeline_result(result))
        return

    console.print("[bold green]Starting live network traffic monitor...[/bold green]")
    console.print("[dim]Monitoring all network connections. Press Ctrl+C to stop.[/dim]\n")

    # Buffer for batch processing
    event_buffer = []
    BATCH_SIZE = 20
    BATCH_INTERVAL = 30  # seconds

    def on_captured_event(event):
        event_buffer.append(event)
        console.print(f"[dim]  📡 {event.message[:100]}[/dim]")

        if len(event_buffer) >= BATCH_SIZE:
            process_buffer()

    def process_buffer():
        if not event_buffer:
            return
        console.print(f"\n[bold]Processing batch of {len(event_buffer)} events...[/bold]")
        events = event_buffer.copy()
        event_buffer.clear()
        result = brain.process_live_traffic(events)
        console.print(brain._format_pipeline_result(result))

    on_event(on_captured_event)
    start_live_capture(interval=5.0)

    # Show current connections
    connections = get_current_connections()
    console.print(f"[bold]Current active connections: {len(connections)}[/bold]\n")
    for conn in connections[:10]:
        console.print(f"  {conn['local']} → {conn['remote']} ({conn['process']})")

    try:
        import time
        while True:
            time.sleep(BATCH_INTERVAL)
            if event_buffer:
                process_buffer()
    except KeyboardInterrupt:
        console.print("\n[yellow]Live monitor stopped.[/yellow]")
        if event_buffer:
            process_buffer()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIX — Agentic Cybersecurity Brain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--demo", action="store_true", help="Run full attack demo scenario")
    parser.add_argument("--demo-scenario", type=str, default="full_attack",
                        help="Demo scenario: brute_force, port_scan, lateral_movement, data_exfiltration, full_attack")
    parser.add_argument("--analyze", type=str, help="Analyze a specific log file")
    parser.add_argument("--live", action="store_true", help="Monitor live network traffic")
    parser.add_argument("--status", action="store_true", help="Show system status and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    # Setup
    setup_logging(verbose=args.verbose)
    console = Console()
    print_banner(console)

    # Create data directories
    for dir_name in ["data/sample_logs", "data/audit", "data/memory", "data/reports", "data/quarantine"]:
        os.makedirs(os.path.join(os.path.dirname(__file__), dir_name), exist_ok=True)

    # Initialize the Brain
    console.print("[bold yellow]Initializing the Agentic Brain...[/bold yellow]\n")

    from agents.overlord import OverlordBrain
    brain = OverlordBrain()

    console.print()

    # Route to appropriate mode
    if args.status:
        console.print(brain._format_status())

    elif args.demo:
        console.print(f"[bold]Running demo scenario: {args.demo_scenario}[/bold]\n")
        result = brain.run_demo(args.demo_scenario)
        console.print(brain._format_pipeline_result(result))

    elif args.analyze:
        if not os.path.exists(args.analyze):
            console.print(f"[red]File not found: {args.analyze}[/red]")
            sys.exit(1)
        console.print(f"[bold]Analyzing: {args.analyze}[/bold]\n")
        result = brain.process_log_file(args.analyze)
        console.print(brain._format_pipeline_result(result))

    elif args.live:
        run_live_monitor(brain, console)

    else:
        # Interactive mode
        run_interactive(brain, console)


if __name__ == "__main__":
    main()
