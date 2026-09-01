"""
THE OVERLORD — The Agentic Brain
Central orchestrator that manages all 4 sub-agents, runs the RL feedback
loop, handles hardware adaptation, and provides the autonomous command center.

This is the heart of AEGIX. Everything flows through the Overlord.
"""
import time
import hashlib
import logging
from typing import List, Optional
from pathlib import Path
from config import settings
from core.hardware_profiler import get_profile, SystemProfile
from core.network_monitor import is_online, start_monitor, get_status as net_status
from core.memory import (
    store_lesson, recall_similar, generate_memory_context, get_memory_stats,
)
from core.llm_router import call_llm, call_llm_json, check_ollama_available
from security.identity import register_agent, get_registered_agents
from security.audit_chain import get_audit_chain
from agents.sentinel import SentinelAgent
from agents.detective import DetectiveAgent
from agents.tactician import TacticianAgent
from agents.fixer import FixerAgent
from ingestion.parsers import LogEvent

logger = logging.getLogger("aegix.agents.overlord")


class OverlordBrain:
    """
    The Agentic Brain — autonomous cybersecurity command center.
    Orchestrates Sentinel → Detective → Tactician → Fixer pipeline.
    Manages RL feedback loop for self-improvement.
    """

    def __init__(self):
        self.name = "overlord"
        self.audit = get_audit_chain()
        self.boot_time = time.time()
        self.incidents_handled = 0

        # ── Phase 1: Boot-Up Profiling ("Who Am I?") ──
        logger.info("=" * 60)
        logger.info("  AEGIX AGENTIC BRAIN — BOOT SEQUENCE")
        logger.info("=" * 60)

        self.system_profile: SystemProfile = get_profile()
        self.hardware_context = self.system_profile.to_prompt_context()
        self.fixer_context = self.system_profile.to_fixer_context()

        self.audit.log_event(self.name, "BOOT_PROFILE", {
            "os": self.system_profile.os_name,
            "arch": self.system_profile.cpu_arch,
            "cpu": self.system_profile.cpu_brand,
            "ram_gb": round(self.system_profile.ram_total_gb, 1),
            "gpu": self.system_profile.gpu_name or "None",
        })

        # ── Phase 2: Register Agent Identities ──
        self._register_agents()

        # ── Phase 3: Initialize Sub-Agents ──
        self.sentinel = SentinelAgent()
        self.detective = DetectiveAgent()
        self.tactician = TacticianAgent()
        self.fixer = FixerAgent()

        # ── Phase 4: Start Network Monitor ──
        start_monitor()
        self._network_online = is_online()

        # ── Phase 5: Check LLM Availability ──
        self.ollama_available = check_ollama_available()

        self.audit.log_event(self.name, "BOOT_COMPLETE", {
            "network": "ONLINE" if self._network_online else "OFFLINE",
            "ollama": "AVAILABLE" if self.ollama_available else "UNAVAILABLE",
            "agents_registered": get_registered_agents(),
            "boot_time_ms": round((time.time() - self.boot_time) * 1000),
        })

        logger.info("=" * 60)
        logger.info(f"  Brain: ONLINE | OS: {self.system_profile.os_name} {self.system_profile.cpu_arch}")
        logger.info(f"  CPU: {self.system_profile.cpu_brand}")
        logger.info(f"  Network: {'ONLINE' if self._network_online else 'OFFLINE'}")
        logger.info(f"  Ollama: {'AVAILABLE' if self.ollama_available else 'UNAVAILABLE'}")
        logger.info(f"  Agents: {get_registered_agents()}")
        logger.info("=" * 60)

    def _register_agents(self):
        """Register all agents with identity keys (EDITH Layer 0)."""
        for agent_name in ["overlord", "sentinel", "detective", "tactician", "fixer"]:
            register_agent(agent_name)

    # ═══════════════════════════════════════════════════════════════
    # Core Pipeline — The Autonomous Loop
    # ═══════════════════════════════════════════════════════════════

    def process_log_file(self, filepath: str) -> dict:
        """
        Full autonomous pipeline:
        Sentinel → Detective → Tactician → Fixer → RL Feedback
        """
        logger.info(f"🧠 Overlord: Processing log file — {filepath}")
        self.incidents_handled += 1

        # Step 1: Sentinel — Ingest, normalise, filter
        sentinel_result = self.sentinel.process_log_file(filepath)
        return self._run_pipeline(sentinel_result)

    def process_events(self, events: List[LogEvent]) -> dict:
        """Process pre-parsed events through the full pipeline."""
        self.incidents_handled += 1
        sentinel_result = self.sentinel.process_events(events)
        return self._run_pipeline(sentinel_result)

    def run_demo(self, scenario: str = "full_attack") -> dict:
        """Run a synthetic attack demo through the full pipeline."""
        logger.info(f"🧠 Overlord: Running demo scenario — {scenario}")
        self.incidents_handled += 1
        sentinel_result = self.sentinel.run_synthetic_demo(scenario)
        return self._run_pipeline(sentinel_result)

    def process_live_traffic(self, events: List[LogEvent]) -> dict:
        """Process live captured network events."""
        self.incidents_handled += 1
        sentinel_result = self.sentinel.process_events(events, source="live_capture")
        return self._run_pipeline(sentinel_result)

    def _run_pipeline(self, sentinel_result: dict) -> dict:
        """
        Core pipeline logic — dispatches to agents based on threat level.
        """
        suspicious = sentinel_result.get("suspicious_events", [])
        anomalies = sentinel_result.get("anomalies", [])
        ioc_hits = sentinel_result.get("ioc_hits", [])

        if not suspicious and not anomalies:
            logger.info("🧠 Overlord: No threats detected — all clear")
            return {
                "status": "clear",
                "sentinel_result": sentinel_result,
                "message": "No suspicious activity detected.",
            }

        # ── Memory Context (RL Self-Prompting) ──
        event_desc = self._summarize_events(suspicious, anomalies)
        memory_ctx = generate_memory_context(event_desc)

        # Step 2: Detective — Investigate and correlate
        investigation = self.detective.investigate(
            suspicious_events=suspicious,
            anomalies=anomalies,
            ioc_hits=ioc_hits,
            hardware_context=self.hardware_context,
            memory_context=memory_ctx,
        )

        risk_score = investigation.get("risk_score")
        risk_level = risk_score.risk_level if risk_score else "UNKNOWN"

        # Step 3: Determine response level
        fixer_result = None
        if risk_level in ("HIGH", "CRITICAL"):
            # Step 3a: Fixer — Execute autonomous response
            fixer_result = self.fixer.execute_response(
                investigation_result=investigation,
                hardware_context=self.fixer_context,
                memory_context=memory_ctx,
            )

        # Step 4: Tactician — Generate report
        report = self.tactician.generate_report(
            investigation_result=investigation,
            hardware_context=self.hardware_context,
            memory_context=memory_ctx,
            response_actions=investigation.get("recommended_response", []),
            fixer_results=fixer_result.get("execution_results", []) if fixer_result else [],
        )

        # Step 5: RL Feedback Loop — Critic scoring
        if fixer_result:
            self._rl_feedback_loop(investigation, fixer_result)

        result = {
            "status": "threat_detected",
            "incident_id": report.get("report_id"),
            "risk_score": risk_score.total_score if risk_score else 0,
            "risk_level": risk_level,
            "sentinel_result": sentinel_result.get("summary"),
            "investigation": {
                "correlation": investigation.get("correlation_summary"),
                "mitre": investigation.get("mitre_techniques"),
                "intent": investigation.get("attacker_intent"),
                "iocs": investigation.get("ioc_list"),
            },
            "report": {
                "executive_summary": report.get("executive_summary"),
                "technical_report": report.get("technical_report"),
                "report_file": report.get("report_file"),
            },
            "fixer": fixer_result.get("summary") if fixer_result else None,
            "memory_stats": get_memory_stats(),
        }

        logger.info(
            f"🧠 Overlord: Pipeline complete — "
            f"Risk={risk_score.total_score:.0f}/100 ({risk_level}), "
            f"Report={report.get('report_id')}"
        )

        return result

    # ═══════════════════════════════════════════════════════════════
    # RL Feedback Loop — The Learning Engine
    # ═══════════════════════════════════════════════════════════════

    def _rl_feedback_loop(self, investigation: dict, fixer_result: dict):
        """
        Phase 1: Aftermath Observation + Critic Scoring
        After Fixer acts, evaluate the outcome and store the lesson.
        """
        execution_results = fixer_result.get("execution_results", [])
        summary_stats = fixer_result.get("summary", {})

        # Critic scoring
        successes = summary_stats.get("successes", 0)
        failures = summary_stats.get("failures", 0)

        if successes > 0 and failures == 0:
            critic_score = 1   # All actions succeeded
        elif failures > successes:
            critic_score = -1  # More failures than successes
        else:
            critic_score = 0   # Mixed results

        # Build incident summary
        incident_summary = (
            f"Attack type: {investigation.get('attacker_intent', 'unknown')}. "
            f"MITRE: {investigation.get('mitre_techniques', [])}. "
            f"Risk: {investigation.get('risk_score', 'N/A')}. "
            f"Anomalies: {len(investigation.get('anomalies', []))}."
        )

        # Build action summary
        action_summary = "; ".join(
            f"{r.get('action_type', '?')}: {'success' if r.get('success') else 'failed'}"
            for r in execution_results[:5]
        )

        # Store the lesson
        lesson_id = store_lesson(
            incident_summary=incident_summary,
            action_taken=action_summary,
            critic_score=critic_score,
            agent_name=self.name,
            metadata={
                "attacker_intent": investigation.get("attacker_intent", "unknown"),
                "risk_level": investigation.get("risk_score", {}).risk_level
                    if hasattr(investigation.get("risk_score", {}), "risk_level") else "UNKNOWN",
                "anomaly_count": len(investigation.get("anomalies", [])),
            },
        )

        self.audit.log_event(self.name, "RL_FEEDBACK", {
            "lesson_id": lesson_id,
            "critic_score": critic_score,
            "successes": successes,
            "failures": failures,
        })

        outcome = "✓ POSITIVE" if critic_score > 0 else ("✗ NEGATIVE" if critic_score < 0 else "○ NEUTRAL")
        logger.info(f"🧠 RL Feedback: {outcome} (score={critic_score}) — Lesson stored [{lesson_id}]")

    # ═══════════════════════════════════════════════════════════════
    # Interactive Chat — Text-to-Text Interface
    # ═══════════════════════════════════════════════════════════════

    def chat(self, user_message: str) -> str:
        """
        Interactive chat with the Brain.
        Handles commands and natural language queries.
        """
        msg_lower = user_message.lower().strip()

        # Command handling
        if msg_lower in ("status", "stats"):
            return self._format_status()
        elif msg_lower.startswith("analyze ") or msg_lower.startswith("analyse "):
            filepath = user_message.split(" ", 1)[1].strip()
            result = self.process_log_file(filepath)
            return self._format_pipeline_result(result)
        elif msg_lower in ("demo", "run demo", "test"):
            result = self.run_demo("full_attack")
            return self._format_pipeline_result(result)
        elif msg_lower.startswith("demo "):
            scenario = msg_lower.split(" ", 1)[1].strip()
            result = self.run_demo(scenario)
            return self._format_pipeline_result(result)
        elif msg_lower in ("memory", "lessons"):
            stats = get_memory_stats()
            return f"Memory Stats: {stats}"
        elif msg_lower in ("audit", "chain"):
            audit_stats = self.audit.get_stats()
            return f"Audit Chain: {audit_stats}"
        elif msg_lower in ("network", "net"):
            return f"Network: {net_status()}"
        elif msg_lower in ("help", "?"):
            return self._help_text()
        elif msg_lower in ("exit", "quit", "bye"):
            return "SHUTDOWN"

        # Natural language — use LLM
        if self.ollama_available:
            return self._llm_chat(user_message)
        else:
            return (
                "Ollama is not available. I can only process commands right now.\n"
                "Type 'help' for available commands."
            )

    def _llm_chat(self, user_message: str) -> str:
        """Chat with the Brain using LLM."""
        prompt_file = Path(__file__).parent.parent / "prompts" / "overlord_brain.txt"
        try:
            prompt = prompt_file.read_text(encoding="utf-8")
        except Exception:
            prompt = "You are the AEGIX cybersecurity brain. Help the user with security analysis."

        prompt = prompt.replace("{hardware_context}", self.hardware_context)
        prompt = prompt.replace("{memory_context}", generate_memory_context(user_message, max_lessons=2))
        prompt = prompt.replace("{network_state}", f"Network: {'ONLINE' if is_online() else 'OFFLINE'}")

        try:
            return call_llm(
                agent_name=self.name,
                system_prompt=prompt,
                user_message=user_message,
                temperature=0.5,
            )
        except Exception as e:
            return f"LLM error: {e}. Type 'help' for available commands."

    def _summarize_events(self, suspicious: list, anomalies: list) -> str:
        """Create a brief event description for memory search."""
        types = set()
        for a in anomalies:
            types.add(a.get("anomaly_type", "unknown"))
        for e in suspicious[:5]:
            if hasattr(e, "category"):
                types.add(e.category)
        return f"Security incident involving: {', '.join(types)}"

    def _format_status(self) -> str:
        """Format system status."""
        return (
            f"═══ AEGIX BRAIN STATUS ═══\n"
            f"Uptime: {(time.time() - self.boot_time) / 60:.1f} minutes\n"
            f"OS: {self.system_profile.os_name} {self.system_profile.cpu_arch}\n"
            f"CPU: {self.system_profile.cpu_brand}\n"
            f"RAM: {self.system_profile.ram_available_gb:.1f}/{self.system_profile.ram_total_gb:.1f} GB\n"
            f"Network: {'ONLINE' if is_online() else 'OFFLINE'}\n"
            f"Ollama: {'AVAILABLE' if self.ollama_available else 'UNAVAILABLE'}\n"
            f"Incidents Handled: {self.incidents_handled}\n"
            f"\nAgent Stats:\n"
            f"  Sentinel: {self.sentinel.get_stats()}\n"
            f"  Detective: {self.detective.get_stats()}\n"
            f"  Tactician: {self.tactician.get_stats()}\n"
            f"  Fixer: {self.fixer.get_stats()}\n"
            f"\nMemory: {get_memory_stats()}\n"
            f"Audit: {self.audit.get_stats()}\n"
        )

    def _format_pipeline_result(self, result: dict) -> str:
        """Format pipeline result for CLI output."""
        if result.get("status") == "clear":
            return "✓ No threats detected — all clear."

        lines = [
            f"\n{'═' * 60}",
            f"  🚨 THREAT DETECTED — {result.get('incident_id', 'Unknown')}",
            f"{'═' * 60}",
            f"\nRisk Score: {result.get('risk_score', 0):.0f}/100 ({result.get('risk_level', '?')})",
        ]

        inv = result.get("investigation", {})
        if inv.get("correlation"):
            lines.append(f"\nCorrelation: {inv['correlation']}")
        if inv.get("mitre"):
            lines.append(f"MITRE ATT&CK: {inv['mitre']}")
        if inv.get("intent"):
            lines.append(f"Attacker Intent: {inv['intent']}")

        report = result.get("report", {})
        if report.get("executive_summary"):
            lines.append(f"\n{report['executive_summary']}")
        if report.get("report_file"):
            lines.append(f"\n📄 Full report saved: {report['report_file']}")

        fixer = result.get("fixer")
        if fixer:
            lines.append(f"\n🔧 Fixer: {fixer}")

        lines.append(f"{'═' * 60}")
        return "\n".join(lines)

    def _help_text(self) -> str:
        """Return help text for CLI commands."""
        return (
            "═══ AEGIX BRAIN — COMMANDS ═══\n"
            "  status      — Show system status and agent stats\n"
            "  demo        — Run full attack demo (synthetic data)\n"
            "  demo <type> — Run specific demo (brute_force, port_scan, lateral_movement, data_exfiltration)\n"
            "  analyze <f> — Analyze a log file\n"
            "  memory      — Show RL memory stats\n"
            "  audit       — Show audit chain stats\n"
            "  network     — Show network status\n"
            "  help        — Show this help\n"
            "  exit        — Shut down the Brain\n"
            "\n  Or type anything else to chat with the Brain via LLM.\n"
        )
