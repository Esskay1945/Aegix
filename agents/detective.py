"""
THE DETECTIVE — The Investigator Agent
Deep analysis: threat detection, event correlation, ATT&CK mapping,
kill-chain reconstruction, and risk scoring.

Features mapped: F27–F36 (Threat Detection), F37–F43 (Threat Intel)
"""
import json
import logging
from typing import List
from pathlib import Path
from ingestion.parsers import LogEvent
from detection.risk_scorer import score_anomalies, RiskScore
from core.llm_router import call_llm, call_llm_json
from security.audit_chain import get_audit_chain

logger = logging.getLogger("aegix.agents.detective")


class DetectiveAgent:
    """
    The Investigator — Connects the dots.
    Correlates events, reconstructs attack chains, assigns risk scores.
    """

    def __init__(self):
        self.name = "detective"
        self.investigations = 0
        self.audit = get_audit_chain()
        self._prompt_template = self._load_prompt()

        logger.info("🔍 The Detective (Investigator) initialized")

    def _load_prompt(self) -> str:
        """Load the Detective's system prompt."""
        prompt_file = Path(__file__).parent.parent / "prompts" / "detective_investigator.txt"
        try:
            return prompt_file.read_text(encoding="utf-8")
        except Exception:
            return "You are a cybersecurity threat investigator. Analyze the given events and identify threats."

    def investigate(
        self,
        suspicious_events: List[LogEvent],
        anomalies: List[dict],
        ioc_hits: List[dict] = None,
        hardware_context: str = "",
        memory_context: str = "",
    ) -> dict:
        """
        Full investigation pipeline:
        1. Correlate events
        2. Reconstruct attack chain
        3. Map to MITRE ATT&CK
        4. Score risk
        5. Model attacker intent
        """
        self.investigations += 1
        ioc_hits = ioc_hits or []

        self.audit.log_event(self.name, "INVESTIGATION_START", {
            "suspicious_events": len(suspicious_events),
            "anomalies": len(anomalies),
            "ioc_hits": len(ioc_hits),
            "investigation_number": self.investigations,
        })

        # ── 1. Build event summary for LLM analysis ──
        event_summary = self._build_event_summary(suspicious_events, anomalies, ioc_hits)

        # ── 2. Statistical risk scoring (fast, no LLM needed) ──
        risk_score = score_anomalies(anomalies)

        # ── 3. LLM-powered deep analysis ──
        llm_analysis = self._llm_investigate(event_summary, hardware_context, memory_context)

        # ── 4. Merge statistical + LLM findings ──
        result = {
            "investigation_id": self.investigations,
            "risk_score": risk_score,
            "anomalies": anomalies,
            "event_count": len(suspicious_events),
            "llm_analysis": llm_analysis,
            "correlation_summary": llm_analysis.get("correlation_summary", "Analysis pending"),
            "attack_chain": llm_analysis.get("attack_chain", {}),
            "mitre_techniques": llm_analysis.get("mitre_techniques", []),
            "attacker_intent": llm_analysis.get("attacker_intent", "unknown"),
            "confidence": llm_analysis.get("confidence", risk_score.confidence if risk_score else 0.5),
            "recommended_response": llm_analysis.get("recommended_response", ""),
            "ioc_list": self._extract_iocs(suspicious_events, ioc_hits),
        }

        self.audit.log_event(self.name, "INVESTIGATION_COMPLETE", {
            "investigation_id": self.investigations,
            "risk_score": risk_score.total_score,
            "risk_level": risk_score.risk_level,
            "anomaly_count": len(anomalies),
            "attacker_intent": result["attacker_intent"],
        })

        logger.info(
            f"🔍 Detective investigation #{self.investigations} complete: "
            f"Risk={risk_score.total_score:.0f}/100 ({risk_score.risk_level}), "
            f"Intent={result['attacker_intent']}"
        )

        return result

    def _build_event_summary(
        self,
        events: List[LogEvent],
        anomalies: List[dict],
        ioc_hits: List[dict],
    ) -> str:
        """Build a concise event summary for LLM analysis."""
        lines = [f"=== SECURITY EVENTS FOR INVESTIGATION ({len(events)} events) ===\n"]

        # Anomaly summaries
        if anomalies:
            lines.append(f"DETECTED ANOMALIES ({len(anomalies)}):")
            for i, anomaly in enumerate(anomalies[:15], 1):  # Cap at 15 for context window
                lines.append(
                    f"  [{i}] {anomaly.get('anomaly_type', 'unknown').upper()} "
                    f"(severity={anomaly.get('severity', '?')}, "
                    f"confidence={anomaly.get('confidence', 0):.0%}): "
                    f"{anomaly.get('evidence', 'No details')[:200]}"
                )

        # IOC matches
        if ioc_hits:
            lines.append(f"\nIOC MATCHES ({len(ioc_hits)}):")
            for hit in ioc_hits[:10]:
                for key, match in hit.items():
                    if isinstance(match, dict):
                        lines.append(
                            f"  • {key}: {match.get('description', 'Unknown')} "
                            f"(severity={match.get('severity', '?')})"
                        )

        # Key event samples
        lines.append(f"\nKEY EVENT SAMPLES (showing {min(20, len(events))} of {len(events)}):")
        for event in events[:20]:
            lines.append(
                f"  [{event.severity}] {event.timestamp} | "
                f"{event.source_ip or '?'}:{event.source_port or '?'} → "
                f"{event.dest_ip or '?'}:{event.dest_port or '?'} | "
                f"{event.category}/{event.action} | {event.message[:150]}"
            )

        return "\n".join(lines)

    def _llm_investigate(
        self,
        event_summary: str,
        hardware_context: str = "",
        memory_context: str = "",
    ) -> dict:
        """Use the LLM to perform deep investigation and correlation."""
        prompt = self._prompt_template
        prompt = prompt.replace("{hardware_context}", hardware_context)
        prompt = prompt.replace("{memory_context}", memory_context)

        try:
            result = call_llm_json(
                agent_name=self.name,
                system_prompt=prompt,
                user_message=(
                    f"Investigate the following security events. "
                    f"Correlate them, reconstruct the attack chain, map to MITRE ATT&CK, "
                    f"and assess the risk.\n\n{event_summary}"
                ),
                temperature=0.3,
            )
            return result
        except Exception as e:
            logger.warning(f"LLM investigation failed: {e} — using statistical analysis only")
            return {
                "correlation_summary": "LLM analysis unavailable — using statistical detection only",
                "attack_chain": {},
                "mitre_techniques": [],
                "attacker_intent": "unknown",
                "confidence": 0.5,
                "recommended_response": "Manual investigation recommended — LLM offline",
            }

    def _extract_iocs(self, events: List[LogEvent], ioc_hits: List[dict]) -> dict:
        """Extract all IOCs from events and hits."""
        ips = set()
        users = set()

        for event in events:
            if event.source_ip and not event.is_internal:
                ips.add(event.source_ip)
            if event.username:
                users.add(event.username)

        for hit in ioc_hits:
            for key, match in hit.items():
                if isinstance(match, dict) and "ip" in match:
                    ips.add(match["ip"])

        return {
            "malicious_ips": list(ips),
            "suspicious_users": list(users),
            "malicious_domains": [],
            "malware_hashes": [],
        }

    def get_stats(self) -> dict:
        """Get Detective statistics."""
        return {
            "agent": self.name,
            "investigations_completed": self.investigations,
            "status": "ACTIVE",
        }
