"""
THE TACTICIAN — The Reporter Agent
Strategic communication: dual-tier incident reports, evidence
explanation, counterfactual generation.

Features mapped: F48–F52 (Reports), F57–F60 (Explainability)
"""
import logging
from pathlib import Path
from typing import List
from core.llm_router import call_llm
from response.report_generator import generate_incident_report
from security.audit_chain import get_audit_chain

logger = logging.getLogger("aegix.agents.tactician")


class TacticianAgent:
    """
    The Strategist/Reporter — Translates findings into human-readable intelligence.
    """

    def __init__(self):
        self.name = "tactician"
        self.reports_generated = 0
        self.audit = get_audit_chain()
        self._prompt_template = self._load_prompt()

        logger.info("📋 The Tactician (Reporter) initialized")

    def _load_prompt(self) -> str:
        """Load the Tactician's system prompt."""
        prompt_file = Path(__file__).parent.parent / "prompts" / "tactician_reporter.txt"
        try:
            return prompt_file.read_text(encoding="utf-8")
        except Exception:
            return "You are a cybersecurity report writer. Generate clear, evidence-backed incident reports."

    def generate_report(
        self,
        investigation_result: dict,
        hardware_context: str = "",
        memory_context: str = "",
        response_actions: List[dict] = None,
        fixer_results: List[dict] = None,
    ) -> dict:
        """
        Generate a full incident report from the Detective's investigation.
        """
        self.reports_generated += 1
        incident_id = f"AEGIX-{self.reports_generated:04d}"
        response_actions = response_actions or []
        fixer_results = fixer_results or []

        self.audit.log_event(self.name, "REPORT_START", {
            "incident_id": incident_id,
            "investigation_id": investigation_result.get("investigation_id"),
        })

        anomalies = investigation_result.get("anomalies", [])
        risk_score = investigation_result.get("risk_score")

        # ── LLM-Enhanced Analysis ──
        detective_narrative = self._generate_narrative(
            investigation_result, hardware_context, memory_context
        )

        # ── Generate structured report ──
        report = generate_incident_report(
            incident_id=incident_id,
            anomalies=anomalies,
            risk_score=risk_score,
            detective_analysis=detective_narrative,
            response_actions=response_actions,
            fixer_results=fixer_results,
        )

        self.audit.log_event(self.name, "REPORT_COMPLETE", {
            "incident_id": incident_id,
            "report_file": report.get("report_file"),
            "risk_level": risk_score.risk_level if risk_score else "UNKNOWN",
        })

        logger.info(
            f"📋 Tactician report #{self.reports_generated} generated: "
            f"{incident_id} — saved to {report.get('report_file')}"
        )

        return report

    def _generate_narrative(
        self,
        investigation_result: dict,
        hardware_context: str = "",
        memory_context: str = "",
    ) -> str:
        """Use LLM to generate a human-readable narrative of the investigation."""
        prompt = self._prompt_template
        prompt = prompt.replace("{hardware_context}", hardware_context)
        prompt = prompt.replace("{memory_context}", memory_context)

        # Build investigation summary for the LLM
        inv = investigation_result
        summary = (
            f"Investigation findings:\n"
            f"- Correlation: {inv.get('correlation_summary', 'N/A')}\n"
            f"- Risk Score: {inv.get('risk_score', {})}\n"
            f"- MITRE Techniques: {inv.get('mitre_techniques', [])}\n"
            f"- Attacker Intent: {inv.get('attacker_intent', 'unknown')}\n"
            f"- Anomalies detected: {len(inv.get('anomalies', []))}\n"
            f"- IOCs: {inv.get('ioc_list', {})}\n"
            f"- Recommended Response: {inv.get('recommended_response', 'N/A')}\n"
        )

        # Add anomaly details
        for i, anomaly in enumerate(inv.get("anomalies", [])[:10], 1):
            summary += (
                f"\nAnomaly {i}: {anomaly.get('anomaly_type', '?')} — "
                f"{anomaly.get('evidence', 'No details')[:200]}"
            )

        try:
            narrative = call_llm(
                agent_name=self.name,
                system_prompt=prompt,
                user_message=(
                    f"Generate a clear, evidence-backed incident narrative "
                    f"based on these investigation findings:\n\n{summary}"
                ),
                temperature=0.4,
            )
            return narrative
        except Exception as e:
            logger.warning(f"LLM narrative generation failed: {e}")
            return inv.get("correlation_summary", "LLM narrative generation unavailable.")

    def get_stats(self) -> dict:
        """Get Tactician statistics."""
        return {
            "agent": self.name,
            "reports_generated": self.reports_generated,
            "status": "ACTIVE",
        }
