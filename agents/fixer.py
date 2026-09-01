"""
THE FIXER — The Solver Agent
Autonomous remediation: executes OS-level commands to neutralise threats.
All actions are STRIDE-gated and audit-logged.

Features mapped: F53–F56 (Response) + NEW autonomous execution
"""
import json
import logging
from pathlib import Path
from typing import List
from core.llm_router import call_llm_json
from response.os_executor import (
    execute_command, block_ip, kill_process,
    quarantine_file, ExecutionResult,
)
from security.audit_chain import get_audit_chain
from config import settings

logger = logging.getLogger("aegix.agents.fixer")


class FixerAgent:
    """
    The Solver — Takes autonomous action to neutralise threats.
    Only agent authorised to interact with the OS.
    """

    def __init__(self):
        self.name = "fixer"
        self.actions_executed = 0
        self.actions_blocked = 0
        self.actions_succeeded = 0
        self.actions_failed = 0
        self.audit = get_audit_chain()
        self._prompt_template = self._load_prompt()

        logger.info("🔧 The Fixer (Solver) initialized")

    def _load_prompt(self) -> str:
        """Load the Fixer's system prompt."""
        prompt_file = Path(__file__).parent.parent / "prompts" / "fixer_solver.txt"
        try:
            return prompt_file.read_text(encoding="utf-8")
        except Exception:
            return "You are a cybersecurity remediation agent. Plan and execute defensive actions."

    def execute_response(
        self,
        investigation_result: dict,
        hardware_context: str = "",
        memory_context: str = "",
        dry_run: bool = None,
    ) -> dict:
        """
        Plan and execute autonomous remediation based on investigation results.

        1. Use LLM to plan response actions
        2. Execute each action (STRIDE-gated)
        3. Report results
        """
        # Default to demo mode dry_run
        if dry_run is None:
            dry_run = settings.DEMO_MODE

        risk_score = investigation_result.get("risk_score")
        anomalies = investigation_result.get("anomalies", [])
        ioc_list = investigation_result.get("ioc_list", {})

        self.audit.log_event(self.name, "RESPONSE_START", {
            "risk_level": risk_score.risk_level if risk_score else "UNKNOWN",
            "anomaly_count": len(anomalies),
            "dry_run": dry_run,
        })

        # ── 1. Plan response actions ──
        planned_actions = self._plan_response(
            investigation_result, hardware_context, memory_context
        )

        # ── 2. Execute each action ──
        execution_results = []
        for action in planned_actions:
            result = self._execute_action(action, dry_run=dry_run)
            execution_results.append(result)

        # ── 3. Auto-block known malicious IPs from IOCs ──
        for ip in ioc_list.get("malicious_ips", []):
            result = self._execute_action({
                "action_type": "block_ip",
                "target": ip,
                "rationale": f"Known malicious IP from IOC database",
            }, dry_run=dry_run)
            execution_results.append(result)

        # ── 4. Compile results ──
        successes = sum(1 for r in execution_results if r.get("success"))
        failures = sum(1 for r in execution_results if not r.get("success") and not r.get("blocked"))
        blocked = sum(1 for r in execution_results if r.get("blocked"))

        self.audit.log_event(self.name, "RESPONSE_COMPLETE", {
            "total_actions": len(execution_results),
            "successes": successes,
            "failures": failures,
            "blocked_by_stride": blocked,
            "dry_run": dry_run,
        })

        logger.info(
            f"🔧 Fixer response complete: "
            f"{successes} succeeded, {failures} failed, {blocked} blocked by STRIDE"
            f"{' [DRY RUN]' if dry_run else ''}"
        )

        return {
            "status": "complete",
            "dry_run": dry_run,
            "planned_actions": planned_actions,
            "execution_results": execution_results,
            "summary": {
                "total": len(execution_results),
                "successes": successes,
                "failures": failures,
                "blocked": blocked,
            },
        }

    def _plan_response(
        self,
        investigation_result: dict,
        hardware_context: str = "",
        memory_context: str = "",
    ) -> List[dict]:
        """Use LLM to plan response actions."""
        prompt = self._prompt_template
        prompt = prompt.replace("{hardware_context}", hardware_context)
        prompt = prompt.replace("{memory_context}", memory_context)

        # Build context for the LLM
        inv = investigation_result
        context = (
            f"Investigation findings requiring response:\n"
            f"- Risk: {inv.get('risk_score', 'N/A')}\n"
            f"- MITRE: {inv.get('mitre_techniques', [])}\n"
            f"- Intent: {inv.get('attacker_intent', 'unknown')}\n"
            f"- IOCs: {inv.get('ioc_list', {})}\n"
            f"- Recommended: {inv.get('recommended_response', 'N/A')}\n"
        )

        for i, anomaly in enumerate(inv.get("anomalies", [])[:5], 1):
            context += (
                f"\nAnomaly {i}: {anomaly.get('anomaly_type', '?')} — "
                f"{anomaly.get('evidence', '')[:150]}"
            )

        try:
            result = call_llm_json(
                agent_name=self.name,
                system_prompt=prompt,
                user_message=f"Plan response actions for this incident:\n\n{context}",
                temperature=0.3,
            )

            actions = result.get("actions_planned", [])
            if not isinstance(actions, list):
                actions = [result]

            return actions

        except Exception as e:
            logger.warning(f"LLM response planning failed: {e} — using rule-based fallback")
            return self._rule_based_response(investigation_result)

    def _rule_based_response(self, investigation_result: dict) -> List[dict]:
        """Fallback rule-based response when LLM is unavailable."""
        actions = []
        ioc_list = investigation_result.get("ioc_list", {})

        # Block malicious IPs
        for ip in ioc_list.get("malicious_ips", []):
            actions.append({
                "action_type": "block_ip",
                "target": ip,
                "rationale": "Known malicious IP — block at firewall",
                "risk_assessment": "May block legitimate traffic if IP is misidentified",
                "reversible": True,
            })

        return actions

    def _execute_action(self, action: dict, dry_run: bool = False) -> dict:
        """Execute a single remediation action."""
        action_type = action.get("action_type", "unknown")
        target = action.get("target", "")

        self.actions_executed += 1
        result_dict = {
            "action_type": action_type,
            "target": target,
            "rationale": action.get("rationale", ""),
        }

        try:
            if action_type == "block_ip":
                exec_result = block_ip(target, dry_run=dry_run)
            elif action_type == "kill_process":
                exec_result = kill_process(target, dry_run=dry_run)
            elif action_type == "quarantine_file":
                exec_result = quarantine_file(target, dry_run=dry_run)
            elif action_type == "custom_command":
                command = action.get("command", "")
                exec_result = execute_command(command, dry_run=dry_run)
            else:
                exec_result = ExecutionResult(
                    command=f"Unknown action: {action_type}",
                    success=False,
                    stderr=f"Unknown action type: {action_type}",
                )

            result_dict["success"] = exec_result.success
            result_dict["blocked"] = exec_result.blocked
            result_dict["command"] = exec_result.command
            result_dict["stdout"] = exec_result.stdout
            result_dict["stderr"] = exec_result.stderr
            result_dict["blocked_reason"] = exec_result.blocked_reason

            if exec_result.success:
                self.actions_succeeded += 1
            elif exec_result.blocked:
                self.actions_blocked += 1
            else:
                self.actions_failed += 1

        except Exception as e:
            result_dict["success"] = False
            result_dict["stderr"] = str(e)
            self.actions_failed += 1
            logger.error(f"Action execution error: {action_type} on {target} — {e}")

        return result_dict

    def get_stats(self) -> dict:
        """Get Fixer statistics."""
        return {
            "agent": self.name,
            "actions_executed": self.actions_executed,
            "actions_succeeded": self.actions_succeeded,
            "actions_failed": self.actions_failed,
            "actions_blocked_by_stride": self.actions_blocked,
            "status": "ACTIVE",
        }
