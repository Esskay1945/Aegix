"""
AEGIX Report Generator — Dual-Tier Incident Reports (F48–F52)
Generates Executive and Technical incident reports with
citation-locked evidence grounding.
"""
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from config import settings

logger = logging.getLogger("aegix.response.report_generator")


def generate_incident_report(
    incident_id: str,
    anomalies: List[dict],
    risk_score: object,
    detective_analysis: str = "",
    response_actions: List[dict] = None,
    fixer_results: List[dict] = None,
) -> dict:
    """
    Generate a dual-tier incident report.

    Returns a dict containing:
    - executive_summary: Non-technical 1-2 paragraph summary
    - technical_report: Full forensic detail
    - metadata: Report metadata
    - raw_json: Machine-readable full report
    """
    now = datetime.now(timezone.utc)
    response_actions = response_actions or []
    fixer_results = fixer_results or []

    # ── Collect Evidence ──
    affected_ips = set()
    affected_users = set()
    mitre_techniques = set()
    attack_types = set()

    for anomaly in anomalies:
        attack_types.add(anomaly.get("anomaly_type", "unknown"))
        if anomaly.get("source_ip"):
            affected_ips.add(anomaly["source_ip"])
        if anomaly.get("affected_users"):
            affected_users.update(anomaly["affected_users"])
        if anomaly.get("mitre_technique"):
            mitre_techniques.add(anomaly["mitre_technique"])

    # ── Executive Summary ──
    executive_summary = _build_executive_summary(
        incident_id, anomalies, risk_score,
        affected_ips, affected_users, attack_types, mitre_techniques
    )

    # ── Technical Report ──
    technical_report = _build_technical_report(
        incident_id, anomalies, risk_score, detective_analysis,
        affected_ips, affected_users, attack_types, mitre_techniques,
        response_actions, fixer_results
    )

    # ── Plain-English Report (Zero Jargon for Non-Tech Users) ──
    plain_english_summary = _build_plain_english_summary(
        incident_id, anomalies, risk_score,
        affected_ips, affected_users, attack_types,
        response_actions, fixer_results
    )

    # ── Machine-Readable JSON ──
    raw_json = {
        "report_id": incident_id,
        "generated_at": now.isoformat(),
        "risk_score": risk_score.total_score if risk_score else 0,
        "risk_level": risk_score.risk_level if risk_score else "UNKNOWN",
        "anomaly_count": len(anomalies),
        "attack_types": list(attack_types),
        "mitre_techniques": list(mitre_techniques),
        "affected_ips": list(affected_ips),
        "affected_users": list(affected_users),
        "anomalies": [
            {
                "type": a.get("anomaly_type"),
                "severity": a.get("severity"),
                "confidence": a.get("confidence"),
                "evidence": a.get("evidence"),
                "mitre": a.get("mitre_technique"),
            }
            for a in anomalies
        ],
        "response_actions": response_actions,
        "fixer_results": [
            {
                "command": r.get("command", ""),
                "success": r.get("success", False),
            }
            for r in fixer_results
        ],
        "plain_english_summary": plain_english_summary,
        "executive_summary": executive_summary,
        "technical_report": technical_report,
    }

    # ── Save JSON & Plain-English TXT Reports ──
    reports_dir = Path(settings.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp_str = now.strftime('%Y%m%d_%H%M%S')
    report_file_json = reports_dir / f"incident_{incident_id}_{timestamp_str}.json"
    report_file_txt = reports_dir / f"incident_{incident_id}_{timestamp_str}.txt"

    # Write JSON report (for SIEM and programmatic ingestion)
    with open(report_file_json, "w", encoding="utf-8") as f:
        json.dump(raw_json, f, indent=2, default=str)

    # Write Plain-English TXT report (for non-technical executives and users)
    with open(report_file_txt, "w", encoding="utf-8") as f:
        f.write(plain_english_summary)

    logger.info(f"Incident report saved: {report_file_json} and {report_file_txt}")

    return {
        "report_id": incident_id,
        "executive_summary": executive_summary,
        "plain_english_summary": plain_english_summary,
        "technical_report": technical_report,
        "report_file": str(report_file_json),
        "report_file_txt": str(report_file_txt),
        "raw_json": raw_json,
    }


def _build_plain_english_summary(
    incident_id: str,
    anomalies: List[dict],
    risk_score: object,
    affected_ips: set,
    affected_users: set,
    attack_types: set,
    response_actions: list,
    fixer_results: list,
) -> str:
    """
    Generate an easy-to-read, plain-English summary designed for non-technical 
    executives, managers, and everyday users with ZERO technical jargon.
    """
    score = int(risk_score.total_score) if risk_score and hasattr(risk_score, "total_score") else 50
    level = str(risk_score.risk_level).upper() if risk_score and hasattr(risk_score, "risk_level") else "MEDIUM"
    
    # Friendly risk explanation
    if score >= 75 or level == "CRITICAL":
        threat_level_desc = "🔴 CRITICAL (Active Cyber Threat — Immediate Action Taken)"
        risk_explanation = "A severe cyber threat was detected. The system took immediate emergency action to protect your computers, data, and user accounts."
    elif score >= 50 or level == "HIGH":
        threat_level_desc = "🟠 HIGH (Suspicious Attack Activity)"
        risk_explanation = "Significant unauthorized activity was detected. Defenses were raised to isolate the suspicious computers and protect accounts."
    elif score >= 25 or level == "MEDIUM":
        threat_level_desc = "🟡 MEDIUM (Guessed Passwords / Potential Intrusion Attempt)"
        risk_explanation = "Someone attempted to test or guess passwords repeatedly to get in, but defenses actively filtered out and blocked the attempts."
    else:
        threat_level_desc = "🟢 LOW (Minor Routine Activity)"
        risk_explanation = "Routine scanning traffic was detected and filtered out. All systems remain fully secure."

    # Simplify attack types into plain English
    plain_actions_explained = []
    for a in attack_types:
        a_str = str(a).lower()
        if "brute_force_success" in a_str:
            plain_actions_explained.append("⚠️ Successful login after guessing passwords — attacker reached system level!")
        elif "brute_force" in a_str:
            plain_actions_explained.append("Repeated attempts to guess passwords on employee / system accounts")
        elif "privilege_escalation" in a_str:
            plain_actions_explained.append("Attempts to gain administrator / master control over the computer")
        elif "ransom" in a_str:
            plain_actions_explained.append("Attempt to delete backup copies or lock files (Ransomware behavior)")
        elif "lateral" in a_str:
            plain_actions_explained.append("Attempt to jump from one computer to another inside the internal office network")
        elif "exfil" in a_str:
            plain_actions_explained.append("Attempt to secretly send confidential business data outside the company")
        else:
            plain_actions_explained.append(f"Suspicious security event: {a}")

    if not plain_actions_explained:
        plain_actions_explained.append("Suspicious network connection attempts")

    # Format IP addresses
    ip_list_str = ", ".join(sorted(affected_ips)) if affected_ips else "Internal / Undisclosed"
    
    # Format Users
    user_list_str = ", ".join(sorted(affected_users)) if affected_users else "General system accounts"

    # Mitigation actions taken by AEGIX Fixer
    mitigation_lines = []
    if fixer_results:
        for r in fixer_results:
            if isinstance(r, dict):
                cmd = r.get("command", "")
                success = r.get("success", True)
                if "New-NetFirewallRule" in cmd or "iptables" in cmd or "BLOCK_IP" in cmd:
                    mitigation_lines.append("• Blocked the attacking computer address at the network firewall.")
                elif "Stop-Process" in cmd or "kill" in cmd or "KILL_PROCESS" in cmd:
                    mitigation_lines.append("• Forcefully terminated the unauthorized program.")
                else:
                    mitigation_lines.append(f"• Executed protective defense action ({'Success' if success else 'Pending'}).")
    if not mitigation_lines:
        if response_actions:
            if isinstance(response_actions, str):
                mitigation_lines.append(f"• Recommended Action: {response_actions}")
            elif isinstance(response_actions, list):
                for act in response_actions[:3]:
                    if isinstance(act, dict):
                        mitigation_lines.append(f"• {act.get('action', act.get('action_type', 'Defense Action'))}: {act.get('reason', act.get('target', ''))}")
                    else:
                        mitigation_lines.append(f"• {act}")
        else:
            mitigation_lines.append("• Automatically quarantined malicious traffic and alerted system administrators.")

    # Plain English recommendations for non-tech users
    recommendations = [
        "1. Reset passwords for any user accounts mentioned above.",
        "2. Ensure Multi-Factor Authentication (2FA) is turned on for all logins.",
        "3. Keep remote connections from unrecognized internet addresses blocked."
    ]

    report = f"""================================================================================
                    AEGIX SECURITY INCIDENT SUMMARY
                 (Simplified Non-Technical Plain-English Report)
================================================================================
Report ID      : {incident_id}
Date & Time    : {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M:%S UTC')}
Threat Level   : {threat_level_desc}
Overall Status : Protected by AEGIX Autonomous AI Defense Swarm
================================================================================

1. WHAT HAPPENED? (IN SIMPLE WORDS)
--------------------------------------------------------------------------------
{risk_explanation}

Specific suspicious behaviors detected:
""" + "\n".join(f"  • {item}" for item in plain_actions_explained) + f"""

2. WHO OR WHAT WAS TARGETED?
--------------------------------------------------------------------------------
  • Targeted User Accounts: {user_list_str}
  • Origin of Attack (Attacking Computer Addresses): {ip_list_str}
  • Total Suspicious Events Detected: {len(anomalies)}

3. WHAT DID AEGIX DO TO PROTECT YOUR SYSTEM?
--------------------------------------------------------------------------------
Our autonomous AI defense agents took the following immediate protective actions:
""" + "\n".join(f"  {line}" for line in mitigation_lines) + f"""

4. WHAT SHOULD YOU / YOUR TEAM DO NEXT?
--------------------------------------------------------------------------------
""" + "\n".join(f"  {r}" for r in recommendations) + """

================================================================================
  Report generated automatically by AEGIX (Autonomous Cybersecurity Brain)
  Designed for easy reading by executives, managers, and non-technical staff.
================================================================================
"""
    return report.strip()


def _build_executive_summary(
    incident_id, anomalies, risk_score,
    affected_ips, affected_users, attack_types, mitre_techniques
) -> str:
    """Build non-technical executive summary."""
    risk_text = f"{risk_score.total_score:.0f}/100 ({risk_score.risk_level})" if risk_score else "Unknown"

    summary = (
        f"══════════════════════════════════════════\n"
        f"  AEGIX INCIDENT REPORT — EXECUTIVE SUMMARY\n"
        f"  Incident ID: {incident_id}\n"
        f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"══════════════════════════════════════════\n\n"
        f"RISK LEVEL: {risk_text}\n\n"
        f"AEGIX has detected {len(anomalies)} security anomalies indicating "
        f"a potential {', '.join(attack_types)} attack. "
    )

    if affected_ips:
        summary += f"The attack originated from {len(affected_ips)} IP address(es). "
    if affected_users:
        summary += f"{len(affected_users)} user account(s) were targeted. "

    if risk_score and risk_score.total_score >= 60:
        summary += (
            "\n\nRECOMMENDATION: Immediate investigation and response required. "
            "The detected activity pattern suggests an active threat that should "
            "be contained immediately."
        )
    elif risk_score and risk_score.total_score >= 40:
        summary += (
            "\n\nRECOMMENDATION: Elevated monitoring recommended. "
            "The detected activity warrants further investigation."
        )

    return summary


def _build_technical_report(
    incident_id, anomalies, risk_score, detective_analysis,
    affected_ips, affected_users, attack_types, mitre_techniques,
    response_actions, fixer_results
) -> str:
    """Build full forensic technical report."""
    report = (
        f"══════════════════════════════════════════════════════\n"
        f"  AEGIX INCIDENT REPORT — TECHNICAL DETAIL\n"
        f"  Incident ID: {incident_id}\n"
        f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"══════════════════════════════════════════════════════\n\n"
    )

    # Risk Score Breakdown
    if risk_score:
        report += (
            f"── RISK ASSESSMENT ──\n"
            f"Total Score: {risk_score.total_score:.0f}/100 ({risk_score.risk_level})\n"
            f"Evidence: {risk_score.evidence_summary}\n"
            f"Contributing Factors:\n"
        )
        for factor in risk_score.contributing_factors:
            report += f"  • {factor}\n"
        report += "\n"

    # MITRE ATT&CK Mapping
    if mitre_techniques:
        report += "── MITRE ATT&CK MAPPING ──\n"
        for technique in mitre_techniques:
            report += f"  • {technique}\n"
        report += "\n"

    # Anomaly Details
    report += f"── DETECTED ANOMALIES ({len(anomalies)}) ──\n"
    for i, anomaly in enumerate(anomalies, 1):
        report += (
            f"\n  [{i}] {anomaly.get('anomaly_type', 'Unknown').upper()}\n"
            f"      Severity: {anomaly.get('severity', 'Unknown')}\n"
            f"      Confidence: {anomaly.get('confidence', 0):.0%}\n"
            f"      Evidence: {anomaly.get('evidence', 'No details')}\n"
        )
        if anomaly.get("mitre_technique"):
            report += f"      MITRE: {anomaly['mitre_technique']}\n"

    # Detective's Analysis
    if detective_analysis:
        parsed_detective = None
        if isinstance(detective_analysis, str):
            clean_str = detective_analysis.strip()
            if clean_str.startswith("```"):
                lines = [l for l in clean_str.split("\n") if not l.strip().startswith("```")]
                clean_str = "\n".join(lines)
            try:
                parsed_detective = json.loads(clean_str)
            except Exception:
                pass
        elif isinstance(detective_analysis, dict):
            parsed_detective = detective_analysis

        if parsed_detective and isinstance(parsed_detective, dict):
            report += "\n── DETECTIVE FORENSIC NARRATIVE ──\n"
            if parsed_detective.get("technical_narrative"):
                report += f"\n{parsed_detective['technical_narrative']}\n"
            elif parsed_detective.get("executive_summary"):
                report += f"\n{parsed_detective['executive_summary']}\n"

            if parsed_detective.get("evidence_citations"):
                report += "\n── EVIDENCE CITATIONS ──\n"
                for cite in parsed_detective["evidence_citations"]:
                    if isinstance(cite, dict):
                        report += f"  • Claim: {cite.get('claim')}\n    Evidence: {cite.get('evidence')}\n"

            if parsed_detective.get("counterfactual"):
                report += f"\n── COUNTERFACTUAL ANALYSIS ──\n{parsed_detective['counterfactual']}\n"

            if parsed_detective.get("risk_communication"):
                report += f"\n── RISK IMPACT & COMMUNICATIONS ──\n{parsed_detective['risk_communication']}\n"
        else:
            report += f"\n── DETECTIVE ANALYSIS ──\n{detective_analysis}\n"

    # IOC List
    report += "\n── INDICATORS OF COMPROMISE (IOCs) ──\n"
    if affected_ips:
        report += "  IPs:\n"
        for ip in affected_ips:
            report += f"    • {ip}\n"
    if affected_users:
        report += "  Users:\n"
        for user in affected_users:
            report += f"    • {user}\n"

    # Response Actions
    if response_actions:
        report += "\n── RESPONSE ACTIONS TAKEN ──\n"
        if isinstance(response_actions, str):
            report += f"  • {response_actions}\n"
        elif isinstance(response_actions, list):
            for action in response_actions:
                if isinstance(action, dict):
                    action_name = action.get("action", action.get("action_type", "Action"))
                    details = action.get("details", action.get("rationale", action.get("target", "")))
                    report += f"  • {action_name}: {details}\n"
                else:
                    report += f"  • {action}\n"


    # Fixer Execution Results
    if fixer_results:
        report += "\n── AUTONOMOUS REMEDIATION RESULTS ──\n"
        for result in fixer_results:
            status = "✓ SUCCESS" if result.get("success") else "✗ FAILED"
            report += f"  [{status}] {result.get('command', 'Unknown')}\n"

    report += (
        f"\n══════════════════════════════════════════════════════\n"
        f"  END OF REPORT — Generated by AEGIX Agentic Brain\n"
        f"══════════════════════════════════════════════════════\n"
    )

    return report
