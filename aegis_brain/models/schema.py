"""
Data models and schemas for the AEGIS Agentic Brain.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import uuid


@dataclass
class HardwareProfile:
    os_name: str
    os_version: str
    os_release: str
    architecture: str          # e.g., 'x86_64', 'ARM64', 'AMD64'
    processor: str             # e.g., 'Intel Core i7', 'AMD Ryzen', 'Apple M2'
    cpu_cores_logical: int
    cpu_cores_physical: int
    total_ram_gb: float
    platform_details: str
    execution_environment: str # e.g., 'Windows-x64-PowerShell', 'Linux-ARM64-Bash'
    boot_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LogEvent:
    event_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    event_type: str            # 'AUTH_FAIL', 'PROCESS_SPAWN', 'FIREWALL_DROP', 'SQL_QUERY', etc.
    raw_message: str
    hostname: str
    user: Optional[str] = None
    process_name: Optional[str] = None
    target_path: Optional[str] = None
    severity: str = "INFO"     # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, event_type: str, raw_message: str, source_ip: str = "192.168.1.100", **kwargs):
        return cls(
            event_id=str(uuid.uuid4())[:8],
            timestamp=datetime.utcnow().isoformat() + "Z",
            source_ip=source_ip,
            destination_ip=kwargs.get("destination_ip", "10.0.0.5"),
            destination_port=kwargs.get("destination_port", 443),
            protocol=kwargs.get("protocol", "TCP"),
            event_type=event_type,
            raw_message=raw_message,
            hostname=kwargs.get("hostname", "SOC-HOST-01"),
            user=kwargs.get("user"),
            process_name=kwargs.get("process_name"),
            target_path=kwargs.get("target_path"),
            severity=kwargs.get("severity", "MEDIUM"),
            metadata=kwargs.get("metadata", {})
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatCorrelation:
    correlation_id: str
    attack_name: str
    threat_category: str       # 'BRUTE_FORCE', 'LATERAL_MOVEMENT', 'RANSOMWARE_STAGING', 'EXFILTRATION', 'ZERO_DAY'
    mitre_techniques: List[str] # ['T1110', 'T1059.001']
    affected_hosts: List[str]
    compromised_entities: List[str]
    attack_chain_steps: List[str]
    correlated_log_ids: List[str]
    confidence_score: float    # 0.0 to 1.0
    narrative: str
    is_arch_specific: bool
    targeted_architecture: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentReport:
    incident_id: str
    title: str
    timestamp: str
    risk_score: float          # 0 to 100
    severity: str              # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    executive_summary: str
    technical_analysis: str
    mitre_attack_mappings: List[Dict[str, str]]
    evidence_citations: List[Dict[str, Any]]
    recommended_actions: List[str]
    hardware_context: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        return f"""# 🛡️ AEGIS SECURITY INCIDENT REPORT [{self.incident_id}]
**Severity:** {self.severity} | **Risk Score:** {self.risk_score:.1f}/100 | **Generated:** {self.timestamp}

---

## 1. Executive Summary
{self.executive_summary}

---

## 2. Hardware & Architecture Context
- **Host Platform:** `{self.hardware_context.get('platform_details', 'Unknown')}`
- **Target Architecture:** `{self.hardware_context.get('architecture', 'Unknown')}` (`{self.hardware_context.get('execution_environment', 'Unknown')}`)

---

## 3. Technical Forensic Analysis
{self.technical_analysis}

### MITRE ATT&CK Framework Mapping:
""" + "\n".join([f"- **{m.get('id', 'N/A')}**: {m.get('name', 'N/A')} ({m.get('tactic', 'N/A')})" for m in self.mitre_attack_mappings]) + f"""

### Evidence Citations:
""" + "\n".join([f"- [Log ID: `{e.get('log_id')}`] {e.get('summary')}" for e in self.evidence_citations]) + f"""

---

## 4. Recommended Tactical Response Actions
""" + "\n".join([f"{i+1}. {act}" for i, act in enumerate(self.recommended_actions)]) + "\n"


@dataclass
class ResponseAction:
    action_id: str
    action_type: str           # 'KILL_PROCESS', 'BLOCK_IP', 'ISOLATE_HOST', 'QUARANTINE_FILE', 'FIREWALL_UPDATE'
    target_entity: str         # e.g., '198.51.100.42', 'mimikatz.exe', 'powershell.exe'
    command_executed: str      # Exact architecture-specific CLI / PowerShell / Bash command
    execution_status: str      # 'SUCCESS', 'FAILED', 'SIMULATED'
    target_architecture: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LessonLearned:
    lesson_id: str
    threat_signature: str
    attack_category: str
    target_architecture: str
    action_taken: str
    reward_score: int          # +1 (Success), -1 (False Positive / Harmful)
    critic_notes: str
    mitigation_rule: str
    embedding_keywords: List[str]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
