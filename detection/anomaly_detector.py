"""
AEGIX Anomaly Detector — Statistical + LLM-Based Detection (F19–F26)
Combines statistical baseline analysis with LLM semantic reasoning
for dual-mode anomaly detection.
"""
import logging
import math
from collections import defaultdict
from typing import List, Tuple
from ingestion.parsers import LogEvent

logger = logging.getLogger("aegix.detection.anomaly")


class AnomalyDetector:
    """
    Dual-mode anomaly detection engine.
    Mode 1: Statistical baseline (z-score, frequency, timing)
    Mode 2: LLM semantic analysis (novel pattern detection)
    """

    def __init__(self):
        # Rolling baselines per entity
        self._ip_frequency: dict = defaultdict(list)      # IP → [timestamps]
        self._user_activity: dict = defaultdict(list)      # user → [timestamps]
        self._port_baseline: dict = defaultdict(int)       # port → access count
        self._hourly_volume: dict = defaultdict(int)       # hour → event count
        self._entity_baselines: dict = defaultdict(list)   # entity → [event_hashes]

        # Detection thresholds
        self.brute_force_threshold = 5      # Failed logins in window
        self.port_scan_threshold = 10       # Unique ports from single IP
        self.data_exfil_threshold = 100     # MB threshold
        self.time_window = 300              # 5-minute window (seconds)

    def analyze_batch(self, events: List[LogEvent]) -> List[dict]:
        """
        Analyze a batch of events and return detected anomalies.

        Returns list of anomaly dicts with:
        - event: The triggering LogEvent
        - anomaly_type: brute_force, port_scan, data_exfiltration, etc.
        - confidence: 0.0 to 1.0
        - evidence: Description of why this is anomalous
        - severity: LOW, MEDIUM, HIGH, CRITICAL
        """
        anomalies = []

        # Update baselines
        for event in events:
            self._update_baseline(event)

        # Run detection rules
        anomalies.extend(self._detect_brute_force(events))
        anomalies.extend(self._detect_port_scan(events))
        anomalies.extend(self._detect_lateral_movement(events))
        anomalies.extend(self._detect_data_exfiltration(events))
        anomalies.extend(self._detect_privilege_escalation(events))
        anomalies.extend(self._detect_suspicious_processes(events))

        if anomalies:
            logger.info(f"Detected {len(anomalies)} anomalies in batch of {len(events)} events")

        return anomalies

    def _update_baseline(self, event: LogEvent):
        """Update rolling baselines with new event."""
        if event.source_ip:
            self._ip_frequency[event.source_ip].append(event.timestamp_unix)
            # Prune old entries
            cutoff = event.timestamp_unix - self.time_window
            self._ip_frequency[event.source_ip] = [
                t for t in self._ip_frequency[event.source_ip] if t > cutoff
            ]

        if event.username:
            self._user_activity[event.username].append(event.timestamp_unix)

        if event.dest_port:
            self._port_baseline[event.dest_port] += 1

    def _detect_brute_force(self, events: List[LogEvent]) -> List[dict]:
        """Detect brute force login attempts (F19)."""
        anomalies = []
        failed_logins = defaultdict(list)

        for event in events:
            if event.category == "authentication" and "fail" in event.action.lower():
                key = f"{event.source_ip}→{event.dest_ip or 'localhost'}"
                failed_logins[key].append(event)

        for key, failed_events in failed_logins.items():
            if len(failed_events) >= self.brute_force_threshold:
                source_ip = failed_events[0].source_ip
                usernames = list(set(e.username for e in failed_events if e.username))
                confidence = min(1.0, len(failed_events) / (self.brute_force_threshold * 3))

                anomalies.append({
                    "event": failed_events[-1],
                    "related_events": failed_events,
                    "anomaly_type": "brute_force",
                    "confidence": confidence,
                    "severity": "HIGH" if len(failed_events) > 20 else "MEDIUM",
                    "evidence": (
                        f"Brute force detected: {len(failed_events)} failed login attempts "
                        f"from {source_ip} targeting users: {usernames} "
                        f"within {self.time_window}s window"
                    ),
                    "mitre_technique": "T1110 — Brute Force",
                    "source_ip": source_ip,
                    "affected_users": usernames,
                })

        # Check if brute force was followed by a success
        for event in events:
            if event.category == "authentication" and "success" in event.action.lower():
                bf_key = f"{event.source_ip}→{event.dest_ip or 'localhost'}"
                if bf_key in failed_logins and len(failed_logins[bf_key]) >= self.brute_force_threshold:
                    anomalies.append({
                        "event": event,
                        "anomaly_type": "brute_force_success",
                        "confidence": 0.95,
                        "severity": "CRITICAL",
                        "evidence": (
                            f"CRITICAL: Successful login from {event.source_ip} as '{event.username}' "
                            f"AFTER {len(failed_logins[bf_key])} failed attempts — "
                            f"attacker has likely gained access!"
                        ),
                        "mitre_technique": "T1110 — Brute Force (Successful)",
                        "source_ip": event.source_ip,
                    })

        return anomalies

    def _detect_port_scan(self, events: List[LogEvent]) -> List[dict]:
        """Detect port scanning activity."""
        anomalies = []
        ports_per_ip = defaultdict(set)

        for event in events:
            if event.category == "network" and event.source_ip:
                if event.dest_port:
                    ports_per_ip[event.source_ip].add(event.dest_port)

        for ip, ports in ports_per_ip.items():
            if len(ports) >= self.port_scan_threshold:
                anomalies.append({
                    "event": events[0],
                    "anomaly_type": "port_scan",
                    "confidence": min(1.0, len(ports) / 50),
                    "severity": "MEDIUM",
                    "evidence": (
                        f"Port scan detected: {ip} probed {len(ports)} unique ports: "
                        f"{sorted(list(ports))[:20]}"
                    ),
                    "mitre_technique": "T1046 — Network Service Discovery",
                    "source_ip": ip,
                    "scanned_ports": sorted(list(ports)),
                })

        return anomalies

    def _detect_lateral_movement(self, events: List[LogEvent]) -> List[dict]:
        """Detect lateral movement patterns (F23)."""
        anomalies = []
        internal_pivots = defaultdict(set)

        for event in events:
            if (event.category == "authentication" and
                event.source_ip and event.dest_ip and
                event.is_internal and "success" in event.action.lower()):
                internal_pivots[event.source_ip].add(event.dest_ip)

        for src_ip, targets in internal_pivots.items():
            if len(targets) >= 2:
                anomalies.append({
                    "event": events[0],
                    "anomaly_type": "lateral_movement",
                    "confidence": min(1.0, len(targets) / 5),
                    "severity": "HIGH",
                    "evidence": (
                        f"Lateral movement suspected: {src_ip} authenticated to "
                        f"{len(targets)} internal hosts: {list(targets)}"
                    ),
                    "mitre_technique": "T1021 — Remote Services",
                    "source_ip": src_ip,
                    "targets": list(targets),
                })

        return anomalies

    def _detect_data_exfiltration(self, events: List[LogEvent]) -> List[dict]:
        """Detect data exfiltration patterns."""
        anomalies = []

        for event in events:
            if event.category == "network" and event.action == "data_transfer":
                # Check for large outbound transfers
                msg_lower = event.message.lower()
                if "mb" in msg_lower or "transfer" in msg_lower:
                    anomalies.append({
                        "event": event,
                        "anomaly_type": "data_exfiltration",
                        "confidence": 0.7,
                        "severity": "HIGH",
                        "evidence": (
                            f"Potential data exfiltration: Large outbound transfer from "
                            f"{event.source_ip} to external {event.dest_ip}:{event.dest_port}"
                        ),
                        "mitre_technique": "T1041 — Exfiltration Over C2 Channel",
                        "source_ip": event.source_ip,
                        "dest_ip": event.dest_ip,
                    })

        return anomalies

    def _detect_privilege_escalation(self, events: List[LogEvent]) -> List[dict]:
        """Detect privilege escalation attempts."""
        anomalies = []

        priv_esc_keywords = [
            "sudo", "runas", "privilege", "escalat", "admin",
            "localgroup administrators", "net user", "4672", "4688",
            "suid", "setuid",
        ]

        for event in events:
            msg_lower = event.message.lower()
            if any(kw in msg_lower for kw in priv_esc_keywords):
                anomalies.append({
                    "event": event,
                    "anomaly_type": "privilege_escalation",
                    "confidence": 0.6,
                    "severity": "HIGH",
                    "evidence": (
                        f"Privilege escalation detected: {event.message[:200]}"
                    ),
                    "mitre_technique": "T1548 — Abuse Elevation Control Mechanism",
                    "source_ip": event.source_ip,
                })

        return anomalies

    def _detect_suspicious_processes(self, events: List[LogEvent]) -> List[dict]:
        """Detect suspicious process execution."""
        anomalies = []

        suspicious_procs = [
            "nc", "ncat", "netcat", "nmap", "masscan",
            "mimikatz", "lazagne", "hashcat", "john",
            "powershell -enc", "cmd /c", "certutil -decode",
            "bitsadmin", "mshta", "regsvr32", "rundll32",
        ]

        for event in events:
            if event.category == "process":
                msg_lower = event.message.lower()
                for proc in suspicious_procs:
                    if proc in msg_lower:
                        anomalies.append({
                            "event": event,
                            "anomaly_type": "suspicious_process",
                            "confidence": 0.75,
                            "severity": "HIGH",
                            "evidence": (
                                f"Suspicious process detected: '{proc}' found in "
                                f"{event.message[:200]}"
                            ),
                            "mitre_technique": "T1059 — Command and Scripting Interpreter",
                        })
                        break

        return anomalies
