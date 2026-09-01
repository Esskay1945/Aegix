"""
THE SENTINEL — The Shield Agent
Perimeter defense: log ingestion, normalisation, multi-level firewall
filtering, and initial anomaly detection.

Features mapped: F01–F09 (Ingestion), F10–F18 (Normalisation), F19–F26 (Log Analysis)
"""
import logging
from typing import List
from pathlib import Path
from ingestion.parsers import LogEvent, parse_log_file, parse_log_line
from ingestion.normaliser import normalise_events, deduplicate_events
from ingestion.live_capture import generate_synthetic_attack
from detection.anomaly_detector import AnomalyDetector
from intelligence.ioc_database import ioc_db
from security.audit_chain import get_audit_chain

logger = logging.getLogger("aegix.agents.sentinel")


class SentinelAgent:
    """
    The Shield — First line of defense.
    Ingests, normalises, filters, and flags suspicious events.
    """

    def __init__(self):
        self.name = "sentinel"
        self.anomaly_detector = AnomalyDetector()
        self.events_processed = 0
        self.events_filtered = 0
        self.events_flagged = 0
        self.audit = get_audit_chain()

        logger.info("🛡️ The Sentinel (Shield) initialized")

    def process_log_file(self, filepath: str) -> dict:
        """
        Full pipeline: Parse → Normalise → Deduplicate → IOC Check → Anomaly Detect.
        Returns results dict with suspicious events and anomalies.
        """
        self.audit.log_event(self.name, "INGEST_FILE", {"filepath": filepath})

        # 1. Parse
        events = parse_log_file(filepath)
        if not events:
            return {"status": "empty", "events_parsed": 0}

        return self._process_events(events, source=filepath)

    def process_raw_logs(self, log_lines: List[str], source: str = "direct") -> dict:
        """Process raw log lines (e.g., from live capture or user input)."""
        events = []
        for line in log_lines:
            event = parse_log_line(line.strip(), source_file=source)
            if event and event.source_type != "empty":
                events.append(event)

        if not events:
            return {"status": "empty", "events_parsed": 0}

        return self._process_events(events, source=source)

    def process_events(self, events: List[LogEvent], source: str = "pipeline") -> dict:
        """Process pre-parsed LogEvent objects."""
        return self._process_events(events, source=source)

    def run_synthetic_demo(self, scenario: str = "full_attack") -> dict:
        """Run a synthetic attack scenario for testing."""
        logger.info(f"🛡️ Sentinel: Running synthetic demo — scenario: {scenario}")
        self.audit.log_event(self.name, "SYNTHETIC_DEMO", {"scenario": scenario})

        events = generate_synthetic_attack(scenario)
        return self._process_events(events, source=f"synthetic:{scenario}")

    def _process_events(self, events: List[LogEvent], source: str = "unknown") -> dict:
        """Core processing pipeline."""
        total_raw = len(events)

        # 2. Normalise
        events = normalise_events(events)

        # 3. Deduplicate
        events = deduplicate_events(events)
        deduped_count = total_raw - len(events)

        # 4. Multi-level firewall — IOC check
        suspicious_events = []
        clean_events = []
        ioc_hits = []

        for event in events:
            self.events_processed += 1
            ioc_match = self._check_ioc(event)
            if ioc_match:
                ioc_hits.append(ioc_match)
                event.severity = "CRITICAL"
                suspicious_events.append(event)
            elif event.severity in ("ERROR", "CRITICAL", "WARNING"):
                suspicious_events.append(event)
            else:
                clean_events.append(event)

        self.events_filtered += len(clean_events)
        self.events_flagged += len(suspicious_events)

        # 5. Anomaly detection on all events
        anomalies = self.anomaly_detector.analyze_batch(events)

        # Add anomaly events to suspicious if not already there
        for anomaly in anomalies:
            anomaly_event = anomaly.get("event")
            if anomaly_event and anomaly_event not in suspicious_events:
                suspicious_events.append(anomaly_event)

        self.audit.log_event(self.name, "PROCESS_COMPLETE", {
            "source": source,
            "total_raw": total_raw,
            "deduplicated": deduped_count,
            "suspicious": len(suspicious_events),
            "anomalies": len(anomalies),
            "ioc_hits": len(ioc_hits),
            "filtered": len(clean_events),
        })

        logger.info(
            f"🛡️ Sentinel processed {total_raw} events: "
            f"{len(suspicious_events)} suspicious, {len(anomalies)} anomalies, "
            f"{len(ioc_hits)} IOC hits, {len(clean_events)} filtered as clean"
        )

        return {
            "status": "complete",
            "source": source,
            "events_parsed": total_raw,
            "events_deduplicated": deduped_count,
            "suspicious_events": suspicious_events,
            "clean_events": clean_events,
            "anomalies": anomalies,
            "ioc_hits": ioc_hits,
            "summary": {
                "total": total_raw,
                "suspicious": len(suspicious_events),
                "anomalies": len(anomalies),
                "ioc_hits": len(ioc_hits),
                "filtered": len(clean_events),
            },
        }

    def _check_ioc(self, event: LogEvent) -> dict:
        """Check event against IOC database (multi-level firewall)."""
        results = {}

        # Check source IP
        if event.source_ip:
            ip_result = ioc_db.check_ip(event.source_ip)
            if ip_result:
                results["source_ip"] = ip_result

        # Check destination IP
        if event.dest_ip:
            ip_result = ioc_db.check_ip(event.dest_ip)
            if ip_result:
                results["dest_ip"] = ip_result

        # Check suspicious ports
        if event.dest_port:
            port_result = ioc_db.check_port(event.dest_port)
            if port_result:
                results["dest_port"] = port_result

        return results if results else None

    def get_stats(self) -> dict:
        """Get Sentinel statistics."""
        return {
            "agent": self.name,
            "events_processed": self.events_processed,
            "events_filtered": self.events_filtered,
            "events_flagged": self.events_flagged,
            "ioc_database": ioc_db.get_summary(),
            "status": "ACTIVE",
        }
