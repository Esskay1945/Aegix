"""
AEGIX Log Parsers — Multi-Format Log Ingestion (F01–F09)
Parses Syslog, CEF, JSON, Windows Event XML, and raw text logs
into standardised LogEvent objects.

Supports: Syslog (RFC 5424/3164), CEF, LEEF, JSON, EVTX XML, raw text.
"""
import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from dateutil import parser as date_parser

logger = logging.getLogger("aegix.ingestion.parsers")


@dataclass
class LogEvent:
    """Standardised log event — universal format for all downstream processing."""

    # Identity
    event_id: str = ""           # Unique hash of the event
    source_type: str = ""        # syslog, cef, json, evtx, raw, live_capture
    source_file: str = ""        # Original file/stream this came from

    # Timing
    timestamp: str = ""          # ISO 8601 UTC
    timestamp_unix: float = 0.0  # Unix epoch

    # Source
    source_ip: str = ""
    source_port: int = 0
    source_host: str = ""

    # Destination
    dest_ip: str = ""
    dest_port: int = 0
    dest_host: str = ""

    # Event Details
    severity: str = "INFO"       # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category: str = ""           # authentication, network, process, file, firewall
    action: str = ""             # login_failed, connection, process_start, etc.
    message: str = ""            # Original message text
    username: str = ""
    process_name: str = ""
    protocol: str = ""           # TCP, UDP, HTTP, DNS, etc.

    # Raw
    raw_log: str = ""            # Original unparsed log line

    # Enrichment (filled later by normaliser/enrichment)
    geo_country: str = ""
    geo_city: str = ""
    asn: str = ""
    is_internal: bool = False
    cve_ids: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)

    # Metadata
    parsed_at: float = 0.0
    enriched: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def compute_id(self) -> str:
        """Generate a unique event ID from content hash."""
        content = f"{self.timestamp}:{self.source_ip}:{self.message}"
        self.event_id = hashlib.sha256(content.encode()).hexdigest()[:16]
        return self.event_id


# ═══════════════════════════════════════════════════════════════
# Syslog Parser (RFC 5424 / RFC 3164)
# ═══════════════════════════════════════════════════════════════

# RFC 3164 pattern: <priority>timestamp hostname process[pid]: message
_SYSLOG_3164 = re.compile(
    r"<(\d{1,3})>"                           # Priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # Timestamp
    r"\s+(\S+)"                               # Hostname
    r"\s+(\S+?)(?:\[(\d+)\])?"                # Process[PID]
    r":\s+(.*)"                               # Message
)

# RFC 5424 pattern
_SYSLOG_5424 = re.compile(
    r"<(\d{1,3})>\d\s+"                      # Priority + version
    r"(\S+)\s+"                               # Timestamp
    r"(\S+)\s+"                               # Hostname
    r"(\S+)\s+"                               # App name
    r"(\S+)\s+"                               # ProcID
    r"(\S+)\s+"                               # MsgID
    r"(?:\[.*?\]\s*)?"                         # Structured data
    r"(.*)"                                    # Message
)

_SYSLOG_SEVERITY_MAP = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "WARNING", 6: "INFO", 7: "DEBUG",
}


def parse_syslog(line: str, source_file: str = "") -> Optional[LogEvent]:
    """Parse a syslog line (RFC 3164 or 5424)."""
    event = LogEvent(source_type="syslog", source_file=source_file, raw_log=line)

    # Try RFC 5424 first
    match = _SYSLOG_5424.match(line)
    if match:
        pri = int(match.group(1))
        event.severity = _SYSLOG_SEVERITY_MAP.get(pri % 8, "INFO")
        try:
            ts = date_parser.parse(match.group(2))
            event.timestamp = ts.astimezone(timezone.utc).isoformat()
            event.timestamp_unix = ts.timestamp()
        except Exception:
            event.timestamp = match.group(2)
        event.source_host = match.group(3)
        event.process_name = match.group(4)
        event.message = match.group(7)
        event.compute_id()
        return event

    # Try RFC 3164
    match = _SYSLOG_3164.match(line)
    if match:
        pri = int(match.group(1))
        event.severity = _SYSLOG_SEVERITY_MAP.get(pri % 8, "INFO")
        try:
            ts = date_parser.parse(match.group(2))
            event.timestamp = ts.astimezone(timezone.utc).isoformat()
            event.timestamp_unix = ts.timestamp()
        except Exception:
            event.timestamp = match.group(2)
        event.source_host = match.group(3)
        event.process_name = match.group(4)
        event.message = match.group(6)
        event.compute_id()
        return event

    return None


# ═══════════════════════════════════════════════════════════════
# CEF Parser (Common Event Format)
# ═══════════════════════════════════════════════════════════════

_CEF_HEADER = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
)


def parse_cef(line: str, source_file: str = "") -> Optional[LogEvent]:
    """Parse a CEF (Common Event Format) log line."""
    match = _CEF_HEADER.match(line)
    if not match:
        return None

    event = LogEvent(source_type="cef", source_file=source_file, raw_log=line)

    severity_val = int(match.group(7)) if match.group(7).isdigit() else 5
    if severity_val >= 9:
        event.severity = "CRITICAL"
    elif severity_val >= 7:
        event.severity = "ERROR"
    elif severity_val >= 4:
        event.severity = "WARNING"
    else:
        event.severity = "INFO"

    event.message = match.group(6)  # Event name
    event.category = match.group(5)  # Signature ID as category

    # Parse extension key=value pairs
    extensions = match.group(8)
    ext_pairs = re.findall(r"(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)", extensions)
    for key, value in ext_pairs:
        if key == "src":
            event.source_ip = value
        elif key == "dst":
            event.dest_ip = value
        elif key == "spt":
            event.source_port = int(value) if value.isdigit() else 0
        elif key == "dpt":
            event.dest_port = int(value) if value.isdigit() else 0
        elif key == "duser" or key == "suser":
            event.username = value
        elif key == "act":
            event.action = value
        elif key == "proto":
            event.protocol = value

    event.compute_id()
    return event


# ═══════════════════════════════════════════════════════════════
# JSON Log Parser
# ═══════════════════════════════════════════════════════════════

def parse_json_log(line: str, source_file: str = "") -> Optional[LogEvent]:
    """Parse a JSON-formatted log line."""
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    event = LogEvent(source_type="json", source_file=source_file, raw_log=line)

    # Map common JSON log fields
    for ts_key in ["timestamp", "@timestamp", "time", "datetime", "ts", "date"]:
        if ts_key in data:
            try:
                ts = date_parser.parse(str(data[ts_key]))
                event.timestamp = ts.astimezone(timezone.utc).isoformat()
                event.timestamp_unix = ts.timestamp()
            except Exception:
                event.timestamp = str(data[ts_key])
            break

    event.source_ip = str(data.get("source_ip", data.get("src_ip", data.get("src", ""))))
    event.dest_ip = str(data.get("dest_ip", data.get("dst_ip", data.get("dst", ""))))
    event.source_port = int(data.get("source_port", data.get("src_port", 0)) or 0)
    event.dest_port = int(data.get("dest_port", data.get("dst_port", 0)) or 0)
    event.source_host = str(data.get("hostname", data.get("host", data.get("source_host", ""))))
    event.username = str(data.get("username", data.get("user", data.get("account", ""))))
    event.process_name = str(data.get("process", data.get("program", data.get("service", ""))))
    event.message = str(data.get("message", data.get("msg", data.get("log", ""))))
    event.action = str(data.get("action", data.get("event_type", data.get("type", ""))))
    event.category = str(data.get("category", data.get("facility", "")))
    event.protocol = str(data.get("protocol", data.get("proto", "")))

    severity = str(data.get("severity", data.get("level", data.get("priority", "INFO")))).upper()
    if severity in ("CRITICAL", "CRIT", "FATAL", "EMERG"):
        event.severity = "CRITICAL"
    elif severity in ("ERROR", "ERR"):
        event.severity = "ERROR"
    elif severity in ("WARNING", "WARN"):
        event.severity = "WARNING"
    elif severity in ("DEBUG", "TRACE"):
        event.severity = "DEBUG"
    else:
        event.severity = "INFO"

    event.compute_id()
    return event


# ═══════════════════════════════════════════════════════════════
# Windows Event XML Parser
# ═══════════════════════════════════════════════════════════════

def parse_evtx(xml_text: str, source_file: str = "") -> Optional[LogEvent]:
    """Parse a Windows Event XML record."""
    import xml.etree.ElementTree as ET

    event = LogEvent(source_type="evtx", source_file=source_file, raw_log=xml_text)

    try:
        root = ET.fromstring(xml_text)
        ns = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # System fields
        system = root.find("evt:System", ns) or root.find("System")
        if system is not None:
            provider = system.find("evt:Provider", ns) or system.find("Provider")
            if provider is not None:
                event.process_name = provider.get("Name", "")

            event_id = system.find("evt:EventID", ns) or system.find("EventID")
            if event_id is not None:
                event.action = f"EventID:{event_id.text}"

            level = system.find("evt:Level", ns) or system.find("Level")
            if level is not None:
                level_map = {"1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFO"}
                event.severity = level_map.get(level.text, "INFO")

            time_created = system.find("evt:TimeCreated", ns) or system.find("TimeCreated")
            if time_created is not None:
                ts_str = time_created.get("SystemTime", "")
                try:
                    ts = date_parser.parse(ts_str)
                    event.timestamp = ts.astimezone(timezone.utc).isoformat()
                    event.timestamp_unix = ts.timestamp()
                except Exception:
                    event.timestamp = ts_str

            computer = system.find("evt:Computer", ns) or system.find("Computer")
            if computer is not None:
                event.source_host = computer.text or ""

        # EventData fields
        event_data = root.find("evt:EventData", ns) or root.find("EventData")
        if event_data is not None:
            data_fields = {}
            for data_elem in event_data:
                name = data_elem.get("Name", "")
                value = data_elem.text or ""
                data_fields[name] = value

            event.username = data_fields.get("TargetUserName", data_fields.get("SubjectUserName", ""))
            event.source_ip = data_fields.get("IpAddress", "")
            event.source_port = int(data_fields.get("IpPort", 0) or 0)
            event.message = json.dumps(data_fields)

    except ET.ParseError as e:
        logger.warning(f"EVTX parse error: {e}")
        return None

    event.compute_id()
    return event


# ═══════════════════════════════════════════════════════════════
# Raw Text Parser (Fallback)
# ═══════════════════════════════════════════════════════════════

# IP address extraction pattern
_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def parse_raw(line: str, source_file: str = "") -> LogEvent:
    """Fallback parser for unrecognized log formats."""
    event = LogEvent(source_type="raw", source_file=source_file, raw_log=line)
    event.message = line.strip()

    # Extract any IP addresses
    ips = _IP_PATTERN.findall(line)
    if len(ips) >= 1:
        event.source_ip = ips[0]
    if len(ips) >= 2:
        event.dest_ip = ips[1]

    # Try to extract a timestamp
    try:
        ts = date_parser.parse(line[:30], fuzzy=True)
        event.timestamp = ts.astimezone(timezone.utc).isoformat()
        event.timestamp_unix = ts.timestamp()
    except Exception:
        event.timestamp = datetime.now(timezone.utc).isoformat()
        event.timestamp_unix = datetime.now(timezone.utc).timestamp()

    # Severity heuristics
    line_lower = line.lower()
    if any(w in line_lower for w in ["critical", "fatal", "emergency", "emerg"]):
        event.severity = "CRITICAL"
    elif any(w in line_lower for w in ["error", "err", "fail"]):
        event.severity = "ERROR"
    elif any(w in line_lower for w in ["warn", "warning"]):
        event.severity = "WARNING"
    elif any(w in line_lower for w in ["debug", "trace"]):
        event.severity = "DEBUG"

    event.compute_id()
    return event


# ═══════════════════════════════════════════════════════════════
# Auto-Detect Parser — Tries All Formats
# ═══════════════════════════════════════════════════════════════

def parse_log_line(line: str, source_file: str = "") -> LogEvent:
    """
    Auto-detect log format and parse accordingly.
    Tries: JSON → Syslog → CEF → Raw (fallback).
    """
    line = line.strip()
    if not line:
        return LogEvent(source_type="empty", raw_log="")

    # Try JSON first (most common in modern systems)
    if line.startswith("{"):
        event = parse_json_log(line, source_file)
        if event:
            return event

    # Try CEF
    if line.startswith("CEF:"):
        event = parse_cef(line, source_file)
        if event:
            return event

    # Try Syslog
    if line.startswith("<"):
        event = parse_syslog(line, source_file)
        if event:
            return event

    # Try EVTX XML
    if line.startswith("<Event") or line.startswith("<?xml"):
        event = parse_evtx(line, source_file)
        if event:
            return event

    # Fallback to raw
    return parse_raw(line, source_file)


def parse_log_file(filepath: str) -> list:
    """Parse an entire log file, auto-detecting format per line."""
    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    event = parse_log_line(line, source_file=filepath)
                    if event and event.source_type != "empty":
                        events.append(event)
    except Exception as e:
        logger.error(f"Failed to parse log file {filepath}: {e}")

    logger.info(f"Parsed {len(events)} events from {filepath}")
    return events
