"""
AEGIX Normaliser — Unified Schema Mapping & Enrichment (F10–F18)
Maps parsed LogEvents to a unified schema, normalises timestamps to UTC,
deduplicates near-duplicates, and enriches with context.
"""
import logging
import ipaddress
import hashlib
from datetime import datetime, timezone
from typing import List
from ingestion.parsers import LogEvent

logger = logging.getLogger("aegix.ingestion.normaliser")

# ═══════════════════════════════════════════════════════════════
# RFC 1918 Private IP Ranges (for internal/external classification)
# ═══════════════════════════════════════════════════════════════

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is internal/private."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════
# Action/Category Classification
# ═══════════════════════════════════════════════════════════════

_CATEGORY_KEYWORDS = {
    "authentication": [
        "login", "logon", "logoff", "logout", "auth", "password",
        "credential", "sshd", "pam_unix", "kerberos", "ntlm",
    ],
    "network": [
        "connection", "socket", "tcp", "udp", "dns", "http",
        "firewall", "iptables", "netfilter", "packet", "port",
    ],
    "process": [
        "process", "exec", "spawn", "fork", "cmd", "powershell",
        "bash", "script", "service", "daemon",
    ],
    "file": [
        "file", "write", "read", "delete", "modify", "create",
        "rename", "permission", "chmod", "chown",
    ],
    "malware": [
        "malware", "virus", "trojan", "ransomware", "exploit",
        "payload", "backdoor", "rootkit", "keylogger",
    ],
}


def _classify_category(event: LogEvent) -> str:
    """Classify event into a category based on message content."""
    if event.category:
        return event.category

    text = f"{event.message} {event.action} {event.process_name}".lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category

    return "general"


def _classify_severity(event: LogEvent) -> str:
    """Refine severity based on message content heuristics."""
    if event.severity in ("CRITICAL", "ERROR"):
        return event.severity

    msg_lower = event.message.lower()

    # Escalate certain patterns
    if any(w in msg_lower for w in ["failed password", "authentication failure", "invalid user"]):
        return "WARNING"
    if any(w in msg_lower for w in ["brute force", "attack", "exploit", "malicious"]):
        return "ERROR"
    if any(w in msg_lower for w in ["ransomware", "data exfiltration", "privilege escalation"]):
        return "CRITICAL"

    return event.severity


def normalise_event(event: LogEvent) -> LogEvent:
    """
    Normalise a single LogEvent:
    1. Ensure timestamp is UTC ISO 8601
    2. Classify category and severity
    3. Mark internal/external IPs
    4. Fill missing fields
    """
    # Timestamp normalisation
    if not event.timestamp:
        event.timestamp = datetime.now(timezone.utc).isoformat()
        event.timestamp_unix = datetime.now(timezone.utc).timestamp()

    # Category classification
    event.category = _classify_category(event)

    # Severity refinement
    event.severity = _classify_severity(event)

    # Internal IP classification
    if event.source_ip:
        event.is_internal = _is_internal_ip(event.source_ip)

    # Ensure event ID
    if not event.event_id:
        event.compute_id()

    event.parsed_at = datetime.now(timezone.utc).timestamp()

    return event


def normalise_events(events: List[LogEvent]) -> List[LogEvent]:
    """Normalise a batch of events."""
    normalised = []
    for event in events:
        try:
            normalised.append(normalise_event(event))
        except Exception as e:
            logger.warning(f"Failed to normalise event: {e}")
    return normalised


# ═══════════════════════════════════════════════════════════════
# Deduplication (F13)
# ═══════════════════════════════════════════════════════════════

def deduplicate_events(events: List[LogEvent], window_seconds: float = 2.0) -> List[LogEvent]:
    """
    Deduplicate near-identical events within a time window.
    Collapses repeated events (same source IP + message) into one
    with a frequency count in the message.
    """
    if not events:
        return events

    seen: dict = {}  # key -> (event, count)
    deduplicated = []

    for event in events:
        # Create a dedup key from core fields
        key = hashlib.md5(
            f"{event.source_ip}:{event.action}:{event.category}:{event.message[:100]}".encode()
        ).hexdigest()

        if key in seen:
            prev_event, count = seen[key]
            # Check time window
            if abs(event.timestamp_unix - prev_event.timestamp_unix) <= window_seconds:
                seen[key] = (prev_event, count + 1)
                continue

        seen[key] = (event, 1)

    for key, (event, count) in seen.items():
        if count > 1:
            event.message = f"[x{count}] {event.message}"
        deduplicated.append(event)

    removed = len(events) - len(deduplicated)
    if removed > 0:
        logger.info(f"Deduplication: {len(events)} → {len(deduplicated)} events ({removed} duplicates collapsed)")

    return deduplicated
