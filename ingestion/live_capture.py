"""
AEGIX Live Traffic Capture — Real-Time Network Monitoring
Captures live network connections and traffic on the host machine
when ONLINE. Falls back to synthetic data when OFFLINE.

Uses psutil for connection monitoring (lightweight, no root/admin needed
for connection listing) and optionally scapy for deep packet inspection.
"""
import time
import json
import logging
import threading
from datetime import datetime, timezone
from typing import List, Callable, Optional
from ingestion.parsers import LogEvent

logger = logging.getLogger("aegix.ingestion.live_capture")

# ═══════════════════════════════════════════════════════════════
# Live Connection Monitor (psutil-based)
# ═══════════════════════════════════════════════════════════════

_capture_thread: Optional[threading.Thread] = None
_capture_running = False
_event_callbacks: list = []
_connection_baseline: dict = {}  # Track known connections


def _capture_connections(interval: float = 5.0):
    """
    Background thread that monitors live network connections.
    Detects new connections, closed connections, and suspicious patterns.
    """
    global _capture_running, _connection_baseline

    try:
        import psutil
    except ImportError:
        logger.error("psutil not installed — live capture disabled. Run: pip install psutil")
        return

    logger.info(f"Live traffic capture started (interval={interval}s)")
    _capture_running = True

    while _capture_running:
        try:
            current_connections = {}
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" or conn.status == "LISTEN":
                    # Build connection key
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?"
                    key = f"{local}->{remote}"

                    current_connections[key] = {
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else "",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "status": conn.status,
                        "pid": conn.pid,
                        "family": str(conn.family),
                    }

            # Detect NEW connections (not in baseline)
            new_connections = set(current_connections.keys()) - set(_connection_baseline.keys())
            for key in new_connections:
                conn_info = current_connections[key]
                event = _connection_to_event(conn_info, action="new_connection")
                _emit_event(event)

            # Detect CLOSED connections
            closed_connections = set(_connection_baseline.keys()) - set(current_connections.keys())
            for key in closed_connections:
                conn_info = _connection_baseline[key]
                event = _connection_to_event(conn_info, action="connection_closed")
                _emit_event(event)

            _connection_baseline = current_connections

        except Exception as e:
            logger.error(f"Live capture error: {e}")

        time.sleep(interval)


def _connection_to_event(conn_info: dict, action: str = "connection") -> LogEvent:
    """Convert a connection dict to a LogEvent."""
    now = datetime.now(timezone.utc)

    # Try to get process name from PID
    process_name = ""
    pid = conn_info.get("pid")
    if pid:
        try:
            import psutil
            proc = psutil.Process(pid)
            process_name = proc.name()
        except Exception:
            process_name = f"PID:{pid}"

    event = LogEvent(
        source_type="live_capture",
        timestamp=now.isoformat(),
        timestamp_unix=now.timestamp(),
        source_ip=conn_info.get("local_ip", ""),
        source_port=conn_info.get("local_port", 0),
        dest_ip=conn_info.get("remote_ip", ""),
        dest_port=conn_info.get("remote_port", 0),
        action=action,
        category="network",
        protocol="TCP",
        process_name=process_name,
        message=(
            f"{action}: {conn_info.get('local_ip', '?')}:{conn_info.get('local_port', '?')} → "
            f"{conn_info.get('remote_ip', '?')}:{conn_info.get('remote_port', '?')} "
            f"({process_name}) [{conn_info.get('status', '')}]"
        ),
        severity="INFO",
    )
    event.compute_id()
    return event


def _emit_event(event: LogEvent):
    """Send a captured event to all registered callbacks."""
    for callback in _event_callbacks:
        try:
            callback(event)
        except Exception as e:
            logger.error(f"Event callback error: {e}")


def start_live_capture(interval: float = 5.0):
    """Start live network traffic capture in a background thread."""
    global _capture_thread
    if _capture_thread is not None and _capture_thread.is_alive():
        logger.info("Live capture already running")
        return

    _capture_thread = threading.Thread(
        target=_capture_connections,
        args=(interval,),
        daemon=True,
        name="aegix-live-capture",
    )
    _capture_thread.start()


def stop_live_capture():
    """Stop the live capture thread."""
    global _capture_running
    _capture_running = False
    logger.info("Live capture stopped")


def on_event(callback: Callable[[LogEvent], None]):
    """Register a callback for live captured events."""
    _event_callbacks.append(callback)


def get_current_connections() -> List[dict]:
    """Get snapshot of current network connections."""
    try:
        import psutil
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED":
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        proc_name = f"PID:{conn.pid}"

                connections.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?",
                    "process": proc_name,
                    "status": conn.status,
                    "pid": conn.pid,
                })
        return connections
    except ImportError:
        return []


# ═══════════════════════════════════════════════════════════════
# Synthetic Data Generator (Offline Mode)
# ═══════════════════════════════════════════════════════════════

import random

_ATTACK_SCENARIOS = {
    "brute_force": {
        "source_ips": ["185.220.101.10", "45.146.164.110", "103.145.13.200"],
        "dest_port": 22,
        "usernames": ["root", "admin", "user", "test", "ubuntu", "pi"],
        "messages": [
            "Failed password for {user} from {ip} port {port} ssh2",
            "Invalid user {user} from {ip} port {port}",
            "PAM authentication failure; logname= uid=0 euid=0 ruser= rhost={ip} user={user}",
            "Connection closed by authenticating user {user} {ip} port {port} [preauth]",
        ],
    },
    "port_scan": {
        "source_ips": ["198.51.100.22", "45.146.164.110"],
        "dest_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443],
        "messages": [
            "Connection attempt from {ip} to port {port} — SYN received, no response sent",
            "Firewall DENY: {ip} → 0.0.0.0:{port} TCP SYN",
        ],
    },
    "lateral_movement": {
        "internal_ips": ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5"],
        "messages": [
            "Accepted publickey for admin from {src} port {port} ssh2",
            "New session opened for user admin by (uid=0) from {src}",
            "SMB connection from {src} to \\\\{dst}\\C$ — admin share access",
            "WMI process creation on {dst} initiated by {src}: cmd.exe /c whoami",
        ],
    },
    "data_exfiltration": {
        "internal_ip": "192.168.1.10",
        "external_ips": ["185.220.101.10", "198.51.100.22"],
        "messages": [
            "Large outbound transfer: {src} → {dst}:{port} — {size}MB transferred",
            "DNS TXT query from {src} to {dst}: base64-encoded payload detected",
            "HTTP POST from {src} to {dst}:{port} — unusual payload size ({size}MB)",
        ],
    },
    "privilege_escalation": {
        "messages": [
            "sudo: user 'www-data' ran command '/bin/bash' as root",
            "EventID:4672 Special privileges assigned to new logon: admin",
            "EventID:4688 Process created: cmd.exe /c net localgroup administrators hacker /add",
            "SUID binary executed: /usr/bin/find -exec /bin/sh \\;",
        ],
    },
}


def generate_synthetic_attack(
    scenario: str = "brute_force",
    num_events: int = 50,
) -> List[LogEvent]:
    """
    Generate synthetic attack log events for offline testing.
    Simulates realistic multi-stage attack patterns.
    """
    events = []
    now = datetime.now(timezone.utc)

    if scenario == "brute_force":
        config = _ATTACK_SCENARIOS["brute_force"]
        for i in range(num_events):
            src_ip = random.choice(config["source_ips"])
            username = random.choice(config["usernames"])
            msg_template = random.choice(config["messages"])
            port = random.randint(40000, 65535)

            msg = msg_template.format(user=username, ip=src_ip, port=port)
            ts = now.timestamp() + (i * 0.5)  # 0.5s between attempts

            event = LogEvent(
                source_type="synthetic",
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                timestamp_unix=ts,
                source_ip=src_ip,
                source_port=port,
                dest_port=22,
                category="authentication",
                action="login_failed",
                severity="WARNING",
                username=username,
                process_name="sshd",
                message=msg,
                raw_log=f"<38>{datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {msg}",
            )
            event.compute_id()
            events.append(event)

        # Add one successful login at the end (the attacker got in)
        success_event = LogEvent(
            source_type="synthetic",
            timestamp=datetime.fromtimestamp(now.timestamp() + num_events * 0.5, tz=timezone.utc).isoformat(),
            timestamp_unix=now.timestamp() + num_events * 0.5,
            source_ip=random.choice(config["source_ips"]),
            source_port=random.randint(40000, 65535),
            dest_port=22,
            category="authentication",
            action="login_success",
            severity="CRITICAL",
            username="root",
            process_name="sshd",
            message=f"Accepted password for root from {random.choice(config['source_ips'])} port {random.randint(40000, 65535)} ssh2",
        )
        success_event.compute_id()
        events.append(success_event)

    elif scenario == "port_scan":
        config = _ATTACK_SCENARIOS["port_scan"]
        src_ip = random.choice(config["source_ips"])
        for i, port in enumerate(config["dest_ports"]):
            msg_template = random.choice(config["messages"])
            msg = msg_template.format(ip=src_ip, port=port)
            ts = now.timestamp() + (i * 0.1)

            event = LogEvent(
                source_type="synthetic",
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                timestamp_unix=ts,
                source_ip=src_ip,
                dest_port=port,
                category="network",
                action="port_scan",
                severity="WARNING",
                protocol="TCP",
                message=msg,
            )
            event.compute_id()
            events.append(event)

    elif scenario == "lateral_movement":
        config = _ATTACK_SCENARIOS["lateral_movement"]
        ips = config["internal_ips"]
        for i in range(min(num_events, len(ips) - 1)):
            src = ips[i]
            dst = ips[i + 1]
            msg_template = random.choice(config["messages"])
            port = random.randint(40000, 65535)
            msg = msg_template.format(src=src, dst=dst, port=port)
            ts = now.timestamp() + (i * 30)  # 30s between pivots

            event = LogEvent(
                source_type="synthetic",
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                timestamp_unix=ts,
                source_ip=src,
                dest_ip=dst,
                category="authentication",
                action="lateral_movement",
                severity="ERROR",
                username="admin",
                message=msg,
            )
            event.compute_id()
            events.append(event)

    elif scenario == "data_exfiltration":
        config = _ATTACK_SCENARIOS["data_exfiltration"]
        for i in range(num_events):
            dst = random.choice(config["external_ips"])
            size = random.randint(10, 500)
            port = random.choice([80, 443, 8080, 53])
            msg_template = random.choice(config["messages"])
            msg = msg_template.format(
                src=config["internal_ip"], dst=dst, port=port, size=size
            )
            ts = now.timestamp() + (i * 5)

            event = LogEvent(
                source_type="synthetic",
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                timestamp_unix=ts,
                source_ip=config["internal_ip"],
                dest_ip=dst,
                dest_port=port,
                category="network",
                action="data_transfer",
                severity="ERROR",
                message=msg,
            )
            event.compute_id()
            events.append(event)

    elif scenario == "full_attack":
        # Multi-stage: recon → brute force → pivot → escalate → exfil
        events.extend(generate_synthetic_attack("port_scan", 18))
        events.extend(generate_synthetic_attack("brute_force", 30))
        events.extend(generate_synthetic_attack("lateral_movement", 4))
        events.extend(generate_synthetic_attack("data_exfiltration", 10))

    logger.info(f"Generated {len(events)} synthetic events (scenario: {scenario})")
    return events
