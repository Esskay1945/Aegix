"""
AEGIX Network Monitor — Online/Offline Heartbeat Detection
Continuously monitors internet connectivity and provides the
"Smart Switch" for routing between local and cloud LLMs.

When transitioning ONLINE → triggers threat feed sync.
When transitioning OFFLINE → Brain switches to local-only mode.
"""
import time
import socket
import logging
import threading
from typing import Callable, Optional
from config import settings

logger = logging.getLogger("aegix.network_monitor")

# ═══════════════════════════════════════════════════════════════
# Network State
# ═══════════════════════════════════════════════════════════════

_network_state = {
    "online": False,
    "last_check": 0.0,
    "last_transition": 0.0,
    "check_count": 0,
}

_state_lock = threading.Lock()
_monitor_thread: Optional[threading.Thread] = None
_on_state_change_callbacks: list = []


# Reliable endpoints to test connectivity
_HEARTBEAT_TARGETS = [
    ("8.8.8.8", 53),           # Google DNS
    ("1.1.1.1", 53),           # Cloudflare DNS
    ("208.67.222.222", 53),    # OpenDNS
    ("9.9.9.9", 53),           # Quad9 DNS
]


def _check_connectivity() -> bool:
    """
    Check internet connectivity by attempting TCP connections
    to reliable DNS servers. Returns True if any succeed.
    """
    for host, port in _HEARTBEAT_TARGETS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(settings.HEARTBEAT_TIMEOUT)
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.timeout, socket.error, OSError):
            continue
    return False


def is_online() -> bool:
    """
    Get current network state.
    Uses cached value if checked within last interval.
    """
    with _state_lock:
        now = time.time()
        # Use cached value if recent enough
        if now - _network_state["last_check"] < settings.HEARTBEAT_INTERVAL:
            return _network_state["online"]

    # Perform fresh check
    online = _check_connectivity()
    _update_state(online)
    return online


def _update_state(online: bool):
    """Update network state and fire callbacks on transitions."""
    with _state_lock:
        prev_state = _network_state["online"]
        _network_state["online"] = online
        _network_state["last_check"] = time.time()
        _network_state["check_count"] += 1

        state_changed = prev_state != online

        if state_changed:
            _network_state["last_transition"] = time.time()
            direction = "ONLINE" if online else "OFFLINE"
            logger.warning(f"Network state transition: → {direction}")

    # Fire callbacks outside lock
    if state_changed:
        for callback in _on_state_change_callbacks:
            try:
                callback(online)
            except Exception as e:
                logger.error(f"Network state callback error: {e}")


def on_state_change(callback: Callable[[bool], None]):
    """
    Register a callback for network state transitions.
    Callback receives True (went online) or False (went offline).
    Used by: Overlord (route switching), threat_feeds (sync trigger).
    """
    _on_state_change_callbacks.append(callback)


def _monitor_loop():
    """Background thread that continuously monitors connectivity."""
    logger.info(
        f"Network heartbeat monitor started "
        f"(interval={settings.HEARTBEAT_INTERVAL}s, "
        f"timeout={settings.HEARTBEAT_TIMEOUT}s)"
    )
    while True:
        try:
            online = _check_connectivity()
            _update_state(online)
        except Exception as e:
            logger.error(f"Heartbeat monitor error: {e}")
        time.sleep(settings.HEARTBEAT_INTERVAL)


def start_monitor():
    """Start the background network heartbeat monitor thread."""
    global _monitor_thread
    if _monitor_thread is not None and _monitor_thread.is_alive():
        return

    # Do initial check synchronously
    initial = _check_connectivity()
    _update_state(initial)
    logger.info(f"Initial network state: {'ONLINE' if initial else 'OFFLINE'}")

    # Start background thread
    _monitor_thread = threading.Thread(
        target=_monitor_loop,
        daemon=True,
        name="aegix-network-monitor",
    )
    _monitor_thread.start()


def get_status() -> dict:
    """Get full network monitor status for dashboard/debug."""
    with _state_lock:
        return {
            "online": _network_state["online"],
            "last_check": _network_state["last_check"],
            "last_transition": _network_state["last_transition"],
            "check_count": _network_state["check_count"],
            "heartbeat_interval": settings.HEARTBEAT_INTERVAL,
        }
