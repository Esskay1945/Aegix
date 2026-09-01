"""
AEGIX Audit Chain — SHA-256 Hash-Chained Append-Only Audit Log (EDITH Layer 5)
Every agent action, tool call, decision, and inter-agent message is recorded
in a tamper-evident hash chain. Each entry includes the hash of the previous
entry — tampering with any record breaks the chain.

This is the evidentiary foundation for incident reports (F46).
Adapted from EDITH Pentagon Layer 5: Immutable Hash-Chained Audit Trail.
"""
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from typing import Optional
from config import settings

logger = logging.getLogger("aegix.security.audit_chain")


class AuditChain:
    """
    Append-only, hash-chained audit log.
    Thread-safe. Persists to JSON Lines files.
    """

    def __init__(self, log_dir: str = None):
        self.log_dir = Path(log_dir or settings.AUDIT_LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._chain: list = []
        self._prev_hash: str = "GENESIS"  # Genesis block hash
        self._event_count: int = 0

        # Load existing chain if present
        self._log_file = self.log_dir / "audit_chain.jsonl"
        self._load_existing_chain()

    def _load_existing_chain(self):
        """Load existing audit chain from disk."""
        if self._log_file.exists():
            try:
                with open(self._log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        entry = json.loads(line.strip())
                        self._chain.append(entry)
                        self._prev_hash = entry.get("entry_hash", self._prev_hash)
                        self._event_count += 1
                logger.info(f"Loaded {self._event_count} existing audit entries")
            except Exception as e:
                logger.error(f"Failed to load audit chain: {e}")

    def log_event(
        self,
        agent_name: str,
        action: str,
        details: dict = None,
        severity: str = "INFO",
    ) -> dict:
        """
        Append a new event to the audit chain.

        Each entry contains:
        - sequence: Monotonic event number
        - timestamp: Unix timestamp
        - agent: Which agent performed the action
        - action: What was done
        - details: Additional context
        - severity: INFO, WARNING, CRITICAL
        - prev_hash: Hash of the previous entry (chain link)
        - entry_hash: SHA-256 hash of this entry (for next link)
        """
        with self._lock:
            self._event_count += 1

            entry = {
                "sequence": self._event_count,
                "timestamp": time.time(),
                "agent": agent_name,
                "action": action,
                "details": details or {},
                "severity": severity,
                "prev_hash": self._prev_hash,
            }

            # Compute hash of this entry (excluding entry_hash itself)
            entry_data = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            entry["entry_hash"] = entry_hash

            # Update chain
            self._chain.append(entry)
            self._prev_hash = entry_hash

            # Persist to disk
            try:
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                logger.error(f"Failed to persist audit entry: {e}")

            return entry

    def verify_chain_integrity(self) -> tuple:
        """
        Verify the entire audit chain for tampering.

        Returns:
            (is_valid: bool, broken_at: Optional[int])
            If is_valid is False, broken_at indicates the sequence
            number where the chain breaks.
        """
        if not self._chain:
            return True, None

        prev_hash = "GENESIS"
        for entry in self._chain:
            # Check chain link
            if entry.get("prev_hash") != prev_hash:
                return False, entry.get("sequence", 0)

            # Recompute hash
            entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed = hashlib.sha256(
                json.dumps(entry_copy, sort_keys=True).encode()
            ).hexdigest()

            if recomputed != entry.get("entry_hash"):
                return False, entry.get("sequence", 0)

            prev_hash = entry["entry_hash"]

        return True, None

    def get_entries(
        self,
        agent_name: str = None,
        action: str = None,
        last_n: int = None,
    ) -> list:
        """Query audit entries with optional filters."""
        entries = self._chain

        if agent_name:
            entries = [e for e in entries if e.get("agent") == agent_name]
        if action:
            entries = [e for e in entries if e.get("action") == action]
        if last_n:
            entries = entries[-last_n:]

        return entries

    def get_stats(self) -> dict:
        """Get audit chain statistics."""
        is_valid, broken_at = self.verify_chain_integrity()
        return {
            "total_events": self._event_count,
            "chain_valid": is_valid,
            "broken_at": broken_at,
            "log_file": str(self._log_file),
            "status": "INTACT" if is_valid else "TAMPERED",
        }


# ═══════════════════════════════════════════════════════════════
# Singleton instance
# ═══════════════════════════════════════════════════════════════

_audit_chain: Optional[AuditChain] = None


def get_audit_chain() -> AuditChain:
    """Get the singleton audit chain instance."""
    global _audit_chain
    if _audit_chain is None:
        _audit_chain = AuditChain()
    return _audit_chain
