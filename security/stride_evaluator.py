"""
AEGIX STRIDE Evaluator — Threat Model Evaluation Per Action (EDITH Layer 2)
Before The Fixer executes any OS-level command, the Overlord runs a STRIDE
evaluation to assess the risk of that action.

STRIDE categories:
  S — Spoofing (Can this action be faked?)
  T — Tampering (Can this action modify critical data?)
  R — Repudiation (Can the actor deny doing this?)
  I — Information Disclosure (Can this leak sensitive data?)
  D — Denial of Service (Can this disrupt legitimate operations?)
  E — Elevation of Privilege (Can this grant unauthorized access?)

Actions with unacceptably high STRIDE scores are BLOCKED or escalated.
Adapted from EDITH Pentagon Layer 2: Capability Guard.
"""
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("aegix.security.stride")


@dataclass
class STRIDEResult:
    """Result of a STRIDE threat model evaluation."""

    # Individual scores (0.0 = no risk, 1.0 = maximum risk)
    spoofing: float = 0.0
    tampering: float = 0.0
    repudiation: float = 0.0
    information_disclosure: float = 0.0
    denial_of_service: float = 0.0
    elevation_of_privilege: float = 0.0

    # Computed fields
    total_score: float = 0.0
    risk_level: str = "LOW"       # LOW, MEDIUM, HIGH, CRITICAL
    approved: bool = True
    warnings: list = field(default_factory=list)
    blocked_reason: str = ""

    def compute(self, threshold: float = 3.0):
        """Compute total score and risk level."""
        self.total_score = (
            self.spoofing + self.tampering + self.repudiation +
            self.information_disclosure + self.denial_of_service +
            self.elevation_of_privilege
        )

        if self.total_score <= 1.5:
            self.risk_level = "LOW"
        elif self.total_score <= 3.0:
            self.risk_level = "MEDIUM"
        elif self.total_score <= 4.5:
            self.risk_level = "HIGH"
        else:
            self.risk_level = "CRITICAL"

        self.approved = self.total_score <= threshold


# ═══════════════════════════════════════════════════════════════
# Dangerous Command Patterns (OS-level)
# ═══════════════════════════════════════════════════════════════

# Commands that should NEVER be auto-executed
_BLOCKED_COMMANDS = [
    r"rm\s+-rf\s+/",              # Nuclear delete on Linux
    r"del\s+/s\s+/q\s+C:\\",      # Nuclear delete on Windows
    r"format\s+C:",               # Format system drive
    r":(){ :\|:& };:",            # Fork bomb
    r"mkfs\.",                    # Filesystem format
    r"dd\s+if=.*of=/dev/sd",     # Raw disk overwrite
    r"shutdown",                  # System shutdown
    r"reboot",                    # System reboot
    r"reg\s+delete.*HKLM",       # Delete Windows registry keys
    r"Remove-Item.*-Recurse.*C:\\Windows",  # Delete Windows dir
    r"Stop-Service.*WinDefend",  # Disable Windows Defender
]

# Commands that significantly elevate risk
_HIGH_RISK_PATTERNS = [
    r"Stop-Process",             # Kill processes
    r"kill\s+-9",                # Force kill
    r"taskkill",                 # Windows task kill
    r"iptables.*DROP",           # Firewall block
    r"New-NetFirewallRule",      # Windows firewall rule
    r"netsh\s+advfirewall",      # Windows firewall
    r"chmod\s+777",              # Wide open permissions
    r"net\s+user.*\/add",        # Add user account
    r"sc\s+stop",                # Stop service
    r"sc\s+delete",              # Delete service
]

# System-critical processes that should NEVER be killed
_PROTECTED_PROCESSES = [
    "svchost", "csrss", "lsass", "winlogon", "services",
    "wininit", "smss", "system", "idle", "explorer",
    "dwm", "conhost", "fontdrvhost", "sihost", "taskhostw",
    # Linux
    "init", "systemd", "journald", "udevd", "sshd",
    # macOS
    "launchd", "kernel_task", "WindowServer",
]


def evaluate_command(command: str, agent_name: str = "fixer") -> STRIDEResult:
    """
    Evaluate a proposed OS command against the STRIDE threat model.

    This is the gatekeeper for The Fixer's autonomous execution.
    """
    result = STRIDEResult()
    cmd_lower = command.lower().strip()

    # ── Check for absolutely blocked commands ──
    for pattern in _BLOCKED_COMMANDS:
        if re.search(pattern, command, re.IGNORECASE):
            result.tampering = 1.0
            result.denial_of_service = 1.0
            result.elevation_of_privilege = 1.0
            result.blocked_reason = f"BLOCKED: Command matches destructive pattern '{pattern}'"
            result.approved = False
            result.warnings.append(result.blocked_reason)
            result.compute(threshold=0)  # Force block
            logger.critical(f"STRIDE BLOCKED command from {agent_name}: {command}")
            return result

    # ── Check for protected process targeting ──
    for proc in _PROTECTED_PROCESSES:
        if proc.lower() in cmd_lower:
            result.denial_of_service = 0.9
            result.tampering = 0.8
            result.warnings.append(
                f"WARNING: Command targets system-critical process '{proc}'. "
                "Killing this process may crash the OS."
            )

    # ── Evaluate STRIDE dimensions ──

    # Spoofing: Can this action fake identity?
    if any(p in cmd_lower for p in ["net user", "useradd", "adduser", "runas"]):
        result.spoofing = 0.7
        result.warnings.append("Spoofing risk: Command creates/modifies user accounts")

    # Tampering: Can this modify critical data?
    if any(p in cmd_lower for p in ["del ", "rm ", "remove-item", "reg delete", "chmod"]):
        result.tampering = 0.6
        result.warnings.append("Tampering risk: Command modifies/deletes files or settings")

    # Repudiation: Can the actor deny doing this?
    # All commands are audit-logged, so repudiation is low
    result.repudiation = 0.1

    # Information Disclosure: Can this leak data?
    if any(p in cmd_lower for p in ["type ", "cat ", "get-content", "more ", "curl ", "wget "]):
        result.information_disclosure = 0.4
        result.warnings.append("Info disclosure risk: Command reads/transfers data")

    # Denial of Service: Can this disrupt operations?
    if any(p in cmd_lower for p in _HIGH_RISK_PATTERNS):
        result.denial_of_service += 0.5
        result.warnings.append("DoS risk: Command may disrupt running services")

    # Elevation of Privilege: Does this grant more access?
    if any(p in cmd_lower for p in ["sudo ", "runas", "escalate", "admin", "privilege"]):
        result.elevation_of_privilege = 0.8
        result.warnings.append("EoP risk: Command involves privilege escalation")

    # Compute final score
    result.compute(threshold=3.0)

    if not result.approved:
        logger.warning(
            f"STRIDE REJECTED command from {agent_name}: "
            f"score={result.total_score:.1f} ({result.risk_level}) — {command[:80]}"
        )
    else:
        logger.info(
            f"STRIDE APPROVED command from {agent_name}: "
            f"score={result.total_score:.1f} ({result.risk_level}) — {command[:80]}"
        )

    return result


def evaluate_action(
    action_type: str,
    action_details: dict,
    agent_name: str = "fixer",
) -> STRIDEResult:
    """
    Evaluate a non-command action (e.g., firewall rule, file quarantine).
    Higher-level than evaluate_command.
    """
    result = STRIDEResult()

    if action_type == "block_ip":
        result.denial_of_service = 0.3
        result.warnings.append("Blocking an IP may disrupt legitimate traffic if misidentified")

    elif action_type == "kill_process":
        process_name = action_details.get("process", "").lower()
        if process_name in [p.lower() for p in _PROTECTED_PROCESSES]:
            result.denial_of_service = 0.9
            result.tampering = 0.8
            result.warnings.append(f"CRITICAL: '{process_name}' is a system-critical process!")
        else:
            result.denial_of_service = 0.3

    elif action_type == "quarantine_file":
        result.tampering = 0.3
        result.warnings.append("File quarantine moves files — ensure they're not system-critical")

    elif action_type == "modify_firewall":
        result.denial_of_service = 0.4
        result.tampering = 0.4
        result.warnings.append("Firewall modifications affect network connectivity")

    result.compute(threshold=3.0)
    return result
