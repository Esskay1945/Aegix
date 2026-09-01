"""
AEGIX OS Executor — Cross-Platform Command Execution (The Fixer's Hands)
Executes OS-level commands for autonomous remediation.
All commands are STRIDE-gated and audit-logged.
Uses hardware_profiler to determine correct platform commands.
"""
import subprocess
import logging
import time
import platform
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger("aegix.response.os_executor")


@dataclass
class ExecutionResult:
    """Result of an OS command execution."""
    command: str = ""
    success: bool = False
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    platform: str = ""
    blocked: bool = False
    blocked_reason: str = ""


def execute_command(
    command: str,
    timeout: int = 30,
    shell: bool = True,
    dry_run: bool = False,
) -> ExecutionResult:
    """
    Execute an OS command with STRIDE gating and audit logging.
    
    All commands pass through:
    1. STRIDE evaluation (security/stride_evaluator.py)
    2. Execution with timeout
    3. Audit chain logging
    """
    from security.stride_evaluator import evaluate_command
    from security.audit_chain import get_audit_chain

    audit = get_audit_chain()
    result = ExecutionResult(command=command, platform=platform.system())

    # ── STRIDE Gate ──
    stride_result = evaluate_command(command)
    if not stride_result.approved:
        result.blocked = True
        result.blocked_reason = stride_result.blocked_reason or f"STRIDE score too high: {stride_result.total_score}"
        audit.log_event("fixer", "COMMAND_BLOCKED", {
            "command": command[:200],
            "stride_score": stride_result.total_score,
            "risk_level": stride_result.risk_level,
            "reason": result.blocked_reason,
        }, severity="WARNING")
        logger.warning(f"Command BLOCKED by STRIDE: {command[:100]} — {result.blocked_reason}")
        return result

    # ── Dry Run Mode ──
    if dry_run:
        result.success = True
        result.stdout = f"[DRY RUN] Would execute: {command}"
        audit.log_event("fixer", "COMMAND_DRY_RUN", {
            "command": command[:200],
            "stride_score": stride_result.total_score,
        })
        return result

    # ── Execute ──
    start = time.time()
    try:
        # Use platform-appropriate shell
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True, text=True, timeout=timeout,
                shell=False,
            )
        else:
            proc = subprocess.run(
                command, capture_output=True, text=True,
                timeout=timeout, shell=shell,
            )

        result.return_code = proc.returncode
        result.stdout = proc.stdout[:2000]  # Limit output size
        result.stderr = proc.stderr[:2000]
        result.success = proc.returncode == 0
        result.duration_ms = (time.time() - start) * 1000

        audit.log_event("fixer", "COMMAND_EXECUTED", {
            "command": command[:200],
            "return_code": result.return_code,
            "success": result.success,
            "duration_ms": result.duration_ms,
            "stride_score": stride_result.total_score,
        }, severity="INFO" if result.success else "WARNING")

        if result.success:
            logger.info(f"Command executed successfully: {command[:100]} ({result.duration_ms:.0f}ms)")
        else:
            logger.warning(f"Command failed (rc={result.return_code}): {command[:100]} — {result.stderr[:100]}")

    except subprocess.TimeoutExpired:
        result.stderr = f"Command timed out after {timeout}s"
        result.duration_ms = timeout * 1000
        audit.log_event("fixer", "COMMAND_TIMEOUT", {
            "command": command[:200],
            "timeout": timeout,
        }, severity="WARNING")
        logger.warning(f"Command timed out: {command[:100]}")

    except Exception as e:
        result.stderr = str(e)
        audit.log_event("fixer", "COMMAND_ERROR", {
            "command": command[:200],
            "error": str(e),
        }, severity="ERROR")
        logger.error(f"Command execution error: {command[:100]} — {e}")

    return result


# ═══════════════════════════════════════════════════════════════
# Platform-Specific Remediation Commands
# ═══════════════════════════════════════════════════════════════

def block_ip(ip: str, dry_run: bool = False) -> ExecutionResult:
    """Block an IP address at the firewall level."""
    if platform.system() == "Windows":
        cmd = f'New-NetFirewallRule -DisplayName "AEGIX Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'
    elif platform.system() == "Linux":
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
    elif platform.system() == "Darwin":
        cmd = f'echo "block drop from {ip}" | pfctl -a aegix -f -'
    else:
        cmd = f"echo 'Block IP {ip} — platform not supported'"

    return execute_command(cmd, dry_run=dry_run)


def kill_process(process_name: str, dry_run: bool = False) -> ExecutionResult:
    """Kill a process by name."""
    if platform.system() == "Windows":
        cmd = f'Stop-Process -Name "{process_name}" -Force -ErrorAction SilentlyContinue'
    else:
        cmd = f"pkill -f '{process_name}'"

    return execute_command(cmd, dry_run=dry_run)


def quarantine_file(filepath: str, dry_run: bool = False) -> ExecutionResult:
    """Move a suspicious file to quarantine directory."""
    import os
    quarantine_dir = os.path.join("data", "quarantine")

    if platform.system() == "Windows":
        cmd = f'New-Item -ItemType Directory -Force -Path "{quarantine_dir}"; Move-Item -Path "{filepath}" -Destination "{quarantine_dir}" -Force'
    else:
        cmd = f'mkdir -p "{quarantine_dir}" && mv "{filepath}" "{quarantine_dir}/"'

    return execute_command(cmd, dry_run=dry_run)


def get_running_processes() -> ExecutionResult:
    """Get list of running processes."""
    if platform.system() == "Windows":
        cmd = "Get-Process | Select-Object -First 50 Name, Id, CPU, WorkingSet64 | ConvertTo-Json"
    else:
        cmd = "ps aux --sort=-%cpu | head -50"

    return execute_command(cmd)
