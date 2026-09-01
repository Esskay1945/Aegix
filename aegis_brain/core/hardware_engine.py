"""
Hardware-Aware Context Engine for AEGIS Brain.
Profiles host OS and CPU architecture (Intel/AMD x86_64 vs ARM64) on boot
and provides dynamic system instructions for all sub-agents.
"""

import platform
import os
import sys
import psutil if False else None  # optional
from typing import Dict, Any
from aegis_brain.models.schema import HardwareProfile


class HardwareContextEngine:
    """
    Profiles the host hardware and OS to ensure universal adaptability
    across Intel, AMD Ryzen, ARM64 (Apple Silicon, Snapdragon, Raspberry Pi),
    Windows, Linux, and macOS.
    """

    def __init__(self, override_profile: Dict[str, Any] = None):
        self.profile = self._profile_system(override_profile)

    def _profile_system(self, override: Dict[str, Any] = None) -> HardwareProfile:
        if override:
            return HardwareProfile(**override)

        uname = platform.uname()
        os_name = uname.system
        os_release = uname.release
        os_version = uname.version
        raw_arch = uname.machine.lower()
        processor = uname.processor or "Generic Processor"

        # Standardize architecture names
        if "arm" in raw_arch or "aarch" in raw_arch:
            arch = "ARM64"
        elif "64" in raw_arch or "x86" in raw_arch or "amd" in raw_arch:
            arch = "x86_64"
        else:
            arch = raw_arch.upper()

        # Logical & Physical cores
        cores_logical = os.cpu_count() or 4
        cores_physical = max(1, cores_logical // 2)

        # Estimate RAM
        total_ram_gb = 16.0
        try:
            import ctypes
            if os_name == "Windows":
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                total_ram_gb = round(stat.ullTotalPhys / (1024 ** 3), 1)
            elif os_name == "Linux":
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if "MemTotal" in line:
                            kb = int(line.split()[1])
                            total_ram_gb = round(kb / (1024 ** 2), 1)
                            break
        except Exception:
            pass

        # Execution environment determination
        if os_name == "Windows":
            exec_env = f"Windows-{arch}-PowerShell"
        elif os_name == "Linux":
            exec_env = f"Linux-{arch}-Bash"
        elif os_name == "Darwin":
            exec_env = f"macOS-{arch}-Zsh"
        else:
            exec_env = f"{os_name}-{arch}-Shell"

        platform_str = f"{os_name} {os_release} ({arch}) [{processor}]"

        return HardwareProfile(
            os_name=os_name,
            os_version=os_version,
            os_release=os_release,
            architecture=arch,
            processor=processor,
            cpu_cores_logical=cores_logical,
            cpu_cores_physical=cores_physical,
            total_ram_gb=total_ram_gb,
            platform_details=platform_str,
            execution_environment=exec_env
        )

    def get_hardware_prompt_modifier(self, agent_name: str) -> str:
        """
        Dynamically generates architecture-specific system prompt injection
        for a given agent.
        """
        p = self.profile
        base_prompt = f"""
[HARDWARE & OS CONTEXT - AGENT AWARENESS]
- Host Platform: {p.os_name} {p.os_release}
- Architecture: {p.architecture} ({p.processor})
- Execution Target: {p.execution_environment}
- System Resources: {p.cpu_cores_logical} Logical Cores, {p.total_ram_gb} GB RAM
"""
        if agent_name == "The Fixer":
            if p.os_name == "Windows" and p.architecture == "x86_64":
                specifics = """
[FIXER EXECUTION DIRECTIVES - WINDOWS x64 (AMD/INTEL)]
- Use Windows PowerShell x64 commands (e.g., Stop-Process -Name, New-NetFirewallRule).
- Ensure 64-bit Registry & System32 binary paths are used.
- Target Windows PE32+ x64 binaries, dll injection hooks, and WMI services.
- Never terminate critical Windows subsystem processes (csrss.exe, wininit.exe, lsass.exe without quarantine protocol).
"""
            elif p.os_name == "Windows" and p.architecture == "ARM64":
                specifics = """
[FIXER EXECUTION DIRECTIVES - WINDOWS ARM64]
- Ensure commands account for ARM64 native processes vs x86/x64 emulation processes (WoW64/WoA).
- Use ARM64-compatible PowerShell core syntax and netsh / NetSecurity cmdlets.
- Verify whether malicious binary is native ARM64 or translated x86 emulation payload.
"""
            elif p.os_name == "Linux":
                specifics = f"""
[FIXER EXECUTION DIRECTIVES - LINUX {p.architecture}]
- Use Linux system commands (iptables/nftables, pkill, systemctl, chmod 000).
- Check {p.architecture} ELF binary execution formats and /proc file descriptors.
"""
            else:
                specifics = f"""
[FIXER EXECUTION DIRECTIVES - {p.os_name} {p.architecture}]
- Use standard POSIX / OS-native containment APIs and process isolation.
"""
            return base_prompt + specifics

        elif agent_name == "The Detective":
            specifics = f"""
[DETECTIVE ANALYSIS DIRECTIVES - {p.architecture} ARCHITECTURE]
- Correlate threat patterns considering {p.architecture}-specific exploits (e.g., memory corruption, buffer overflows, ROP gadgets, or arch-specific shellcode).
- Detect cross-architecture lateral movement (e.g., x64 C2 communicating with ARM IoT edge nodes).
"""
            return base_prompt + specifics

        elif agent_name == "The Sentinel":
            specifics = f"""
[SENTINEL PERIMETER FILTER DIRECTIVES]
- Optimize log filtering throughput based on host hardware ({p.cpu_cores_logical} cores available).
- Drop low-severity noise locally at high speed before passing to cognitive analysis.
"""
            return base_prompt + specifics

        elif agent_name == "The Tactician":
            specifics = f"""
[TACTICIAN STRATEGY DIRECTIVES]
- Document target host hardware architecture ({p.architecture} on {p.os_name}) in the official Incident Report.
- Contextualize vulnerability exploitability based on whether the payload matches the target host architecture.
"""
            return base_prompt + specifics

        return base_prompt
