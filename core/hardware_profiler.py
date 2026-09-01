"""
AEGIX Hardware Profiler — Boot-Up Self-Diagnostic
Detects OS, CPU architecture, GPU, RAM, and generates dynamic
system prompt context for all agents.

This is the "Who Am I?" phase — the Brain profiles the hardware
before it starts analyzing threats, and injects architecture-specific
instructions into every agent's system prompt.
"""
import os
import sys
import platform
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("aegix.hardware_profiler")


@dataclass
class SystemProfile:
    """Complete hardware and OS profile of the host system."""

    # Operating System
    os_name: str = ""                # Windows, Linux, Darwin (macOS)
    os_version: str = ""             # 10.0.22631, 6.5.0-45-generic, etc.
    os_release: str = ""             # 11, 22.04, Ventura, etc.
    os_arch: str = ""                # AMD64, ARM64, x86_64, aarch64

    # CPU
    cpu_brand: str = ""              # AMD Ryzen 7 7800X3D, Intel i5-13600K, Apple M2
    cpu_arch: str = ""               # x86_64, ARM64, aarch64
    cpu_cores_physical: int = 0
    cpu_cores_logical: int = 0

    # Memory
    ram_total_gb: float = 0.0
    ram_available_gb: float = 0.0

    # GPU
    gpu_available: bool = False
    gpu_name: str = ""
    gpu_backend: str = ""            # CUDA, ROCm, Metal, None

    # Disk
    disk_free_gb: float = 0.0

    # Python
    python_version: str = ""

    # Network hostname
    hostname: str = ""

    def to_prompt_context(self) -> str:
        """
        Generate a system prompt context block that the Overlord injects
        into every agent's system prompt for hardware-aware operation.
        """
        gpu_info = f"{self.gpu_name} ({self.gpu_backend})" if self.gpu_available else "No GPU detected"

        return (
            f"=== SYSTEM HARDWARE PROFILE ===\n"
            f"Hostname: {self.hostname}\n"
            f"OS: {self.os_name} {self.os_release} ({self.os_version})\n"
            f"Architecture: {self.os_arch}\n"
            f"CPU: {self.cpu_brand}\n"
            f"CPU Architecture: {self.cpu_arch}\n"
            f"CPU Cores: {self.cpu_cores_physical} physical / {self.cpu_cores_logical} logical\n"
            f"RAM: {self.ram_total_gb:.1f} GB total / {self.ram_available_gb:.1f} GB available\n"
            f"GPU: {gpu_info}\n"
            f"Disk Free: {self.disk_free_gb:.1f} GB\n"
            f"Python: {self.python_version}\n"
            f"=== END HARDWARE PROFILE ===\n\n"
            f"IMPORTANT: You are operating on a {self.os_name} {self.cpu_arch} system. "
            f"All OS-level commands, file paths, and system calls MUST be compatible with "
            f"this architecture. "
        )

    def to_fixer_context(self) -> str:
        """
        Generate Fixer-specific context with OS-appropriate command guidance.
        """
        base = self.to_prompt_context()

        if self.os_name == "Windows":
            return base + (
                "When executing system commands, use PowerShell syntax. "
                "Use 'Get-Process' instead of 'ps', 'Stop-Process' instead of 'kill', "
                "'New-NetFirewallRule' for firewall rules, and Windows-native paths (C:\\). "
                f"{'Use standard x64 execution paths.' if 'x86_64' in self.cpu_arch or 'AMD64' in self.os_arch else 'Ensure ARM64 compatibility for all binaries and scripts.'}"
            )
        elif self.os_name == "Linux":
            return base + (
                "When executing system commands, use bash syntax. "
                "Use 'kill', 'iptables'/'nftables' for firewall rules, "
                "and Linux paths (/). "
                f"{'Use standard x86_64 execution paths.' if 'x86_64' in self.cpu_arch else 'Ensure aarch64/ARM64 compatibility for all binaries.'}"
            )
        elif self.os_name == "Darwin":
            return base + (
                "When executing system commands, use zsh/bash syntax. "
                "Use 'kill', 'pfctl' for firewall rules, and macOS paths (/). "
                f"{'Use Apple Silicon (ARM64) native binaries where possible.' if 'arm' in self.cpu_arch.lower() else 'Use Intel x86_64 execution paths.'}"
            )
        return base


def _get_cpu_brand() -> str:
    """Get the CPU brand string across platforms."""
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            cpu_brand, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            return cpu_brand.strip()
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        return line.split(":")[1].strip()
        elif platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
    except Exception as e:
        logger.warning(f"Could not detect CPU brand: {e}")
    return platform.processor() or "Unknown CPU"


def _get_gpu_info() -> tuple:
    """Detect GPU availability, name, and backend."""
    # Try CUDA (NVIDIA)
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, result.stdout.strip().split("\n")[0], "CUDA"
    except (FileNotFoundError, Exception):
        pass

    # Try ROCm (AMD)
    try:
        import subprocess
        result = subprocess.run(
            ["rocm-smi", "--showproductname"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, "AMD GPU (ROCm)", "ROCm"
    except (FileNotFoundError, Exception):
        pass

    # Try Metal (macOS Apple Silicon)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return True, "Apple Silicon (Integrated)", "Metal"

    return False, "", "None"


def _get_memory_info() -> tuple:
    """Get total and available RAM in GB."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        return mem.total / (1024 ** 3), mem.available / (1024 ** 3)
    except ImportError:
        # Fallback without psutil
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulonglong = ctypes.c_ulonglong

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", c_ulonglong),
                        ("ullAvailPhys", c_ulonglong),
                        ("ullTotalPageFile", c_ulonglong),
                        ("ullAvailPageFile", c_ulonglong),
                        ("ullTotalVirtual", c_ulonglong),
                        ("ullAvailVirtual", c_ulonglong),
                        ("ullAvailExtendedVirtual", c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                return stat.ullTotalPhys / (1024 ** 3), stat.ullAvailPhys / (1024 ** 3)
            except Exception:
                pass
        return 0.0, 0.0


def _get_disk_free() -> float:
    """Get free disk space in GB for the current drive."""
    try:
        import shutil
        usage = shutil.disk_usage(os.path.abspath("."))
        return usage.free / (1024 ** 3)
    except Exception:
        return 0.0


def profile_system() -> SystemProfile:
    """
    Run full system diagnostic and return a SystemProfile.
    Called once at Brain boot-up.
    """
    logger.info("Running hardware self-diagnostic...")

    # OS info
    os_name = platform.system()       # Windows, Linux, Darwin
    os_version = platform.version()
    os_release = platform.release()
    os_arch = platform.machine()       # AMD64, x86_64, arm64, aarch64

    # CPU info
    cpu_brand = _get_cpu_brand()
    cpu_arch = platform.machine()
    cpu_cores_physical = os.cpu_count() or 1
    cpu_cores_logical = os.cpu_count() or 1
    try:
        import psutil
        cpu_cores_physical = psutil.cpu_count(logical=False) or cpu_cores_physical
        cpu_cores_logical = psutil.cpu_count(logical=True) or cpu_cores_logical
    except ImportError:
        pass

    # Memory
    ram_total, ram_available = _get_memory_info()

    # GPU
    gpu_available, gpu_name, gpu_backend = _get_gpu_info()

    # Disk
    disk_free = _get_disk_free()

    profile = SystemProfile(
        os_name=os_name,
        os_version=os_version,
        os_release=os_release,
        os_arch=os_arch,
        cpu_brand=cpu_brand,
        cpu_arch=cpu_arch,
        cpu_cores_physical=cpu_cores_physical,
        cpu_cores_logical=cpu_cores_logical,
        ram_total_gb=ram_total,
        ram_available_gb=ram_available,
        gpu_available=gpu_available,
        gpu_name=gpu_name,
        gpu_backend=gpu_backend,
        disk_free_gb=disk_free,
        python_version=platform.python_version(),
        hostname=platform.node(),
    )

    logger.info(
        f"System Profile: {os_name} {os_arch} | "
        f"CPU: {cpu_brand} ({cpu_cores_physical}P/{cpu_cores_logical}L) | "
        f"RAM: {ram_total:.1f}GB | "
        f"GPU: {gpu_name or 'None'} ({gpu_backend})"
    )

    return profile


# Cached system profile — set on first call
_cached_profile: Optional[SystemProfile] = None


def get_profile() -> SystemProfile:
    """Get the cached system profile, running diagnostic if needed."""
    global _cached_profile
    if _cached_profile is None:
        _cached_profile = profile_system()
    return _cached_profile
