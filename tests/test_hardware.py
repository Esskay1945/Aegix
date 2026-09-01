"""
Unit tests for Hardware Profiler and Network Monitor.
"""
from core.hardware_profiler import profile_system, get_profile
from core.network_monitor import get_status


def test_hardware_profiler():
    profile = profile_system()
    assert profile.os_name != ""
    assert profile.cpu_arch != ""
    assert profile.hostname != ""
    
    prompt_ctx = profile.to_prompt_context()
    assert "SYSTEM HARDWARE PROFILE" in prompt_ctx
    assert profile.os_name in prompt_ctx

    fixer_ctx = profile.to_fixer_context()
    assert "SYSTEM HARDWARE PROFILE" in fixer_ctx


def test_network_monitor_status():
    status = get_status()
    assert "online" in status
    assert "last_check" in status
