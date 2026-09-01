"""
End-to-end pipeline tests for AEGIX agents (Sentinel, Detective, Tactician, Fixer, Overlord).
"""
import pytest
from agents.sentinel import SentinelAgent
from agents.detective import DetectiveAgent
from agents.tactician import TacticianAgent
from agents.fixer import FixerAgent
from agents.overlord import OverlordBrain
from ingestion.live_capture import generate_synthetic_attack


def test_sentinel_synthetic_processing():
    sentinel = SentinelAgent()
    res = sentinel.run_synthetic_demo("brute_force")

    assert res["status"] == "complete"
    assert res["events_parsed"] > 0
    assert len(res["anomalies"]) > 0
    # Check that brute force was caught
    anomaly_types = [a["anomaly_type"] for a in res["anomalies"]]
    assert "brute_force" in anomaly_types or "brute_force_success" in anomaly_types


def test_overlord_full_attack_pipeline():
    brain = OverlordBrain()
    # Run full attack demo (synthetic data, dry_run safe execution)
    result = brain.run_demo("brute_force")

    assert result["status"] == "threat_detected"
    assert result["risk_score"] > 0
    assert "incident_id" in result
    assert result["report"]["report_file"] is not None
