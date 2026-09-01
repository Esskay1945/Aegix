"""
Unit tests for Memory (ChromaDB RL Long-Term Memory).
"""
import pytest
from core.memory import store_lesson, recall_similar, generate_memory_context, get_memory_stats


def test_memory_store_and_recall():
    stats = get_memory_stats()
    if stats.get("status") != "ACTIVE":
        pytest.skip("ChromaDB not active or installed")

    # Store a lesson
    lesson_id = store_lesson(
        incident_summary="SSH Brute Force from 185.220.101.10 targeting root",
        action_taken="Blocked IP at firewall and terminated session",
        critic_score=1,
        agent_name="overlord",
        metadata={"attack_type": "brute_force"}
    )
    assert lesson_id != ""

    # Recall similar
    recalled = recall_similar("SSH brute force attack from malicious IP", top_k=3)
    assert len(recalled) > 0
    assert any("SSH Brute Force" in r["document"] for r in recalled)

    # Generate memory context
    ctx = generate_memory_context("SSH brute force attack")
    assert "MEMORY CONTEXT" in ctx
    assert "SUCCESSFUL" in ctx
