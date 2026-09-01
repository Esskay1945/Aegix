"""
Integration tests for AEGIX Web Server and REST/WebSocket endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from server import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_index_page(client):
    """Test that the index.html frontend is served correctly."""
    response = client.get("/")
    assert response.status_code == 200
    assert "AEGIX" in response.text
    assert "Orbitron" in response.text


def test_api_status(client):
    """Test /api/status endpoint returning real system telemetry."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "uptime_seconds" in data
    assert "hardware" in data
    assert "architecture" in data["hardware"]
    assert "network" in data
    assert "agents" in data
    assert "sentinel" in data["agents"]
    assert "detective" in data["agents"]
    assert "tactician" in data["agents"]
    assert "fixer" in data["agents"]


def test_api_hardware(client):
    """Test /api/hardware endpoint returning hardware profiler context."""
    response = client.get("/api/hardware")
    assert response.status_code == 200
    data = response.json()
    assert "os_name" in data
    assert "cpu_arch" in data
    assert "ram_total_gb" in data
    assert "execution_env" in data


def test_api_agents(client):
    """Test /api/agents endpoint returning 4 orbiting agents and Overlord telemetry."""
    response = client.get("/api/agents")
    assert response.status_code == 200
    data = response.json()
    assert len(data["agents"]) == 4
    agent_names = [a["name"] for a in data["agents"]]
    assert "SENTINEL" in agent_names
    assert "DETECTIVE" in agent_names
    assert "TACTICIAN" in agent_names
    assert "FIXER" in agent_names
    assert data["orchestrator"]["status"] == "ONLINE"


def test_api_memory(client):
    """Test /api/memory endpoint returning RL memory stats."""
    response = client.get("/api/memory")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data


def test_api_voice_process_audit(client):
    """Test /api/voice/process endpoint with system audit voice directive."""
    response = client.post("/api/voice/process", json={"transcript": "run threat audit"})
    assert response.status_code == 200
    data = response.json()
    assert "speech_text" in data
    assert "chat_text" in data
    assert data["intent"] == "SYSTEM_AUDIT"


def test_api_voice_process_demo(client):
    """Test /api/voice/process endpoint triggering attack simulation via voice."""
    response = client.post("/api/voice/process", json={"transcript": "simulate brute force attack"})
    assert response.status_code == 200
    data = response.json()
    assert data["intent"] == "ATTACK_DEMO"
    assert "pipeline_result" in data
    assert data["pipeline_result"]["risk_score"] > 0


def test_api_chat(client):
    """Test /api/chat endpoint for interactive text conversation."""
    response = client.post("/api/chat", json={"message": "What is the status of our firewalls?"})
    assert response.status_code == 200
    data = response.json()
    assert "chat_text" in data
    assert len(data["chat_text"]) > 0


def test_api_demo(client):
    """Test /api/demo endpoint for triggering attack pipelines."""
    response = client.post("/api/demo", json={"scenario": "brute_force"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "pipeline_result" in data
    assert "toast" in data
    assert "CRITICAL THREAT" in data["toast"]["title"]
