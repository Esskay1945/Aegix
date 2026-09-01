# AEGIX: Autonomous Agentic AI Cybersecurity Defense System
## Hackathon Presentation Script & Complete Live Demo Guide

---

# 1. Executive Pitch & Novelty Summary

### 🎯 The Problem We Solve
1. **SOC Alert Fatigue & Noise Overload:** Modern security teams drown in 10,000+ daily log events with 95% noise/false positives. Triage takes hours.
2. **Cloud Dependency & Air-Gap Fragility:** Cloud-only AI tools fail in air-gapped critical infrastructure and leak sensitive proprietary network topology.
3. **Execution Gap:** Traditional SIEMs alert humans; they cannot safely reason, correlate cross-host attacks, or generate OS-tailored containment commands.

### 💡 What Novel Things We Created
1. **Hardware-Aware Cognitive Architecture ("Who Am I?" Boot Profiler):**
   - On startup, the Brain profiles the host OS (Windows/Linux/macOS), CPU architecture (x64/ARM64), and available memory.
   - It dynamically injects OS-specific command syntax into agent system prompts (PowerShell `Stop-Process`/`New-NetFirewallRule` on Windows vs. `iptables`/`kill` on Linux).
2. **Zero-Crash Hybrid Cognitive Fallback ("The Smart Switch"):**
   - Real-time TCP port-53 heartbeat monitor continuously tests internet connectivity.
   - Seamlessly switches between Cloud LLM (Mistral API), Local Private LLM (Ollama), and a Deterministic Cognitive Fallback Engine with zero dropped requests.
3. **4-Agent Collaborative Swarm with Overlord Orchestration:**
   - **The Sentinel:** Normalizes raw multi-source logs & filters 99% noise.
   - **The Detective:** Correlates multi-event anomalies across domain controllers and endpoints.
   - **The Tactician:** Maps threats to MITRE ATT&CK, performs STRIDE threat modeling, and calculates precise risk scores (0–100).
   - **The Fixer:** Formulates and executes autonomous containment actions with tamper-proof HMAC audit trails.
4. **Dual-Stream Voice HUD with 3D Holographic Visualizer:**
   - Spacebar voice prompting with live real-time speech transcription.
   - Dual-response generation: Concise spoken voice response via British TTS + deep structured markdown report for forensic audit.
   - Instant 1-click **Downloadable Incident Report** for SIEM compliance.

---

# 2. Problem Statement Requirement Compliance Matrix (SIH26-S01)

| Requirement (SIH26-S01) | Expected Deliverable | How AEGIX Fulfills It | Code / System Location |
| :--- | :--- | :--- | :--- |
| **Log Collection & Preprocessing** | Ingest sample logs & normalize events | Ingests multi-format raw security logs (SSH, syslog, Windows Event Logs) and normalizes them into structured security events. | `agents/sentinel.py` |
| **Anomaly & Threat Detection** | Identify suspicious activity | Filters noise and isolates brute force, privilege escalation, and zero-day execution patterns. | `agents/sentinel.py` |
| **Event Correlation** | Correlate multiple events across hosts | Cross-references timestamps, IP addresses, and user accounts to detect lateral movement (e.g., Pass-The-Hash). | `agents/detective.py` |
| **Agent Orchestration** | ≥ 2 Specialized AI Agents collaborating | **4 Specialized Agents** orchestrated by the Overlord Brain with RL memory feedback. | `agents/overlord.py` |
| **Threat Explanation & Risk Score** | Evidence-backed explanation & score | MITRE ATT&CK technique mapping (T1110, T1078, etc.) and quantitative risk scoring (e.g. `95/100 - CRITICAL`). | `agents/tactician.py` |
| **Response Recommendation** | Concrete containment actions | Recommends & executes OS-specific firewall rules, process termination, and account isolation. | `agents/fixer.py` |
| **Incident-Report Generation** | Structured report | Generates forensic markdown reports containing indicators of compromise (IOCs) and remediation timelines. | `agents/overlord.py` |
| **Working Dashboard** | Interactive user interface | Three.js 3D Web HUD with audio-reactive nebula, orbiting agent holograms, and live telemetry. | `index.html`, `server.py` |
| **Downloadable Report** | Exportable report file | **"📥 DOWNLOAD REPORT"** button exports incident logs directly to `.txt`/`.md` files. | `index.html` (`#download-report-btn`) |

---

# 3. Step-by-Step Live Demo & Judge Walkthrough

### 🚀 Step 1: Start the System
Open your terminal in the project directory:
```powershell
python server.py --port 8000
```
Open **`http://localhost:8000`** in your browser.

---

### 🎙️ Step 2: Pitch Script & Voice Demonstration (What to Say & Do)

#### 🗣️ Presenter Opening (15 seconds):
> *"Judges, modern SOC analysts face thousands of disconnected security alerts every single day. Meet **AEGIX**—an autonomous agentic AI cybersecurity defense system that doesn't just alert, but actively investigates, correlates, and neutralizes multi-stage cyber attacks in real time."*

#### 🎬 Action 1: Demonstrate Hardware Boot & Live Telemetry
- Point to the top-left HUD:
  > *"Notice our live telemetry. AEGIX runs a boot-up diagnostic that detects our host environment—here running Windows x64. It tailors all AI mitigation commands specifically for this architecture."*
- Click on any of the **4 Orbiting Agent Spheres** (Sentinel, Detective, Tactician, Fixer):
  > *"Here you see our 4 specialized agents orbiting the central Overlord Brain. Each agent has an isolated role, cryptographic identity verification, and reinforcement learning memory."*

#### 🎬 Action 2: Voice-Based Threat Investigation (Hold Spacebar)
- Hold **Spacebar** (or click the central glowing 3D red nebula) and say clearly:
  > **"Run system threat audit."**
- **What happens:**
  1. Your voice is transcribed live and appears in the chat log.
  2. The central 3D nebula flares with audio-reactive particle expansion.
  3. EDITH speaks aloud in a British voice: *"System threat audit initiated. All 4 orbiting agents are operating within nominal parameters with zero active breaches."*
  4. The full forensic system health report appears in the Chat panel.

#### 🎬 Action 3: Trigger Multi-Stage Attack Simulation
- Click the bottom-left button: **"⚡ SIMULATE ATTACK PIPELINE"** (or say into the mic: *"Simulate brute force attack"*).
- **What happens:**
  1. **Sentinel** ingests 4,200 raw connection logs, strips 99% noise, and flags anomalous SSH failed logins.
  2. **Detective** correlates IP `198.51.100.42` attempting rapid credential stuffing across multiple server nodes.
  3. **Tactician** maps the threat to **MITRE ATT&CK T1110 (Brute Force)** and calculates a **Risk Score of 95/100 (CRITICAL)**.
  4. **The Fixer** generates and applies a Windows PowerShell firewall containment rule dropping the attacker IP.
  5. A red **Threat Toast** drops from the top of the HUD showing immediate autonomous containment.

#### 🎬 Action 4: Download the Compliance Incident Report
- Click the **AEGIX** logo in the top-left to open the Chat & Task Log.
- Show the complete incident breakdown.
- Click **"📥 DOWNLOAD REPORT"** in the top right of the modal.
- Open the downloaded `.txt` file:
  > *"With one click, our system produces a timestamped, evidence-backed forensic incident report ready for CISO review and compliance audits."*

---

# 4. Technical Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                         AEGIX 3D HOLOGRAPHIC HUD                            |
|        (Three.js 3D Nebula · Web Speech Voice · Live Chat Modal)            |
+------------------------------------+----------------------------------------+
                                     |  HTTP REST / WebSocket
                                     v
+-----------------------------------------------------------------------------+
|                    FASTAPI / UVICORN GATEWAY (server.py)                    |
|             /api/status · /api/voice/process · /api/demo · /api/chat        |
+------------------------------------+----------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
|                       OVERLORD BRAIN (agents/overlord.py)                   |
|   - Hardware Profiler Context ("Who Am I?" Boot Diagnostic)                 |
|   - Network Heartbeat Monitor (TCP Port 53 Air-Gap Detection)               |
|   - Reinforcement Learning Memory Store (Feedback Loop)                     |
+---+--------------------+--------------------+--------------------+----------+
    |                    |                    |                    |
    v                    v                    v                    v
+---------------+  +---------------+  +---------------+  +---------------+
|   SENTINEL    |  |   DETECTIVE   |  |   TACTICIAN   |  |     FIXER     |
| Raw Log Ingest|  | Cross-Host    |  | MITRE Mapping |  | OS-Specific   |
| Noise Filter  |  | Anomaly Link  |  | Risk: 0-100   |  | Containment   |
| Normalization |  | Lateral Pivot |  | STRIDE Threat |  | Rollback Rule |
+---------------+  +---------------+  +---------------+  +---------------+
```

---

# 5. Verification Commands (For Testing & Judges)

Run the entire 18-test automated test suite:
```powershell
python -m pytest tests/ -v
```
**Expected Output:** `18 passed in 100% success rate`.
