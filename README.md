# AEGIX — Autonomous Agentic Cybersecurity Brain (SIH26-S01)

<div align="center">

```
+==========================================================+
|     ___   ______ _____ _____ _  __                       |
|    /   | / ____// ____//  _/| |/ /                       |
|   / /| |/ __/  / / __  / /  |   /                        |
|  / ___ / /___ / /_/ /_/ /  /   |                         |
| /_/  |_\____/ \____//___/ /_/|_|                         |
|                                                          |
|    Agentic Event Graph Intelligence System               |
|    Autonomous Cybersecurity Brain -- SIH26-S01           |
+==========================================================+
```

**Zero-Trust, Multi-Agent Autonomous Cybersecurity Engine with Reinforcement Learning & Cross-Platform Adaptation**

</div>

---

## 🌟 Overview

**AEGIX** is a zero-trust, multi-agent cybersecurity intelligence platform designed for autonomous threat detection, investigation, remediation, and reporting. Built on an **EDITH-inspired agentic pentagon architecture**, AEGIX operates headlessly across platforms (ARM64 Snapdragon, AMD Ryzen, Intel x86) in both air-gapped offline environments and connected online environments.

---

## 🏛️ Architecture: The Agentic Pentagon

```
                ┌─────────────────────────────────┐
                │          THE OVERLORD           │
                │    (Central Orchestrator)       │
                └────────────────┬────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  THE SENTINEL   │     │  THE DETECTIVE  │     │    THE FIXER    │
│ (Shield/Filter) │────►│ (Investigator)  │────►│(Solver/Remediate│
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  THE TACTICIAN  │
                        │(Forensic Report)│
                        └─────────────────┘
```

1. **🧠 The Overlord (The Brain):** Coordinates the agent lifecycle, dynamically injects hardware profile constraints, and manages the Reinforcement Learning feedback loop.
2. **🛡️ The Sentinel (The Shield):** Ingests raw logs and live traffic, performs deduplication, anomaly pre-filtering, and IOC matching at the perimeter.
3. **🔍 The Detective (The Investigator):** Correlates multi-source logs, models attacker intent, maps to MITRE ATT&CK techniques, and assesses composite risk scores.
4. **🔧 The Fixer (The Solver):** The only agent with execution capabilities. Synthesizes OS-adaptive remediation commands (PowerShell / iptables / firewall rules) strictly evaluated and approved by the **STRIDE execution gate**.
5. **📋 The Tactician (The Reporter):** Compiles evidence-backed forensic incident reports with executive summaries, counterfactuals, and structured JSON outputs.

---

## 🛡️ Security & Zero-Trust Features

- **Layer 1 Prompt & Input Firewall:** Pre-flight and post-flight regex and token sanitization defending against prompt injection, jailbreaks, Unicode smuggling, and secret exfiltration.
- **Agent Identity Keys (HMAC-SHA256):** Every inter-agent communication is signed and verified.
- **Tamper-Evident SHA-256 Audit Chain:** Cryptographic hash-chaining of every agent action and firewall event with integrity validation on shutdown.
- **STRIDE Execution Gating:** Every command formulated by the Fixer is evaluated against Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege before execution.
- **Hardware-Aware Context Engine:** Autonomously profiles host OS (Windows/Linux/macOS), CPU architecture (ARM64/x86_64), RAM, and network status to tailor commands dynamically.
- **Critic & Reinforcement Learning (RL) Memory:** Action outcomes are evaluated by an internal Critic (`+1` reward), stored in persistent vector memory (ChromaDB / JSON fallback), and retrieved to self-prompt future investigations.

---

## 🔄 Hybrid Intelligence Routing

- **🌐 Online Mode (Cloud LLM):** Mistral AI / OpenRouter / Cerebras for ultra-fast, high-capacity semantic reasoning and narrative generation.
- **🔒 Offline Mode (Air-Gapped Local LLM):** Local Ollama (`llama3:8b`, `deepseek-r1:7b`, etc.) without requiring an internet connection or external API keys.
- **⚡ Failover Fallback:** If LLM calls timeout or fail, the system gracefully degrades to mathematical statistical engines and rule-based safety containment.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/Esskay1945/Aegix.git
cd Aegix
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configuration

Copy `.env.example` to `.env` and configure your preferences:

```bash
cp .env.example .env
```

```env
# Offline LLM
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3:8b

# Online LLM (Optional)
ONLINE_LLM_PROVIDER=mistral
ONLINE_LLM_API_KEY=your_mistral_api_key_here
ONLINE_LLM_MODEL=mistral-small-latest
```

### 3. Usage

#### Run the Autonomous Demo (Synthetic Multi-Stage Attack Scenario):
```bash
python main.py --demo
```

#### Run Live Network Monitoring:
```bash
python main.py --live
```

#### Interactive Brain Chat:
```bash
python main.py
```

#### Run the Test Suite:
```bash
pytest
```

---

## 📂 Project Structure

```
AEGIX/
├── agents/                 # Agent Implementations
│   ├── overlord.py         # Central orchestrator & RL coordinator
│   ├── sentinel.py         # Multi-level firewall & anomaly filter
│   ├── detective.py        # Intent modeling & MITRE ATT&CK correlation
│   ├── tactician.py        # Forensic report generator
│   └── fixer.py            # OS-adaptive solver
├── core/                   # Core Engine
│   ├── hardware_profiler.py# Dynamic OS/CPU/RAM profiler
│   ├── llm_router.py       # Hybrid online/offline switch
│   ├── memory.py           # Vector database & RL lesson store
│   └── network_monitor.py  # Heartbeat & connectivity monitor
├── ingestion/              # Ingestion & Traffic Sniffing
│   ├── live_capture.py     # Live host connection monitor (psutil)
│   └── parsers.py          # Syslog, auth.log, JSON, CSV parsers
├── prompts/                # Role-specific system prompts
├── response/               # Reporting & remediation
│   ├── report_generator.py # Formats JSON & text reports
│   └── remediation.py      # OS command builder
├── security/               # Zero-Trust & Firewalls
│   ├── audit_chain.py      # Cryptographic SHA-256 hash chain
│   ├── identity.py         # HMAC-SHA256 agent authentication
│   ├── prompt_firewall.py  # Input/output sanitization & anti-injection
│   └── stride_evaluator.py # STRIDE safety scoring gate
├── tests/                  # Automated Pytest Suite
├── config.py               # Central settings definition
├── main.py                 # CLI entry point
└── requirements.txt        # Python dependencies
```

---

## 📜 License

MIT License. Developed for SIH26-S01 Autonomous Cybersecurity Brain.
