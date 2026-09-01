# SIH26-S01: Agentic AI Cybersecurity Assistant for Automated Threat Investigation and Incident Response
## Full Project Documentation — Research-Grounded Feature Specification

**Submitted by:** Sid (AIML Club Ambassador, APSIT Thane)  
**Problem Statement ID:** SIH26-S01  
**Edition:** Smart India Hackathon 2026  
**Date:** September 2026  
**Prior Publication Anchor:** CogniScan (IEEE Q1) — establishes credibility in multi-modal, multi-agent AI systems

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement Analysis](#2-problem-statement-analysis)
3. [Research Foundation — 50 Papers Surveyed](#3-research-foundation--50-papers-surveyed)
4. [Research Gaps Identified](#4-research-gaps-identified)
5. [System Architecture](#5-system-architecture)
6. [Complete Feature Specification — 55+ Features](#6-complete-feature-specification--55-features)
7. [Agent Roles and Responsibilities](#7-agent-roles-and-responsibilities)
8. [Technology Stack](#8-technology-stack)
9. [Deliverables Mapping](#9-deliverables-mapping)
10. [Why This Is Different](#10-why-this-is-different)

---

## 1. Executive Summary

AEGIS (Agentic Event Graph Intelligence System) is a production-grade, multi-agent cybersecurity platform built for automated threat investigation and incident response. It ingests heterogeneous security logs, normalises them across formats, detects anomalies and coordinated threat campaigns using multi-agent LLM reasoning, assigns evidence-backed risk scores, generates explainable human-readable reports, and recommends response playbooks — all without requiring constant analyst intervention.

Where every existing system reviewed in the literature either:
- achieves high detection accuracy but produces black-box, unexplainable verdicts, or
- provides explainability via SHAP/LIME but fails to chain multi-source events into a coherent attack narrative, or
- offers agentic orchestration but with no zero-trust controls over the agents themselves —

AEGIS closes all three gaps simultaneously. It is the system Sid would build: zero-trust-first, audit-logged by design, STRIDE-modelled at every agent boundary, and grounded in a RAG + Knowledge Graph backend so hallucination is structurally suppressed rather than hoped away.

---

## 2. Problem Statement Analysis

| Requirement | What It Actually Means |
|---|---|
| Ingest sample security logs | Multi-format ingestion: syslog, CEF, JSON, Windows Event, PCAP-derived |
| Normalise events | Schema mapping to OCSF/ECS, deduplication, timestamp normalisation |
| Detect anomalies/threats | Behavioural ML + LLM semantic reasoning combined |
| Correlate multiple events | Attack chain reconstruction across time and source |
| Assign risk level | Composite CVSS-style dynamic risk score with drift tracking |
| Explain the evidence | Human-readable, citation-grounded, analyst-ready prose |
| Recommend response actions | Playbook-driven SOAR suggestions, not just alerts |
| Generate incident report | Structured, downloadable, executive and technical tiers |
| At least two specialised AI agents | AEGIS has six specialised agents + one orchestrator |
| Working dashboard | Real-time, streaming, filterable SOC dashboard |

---

## 3. Research Foundation — 50 Papers Surveyed

The following papers were reviewed to identify the state-of-the-art, existing limitations, and open research gaps. Each is listed with its core contribution and the gap it exposes.

---

### Tier 1: Agentic AI Security Surveys and Frameworks

**[P01]** *AI Agents Under Threat: A Survey of Key Security Challenges and Future Pathways*  
ACM Computing Surveys, 2024. (arxiv: 2406.02630)  
**Contribution:** Taxonomises four knowledge gaps in AI agent security — unpredictability of multi-step inputs, complexity of internal executions, environmental variability, interaction with untrusted external entities.  
**Gap Exposed:** No existing system addresses all four simultaneously; most tackle one in isolation.

**[P02]** *A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes*  
ResearchGate, January 2026.  
**Contribution:** Surveys SOC automation, anomaly detection, insider-threat detection, vulnerability management via agentic AI. Documents emergent risks: collusion, oversight evasion, governance gaps.  
**Gap Exposed:** No framework prevents agent-to-agent collusion or silent oversight evasion in live SOC deployments.

**[P03]** *A Review of Agentic AI in Cybersecurity: Cognitive Autonomy, Ethical Governance, and Quantum-Resilient Defense*  
F1000Research, September 2025.  
**Contribution:** Bibliometric analysis showing 2023 as peak year; charts evolution from rule-based → ML → generative AI → agentic era.  
**Gap Exposed:** No production system maps governance compliance requirements onto agentic design patterns.

**[P04]** *A Survey on Agentic Security: Applications, Threats and Defenses*  
arxiv: 2510.06445, 2025.  
**Contribution:** Covers ProvSEEK (provenance + RAG + CoT), LLMCloudHunter (cloud CTI rule generation at 92% precision), ATT&CK cognitive bias inference.  
**Gap Exposed:** Provenance-graph reasoning and attack-chain narrative reconstruction are separate lines of work — no single system unifies them.

**[P05]** *Owner-Harm: A Missing Threat Model for AI Agent Safety*  
arxiv: 2604.18658, 2026.  
**Contribution:** Formalises eight categories of agent behaviour that harm the deploying organisation — including credential exfiltration (Slack AI, Aug 2024), data leaks (Microsoft 365 Copilot, Jan 2024), and unauthorised posts (Meta, March 2026).  
**Gap Exposed:** Existing threat models focus on external harm; owner-harm from the agent itself is unaddressed in any SOC product.

---

### Tier 2: Log Analysis and Anomaly Detection

**[P06]** *LLM-Orchestrated Multi-Agent Framework for Log-Centric Cyber Threat Detection and Analysis*  
ResearchGate, June 2026.  
**Contribution:** Highlights challenges: multi-source heterogeneous log integration, real-time requirements, semantic understanding difficulties, label scarcity.  
**Gap Exposed:** No single system solves all four simultaneously; most solve one and assume the rest.

**[P07]** *AIOps for Log Anomaly Detection in the Era of LLMs: A Systematic Literature Review*  
ScienceDirect, November 2025.  
**Contribution:** Transformer models (BERT, GPT) significantly improve anomaly detection on unstructured log data. But LLMs are too general for multi-task log analysis without domain-specific fine-tuning.  
**Gap Exposed:** Domain-specific adaptation of LLMs for security logs without sacrificing data confidentiality.

**[P08]** *LLM4Log: A Systematic Review of Large Language Model-based Log Analysis*  
arxiv: 2604.16359.  
**Contribution:** Reviews log parsing, anomaly detection, failure prediction. LEMAD uses LLM-empowered multi-agent for power-grid anomaly detection.  
**Gap Exposed:** No system transfers multi-domain LLM log reasoning to a general-purpose SOC context with real-time streaming.

**[P09]** *Benchmarking and Exploring the Capabilities of LLMs for Attack Investigations*  
arxiv: 2606.10281.  
**Contribution:** 99% of SOC alerts are false positives (USENIX Security '22). LLMs without structured reasoning and tool support cannot internalise complex incident response.  
**Gap Exposed:** Alert fatigue is measured but not structurally solved; reducing false positives requires structured agent reasoning loops, not just better classifiers.

**[P10]** *Agentic and LLM-Based Multimodal Anomaly Detection: Architectures, Challenges, and Prospects*  
Preprints.org, February 2026.  
**Contribution:** Surveys SentinelAgent, Audit-LLM, MTAD, AD-LLM benchmark. Identifies the absence of multimodal anomaly detection at SOC scale.  
**Gap Exposed:** All reviewed systems handle either time-series or text; none handle both simultaneously in a unified SOC pipeline.

**[P11]** *LogLLM: Log-based Anomaly Detection Using Large Language Models*  
arxiv: 2411.08561, 2024.  
**Contribution:** BERT for semantic extraction + Llama for sequence classification on system logs.  
**Gap Exposed:** Works offline; no streaming or real-time adaptation to log schema drift.

**[P12]** *Audit-LLM: Multi-Agent Collaboration for Log-based Insider Threat Detection*  
arxiv: 2408.08902, 2024.  
**Contribution:** Decomposes insider-threat detection into sub-problems solved by three collaborating agents.  
**Gap Exposed:** Insider threat specifically targeted; general SOC threat categories (APT, ransomware, lateral movement) not covered.

**[P13]** *Information-Dense Reasoning for Efficient and Auditable Security Alert Triage*  
arxiv: 2512.08169, 2025.  
**Contribution:** Proposes structured reasoning chains for alert triage; auditable outputs.  
**Gap Exposed:** No mechanism to chain triage results back into long-running investigation threads across multiple analyst sessions.

---

### Tier 3: Multi-Agent Collaboration for Threat Response

**[P14]** *LLM Agents Security Duality: A Comprehensive Survey of Self-Security and Empowered Cybersecurity*  
arxiv: 2606.28450, 2026.  
**Contribution:** Documents iterative reasoning loops (plan-action-check cycle, LogRESP-Agent), multi-agent correlation across data sources. IPCopilot's inference-action-reflection loop for IR.  
**Gap Exposed:** None of these frameworks apply zero-trust controls to their own internal agent communications.

**[P15]** *TraceAegis: Securing LLM-Based Agents via Hierarchical and Behavioral Anomaly Detection*  
ResearchGate, October 2025.  
**Contribution:** Hierarchical and behavioural anomaly detection targeting the agents themselves, not just the network.  
**Gap Exposed:** Securing agents from external attack is addressed; securing agent-to-agent message channels with hash-chain audit trails is not.

**[P16]** *SentinelAgent: Graph-based Anomaly Detection in Multi-Agent Systems*  
arxiv: 2505.24201, 2025.  
**Contribution:** Graph-based detection of anomalous behaviour in multi-agent coordination.  
**Gap Exposed:** Detection at the agent graph level is new; integration with SOC SIEM pipelines is untested.

**[P17]** *IPCopilot: Multi-Agent Framework for Incident Response*  
Lin et al., 2025 (cited in P14).  
**Contribution:** Four agents in inference-action-reflection loop; incident response tree decomposes large targets into sub-tasks.  
**Gap Exposed:** No downloadable, structured incident report generation; output is analyst-readable chat, not a formal document.

**[P18]** *AutoBnB-RAG: Incident Response Simulation with RAG-Enhanced Decision Making*  
Liu & Anwar, 2025 (cited in P14).  
**Contribution:** Game-based IR simulation augmented with RAG to overcome agent knowledge gaps.  
**Gap Exposed:** Simulation environment only; not deployable in live production SOC.

---

### Tier 4: Explainability and Transparency

**[P19]** *An LLM-Based Agentic Network Traffic Incident-Report Approach Towards Explainable-AI Network Defense*  
JSAN, April 2026. (doi: 10.3390/jsan15020032)  
**Contribution:** Ensemble ML (>99.8% accuracy on 11 attack classes) + RAG-grounded LLM incident reports. Groundedness score: 1.0. Bridges gap between detection and actionable narrative.  
**Gap Exposed:** RAG focuses on threat intel retrieval only; does not integrate live log provenance as a grounding source.

**[P20]** *Towards Transparent Cyber Threat Detection: XAI in Information Security Risk Management (2018–2025)*  
ResearchGate, 2025.  
**Contribution:** Systematic literature review showing SHAP and LIME generate feature attributions but not analyst-actionable explanations.  
**Gap Exposed:** XAI outputs require expert interpretation; no system auto-translates them to natural language incident narratives.

**[P21]** *Retrieval-Augmented LLMs for Security Incident Analysis*  
arxiv: 2603.18196, May 2026.  
**Contribution:** RAG-powered LLM for reconstructing attack narratives from dispersed log artifacts (Suricata, Zeek, Windows Auth).  
**Gap Exposed:** Multi-source narrative reconstruction tested only on DARPA datasets; no live streaming pipeline.

---

### Tier 5: Zero Trust and Agent Governance

**[P22]** *The Agentic Trust Framework: Zero Trust Governance for AI Agents*  
Cloud Security Alliance, February 2026.  
**Contribution:** Defines Zero Trust governance for AI agents: continuous monitoring, anomaly detection, schema validation, PII detection, output filtering. Aligns with OWASP Agentic Top 10 (December 2025).  
**Gap Exposed:** Framework is architectural guidance; no reference implementation exists for SOC-specific deployment.

**[P23]** *Design Principles for LLM-based Systems with Zero Trust*  
BSI/ANSSI Joint Release, 2025.  
**Contribution:** Applies traditional Zero Trust pillars (identity, device, network, data, application) to LLM system design.  
**Gap Exposed:** Indirect prompt injection at the application layer is identified as high risk but no runtime defence is specified.

**[P24]** *Zero-Trust Secure System and Communication Architecture to Support LLMs on the Edge Cloud Continuum*  
Springer, 2026.  
**Contribution:** Fault-injection attack mitigation for LLMs using shallow deep neural networks with multiple exits.  
**Gap Exposed:** Focused on edge; cloud-native, SOC-hosted LLM systems lack equivalent fault injection resilience.

**[P25]** *Investigation of Cybersecurity Bottlenecks of AI Agents in Industrial Automation*  
MDPI Computers, October 2025.  
**Contribution:** Simulated DDoS, False Data Injection, Replay, and Adversarial Attacks on CrewAI and LangFlow frameworks. GAN-based anomaly detection proposed.  
**Gap Exposed:** Industrial automation setting; no equivalent adversarial hardening evaluation for SOC-deployed multi-agent systems.

---

### Tier 6: Threat Intelligence and Knowledge Graphs

**[P26]** *CTI-Thinker: An LLM-driven System for CTI Knowledge Graph Construction and Attack Reasoning*  
Springer Cybersecurity, January 2026.  
**Contribution:** LLM for CTI KG construction with RAG for factual consistency. Identifies polysemy and ambiguity issues in threat semantics.  
**Gap Exposed:** Shallow semantic understanding limits reasoning about novel attack chains not in training data.

**[P27]** *Beyond RAG for Cyber Threat Intelligence: A Systematic Evaluation of Graph-Based and Agentic Retrieval*  
arxiv: 2604.11419, April 2026.  
**Contribution:** Compares standard RAG, graph-based RAG (GRAG), agentic GRAG (AGRAG), and hybrid across 3,300 CTI QA pairs. Graph grounding improves structured factual queries.  
**Gap Exposed:** Hybrid architecture outperforms single paradigm — no production system deploys all three modes adaptively.

**[P28]** *TACTIC-KG: Agentic Framework for CSKG Construction Using Modular LLM Agents*  
arxiv: 2607.05001, July 2026.  
**Contribution:** Modular agents (3B-8B) for extraction, typing, verification, curation of cybersecurity knowledge graphs — cheaper and more controllable than monolithic LLMs.  
**Gap Exposed:** KG construction pipeline is offline; no continuous ingestion of live threat intelligence feeds.

**[P29]** *AgCyRAG: Agentic Knowledge Graph Based RAG for Cybersecurity*  
CEUR Workshop, 2025.  
**Contribution:** Integrates knowledge graph with RAG for multi-hop reasoning over attack patterns.  
**Gap Exposed:** Current RAG approaches process disconnected text chunks; security analytics requires reasoning over event sequences, topologies, and hierarchical asset models together.

**[P30]** *CTINexus: Automatic Cyber Threat Intelligence Knowledge Graph Construction Using LLMs*  
arxiv: 2410.21060.  
**Contribution:** Automated CTI KG construction with entity alignment and relationship extraction.  
**Gap Exposed:** No feedback loop from live detection events back into the KG to keep it current.

**[P31]** *CRAKEN: Cybersecurity LLM Agent with Knowledge-Based Execution*  
arxiv: 2505.17107.  
**Contribution:** Knowledge base integrated directly into agent execution loop.  
**Gap Exposed:** Execution-phase knowledge access only; no pre-execution risk assessment using historical KG data.

**[P32]** *RAGRank: Using PageRank to Counter Poisoning in CTI LLM Pipelines*  
arxiv: 2510.20768.  
**Contribution:** PageRank-based trust scoring to detect and rank poisoned CTI documents in RAG pipelines.  
**Gap Exposed:** RAG poisoning is a live threat (False Alarms, Real Damage paper); no deployed SOC system implements adversarial RAG hardening.

---

### Tier 7: MITRE ATT&CK Automation and SOC Hunting

**[P33]** *Policy-Guided Threat Hunting: An LLM-Enabled Framework with Splunk SOC Triage*  
arxiv: 2603.23966, March 2026.  
**Contribution:** CrewAI-based three-agent system — SOC Triage Analyst + Threat Intelligence Analyst + Orchestrator — maps behaviour to MITRE ATT&CK and generates SPL queries.  
**Gap Exposed:** Uses public LLM APIs for sensitive log analysis; no local LLM deployment option with equivalent capability.

**[P34]** *From MITRE ATT&CK to Agentic Threat Investigation*  
Medium (Dr. Inoussa Mouiche, WASP Lab), February 2026.  
**Contribution:** Automated MITRE mapping in 4 seconds vs. 2+ hours manually; ATT&CK Navigator gap layer generation; detection hypothesis auto-generation with telemetry requirements.  
**Gap Exposed:** No integration of MITRE mapping with downstream playbook recommendation or SOAR execution.

**[P35]** *MITRE ATT&CK Driven Threat Hunting Automated by Local LLM*  
Fujitsu Defense & National Security, MITRE APAC 2025.  
**Contribution:** Local LLM deployment for ATT&CK-driven threat hunting; privacy-preserving.  
**Gap Exposed:** Local LLM loses threat intelligence breadth vs. cloud; no hybrid architecture balancing privacy and coverage.

**[P36]** *The Procedural Semantics Gap in Structured CTI: A Measurement-Driven STIX Analysis for APT Emulation*  
arxiv: 2512.12078.  
**Contribution:** STIX-based CTI lacks procedural semantics for APT emulation; attack graphs lose fidelity.  
**Gap Exposed:** STIX + ATT&CK are used together but their semantic alignment at procedure level is broken; automated emulation fails on novel APT TTPs.

**[P37]** *Teams of LLM Agents Can Exploit Zero-Day Vulnerabilities*  
arxiv: 2406.01637.  
**Contribution:** Demonstrates that multi-LLM-agent teams can autonomously discover and exploit previously unknown vulnerabilities.  
**Gap Exposed:** Offensive capability exists; defensive equivalent — agentic zero-day anticipation — does not.

---

### Tier 8: Incident Response and Report Generation

**[P38]** *Advancing Autonomous Incident Response: Leveraging LLMs and Cyber Threat Intelligence*  
arxiv: 2508.10677, August 2025.  
**Contribution:** LLM + CTI integration for autonomous IR decision-making.  
**Gap Exposed:** No structured output format standard; each paper defines its own report schema.

**[P39]** *Towards Transparent Cyber Threat Detection: Systematic Literature Review on XAI in ISRM (2018–2025)*  
ResearchGate.  
**Contribution:** Maps 7 years of XAI application to cybersecurity; shows persistent gap between explanation quality and analyst utility.  
**Gap Exposed:** Explanations are generated but not validated for analyst utility via formal usability studies.

**[P40]** *Position: Mind the Gap — AI Security and the Limits of Current Reporting Standards*  
arxiv: 2412.14855.  
**Contribution:** Identifies absence of standardised AI security reporting; cost of global cybercrime reaching $1.2–1.5 trillion by end of 2025.  
**Gap Exposed:** No common schema for AI-generated security incident reports that regulatory and compliance frameworks can consume.

---

### Tier 9: Alert Fatigue and False Positive Reduction

**[P41]** *99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms*  
USENIX Security, 2022. (Alahmadi, Axon, Martinovic)  
**Contribution:** 99% of security alarms are false positives from analyst perspective; alert fatigue is the dominant SOC productivity killer.  
**Gap Exposed:** No system architecturally suppresses false positives at ingestion; all systems alert first and filter later.

**[P42]** *Threat Hunting Metrics & KPIs: What to Measure in 2026*  
Dropzone AI, June 2026.  
**Contribution:** 40% of security alerts never investigated; 46% are false positives. Enterprise SIEMs cover only 21% of ATT&CK techniques despite having telemetry for 90%.  
**Gap Exposed:** Coverage gap between available telemetry and deployed detection rules is structural, not a capability problem.

---

### Tier 10: Prompt Injection, Adversarial, and Supply Chain Threats

**[P43]** *Defending Against Indirect Prompt Injection Attacks with Spotlighting*  
CAMLIS 2024. (Hines et al.)  
**Contribution:** Spotlighting technique for isolating untrusted external content from trusted instructions.  
**Gap Exposed:** Spotlighting reduces but does not eliminate prompt injection; adversarial inputs crafted specifically to evade spotlighting remain effective.

**[P44]** *False Alarms, Real Damage: Adversarial Attacks Using LLM-based Models on Text-based CTI Systems*  
arxiv: 2507.06252, July 2025.  
**Contribution:** Adversarial CTI documents can manipulate RAG-based threat intelligence systems; demonstrates real operational damage.  
**Gap Exposed:** No production CTI RAG pipeline implements adversarial input detection before knowledge base ingestion.

**[P45]** *The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents*  
arxiv: 2412.16682, 2024.  
**Contribution:** Task alignment enforcement at agent decision boundaries.  
**Gap Exposed:** Task Shield works per-agent; multi-agent systems need cross-agent task alignment verification.

**[P46]** *MAD-CTI: Cyber Threat Intelligence Analysis of the Dark Web Using a Multi-Agent Framework*  
IEEE Access, 2025.  
**Contribution:** Multi-agent framework for dark web CTI extraction and analysis.  
**Gap Exposed:** Dark web CTI is noisy, adversarially manipulated, and lacks provenance — ingesting it without trust scoring poisons downstream analysis.

---

### Tier 11: Specific Detection Capabilities

**[P47]** *LLM Agents Can Autonomously Exploit One-Day Vulnerabilities*  
arxiv: 2404.08144, 2024. (Fang et al.)  
**Contribution:** Autonomous exploitation of known CVEs by LLM agents.  
**Gap Exposed:** Defensive systems must anticipate LLM-assisted attackers — current detection systems are not tuned for LLM-generated attack signatures.

**[P48]** *When LLMs Go Online: The Emerging Threat of Web-Enabled LLMs*  
USENIX Security, 2025.  
**Contribution:** Web-enabled LLM agents introduce novel exfiltration paths.  
**Gap Exposed:** SOC detection rules are not updated to catch LLM-mediated lateral movement and exfiltration.

**[P49]** *Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents*  
arxiv, 2025.  
**Contribution:** Prompt flow integrity mechanism to prevent agents from escalating their own privileges.  
**Gap Exposed:** Privilege escalation via prompt manipulation is a new attack class with no existing detection rule category in SIEM products.

**[P50]** *ConfusedPilot: Confused Deputy Risks in RAG-based LLMs*  
arxiv: 2408.04870, 2024.  
**Contribution:** Confused deputy attack — RAG LLM acts on behalf of an attacker by retrieving and executing instructions embedded in documents.  
**Gap Exposed:** Any RAG-based security tool that ingests external documents is vulnerable to confused deputy; no existing SOC tool detects this class of attack.

---

## 4. Research Gaps Identified

The following 12 major research gaps emerge from synthesising the 50 papers:

| Gap ID | Gap Description | Papers Exposing It |
|---|---|---|
| **RG-01** | No system applies zero-trust controls to agent-to-agent communications within the SOC multi-agent stack itself | P01, P02, P22, P23 |
| **RG-02** | Explainability tools (SHAP, LIME) generate feature scores, not analyst-ready narrative explanations | P19, P20, P39 |
| **RG-03** | Alert fatigue is measured but not architecturally solved; false positive suppression happens post-alert, not pre-alert | P41, P42, P09 |
| **RG-04** | RAG pipelines for CTI have no adversarial input detection; poisoned documents corrupt the knowledge base silently | P32, P44, P50 |
| **RG-05** | MITRE ATT&CK mapping is automated but not connected to downstream playbook recommendation or SOAR execution | P33, P34 |
| **RG-06** | Attack narrative reconstruction requires multi-source log correlation but no production system streams this in real time | P21, P06, P08 |
| **RG-07** | Owner-harm from deployed agents themselves is unaddressed; agent credential exfiltration, data leaks have no SOC detection rule | P05, P47, P48 |
| **RG-08** | No standardised incident report schema exists that compliance and regulatory frameworks can consume directly | P38, P40 |
| **RG-09** | KG-based threat intelligence is offline; no live feedback loop from detection events back into the knowledge graph | P26, P28, P30 |
| **RG-10** | LLM hallucination in incident reports is mitigated by RAG but not structurally suppressed by provenance-locked grounding | P19, P21, P29 |
| **RG-11** | Multi-agent systems detect threats but do not model the attacker's cognitive state or strategic intent | P30, P36 |
| **RG-12** | Prompt injection and confused deputy attacks are identified but no production SOC tool detects or logs them as events | P43, P45, P49, P50 |

---

## 5. System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        AEGIS PLATFORM                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              INGESTION LAYER (F01–F09)               │    │
│  │  Syslog · CEF · JSON · EVTX · PCAP · Cloud · API   │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────┐    │
│  │         NORMALISATION ENGINE (F10–F18)               │    │
│  │   OCSF/ECS Schema · Dedup · Timestamp · Enrichment  │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                    │
│       ┌──────────────────┼──────────────────┐               │
│       │                  │                  │               │
│  ┌────▼────┐       ┌─────▼─────┐     ┌─────▼─────┐        │
│  │ LOG     │       │  THREAT   │     │  INTEL    │        │
│  │ ANALYSIS│       │  DETECT   │     │  AGENT    │        │
│  │ AGENT   │       │  AGENT    │     │  (CTI+KG) │        │
│  │(F19–F26)│       │(F27–F36)  │     │(F37–F43)  │        │
│  └────┬────┘       └─────┬─────┘     └─────┬─────┘        │
│       └──────────────────┼──────────────────┘               │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────┐    │
│  │       ORCHESTRATOR AGENT — EDITH-SEC (F44–F47)      │    │
│  │   Zero-Trust Gate · STRIDE Eval · Hash-Chain Log    │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                    │
│       ┌──────────────────┼──────────────────┐               │
│       │                  │                  │               │
│  ┌────▼────┐       ┌─────▼─────┐     ┌─────▼─────┐        │
│  │ REPORT  │       │ RESPONSE  │     │  EXPLAIN  │        │
│  │ AGENT   │       │ AGENT     │     │  AGENT    │        │
│  │(F48–F52)│       │(F53–F56)  │     │(F57–F60)  │        │
│  └────┬────┘       └─────┬─────┘     └─────┬─────┘        │
│       └──────────────────┼──────────────────┘               │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────┐    │
│  │          SOC DASHBOARD — REAL TIME (F61–F65)         │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Complete Feature Specification — 55+ Features

> Features are grouped by functional area. Each feature references the research gap it closes.

---

### AREA A: Ingestion and Collection (F01–F09)

**F01 — Universal Log Ingestion Gateway**  
Accepts syslog (RFC 5424/3164), Windows Event XML, CEF, LEEF, JSON, AWS CloudTrail, Azure Monitor, GCP Audit Logs, and raw PCAP-derived JSON. A plugin architecture allows new format adapters to be added without touching core code.  
*Closes: RG-06. Directly required by deliverable: sample-log pipeline.*

**F02 — Streaming Ingestion with Backpressure Control**  
Kafka-based ingestion pipeline with configurable backpressure so high-volume log bursts (e.g., during a DDoS) do not drop events. Exactly-once delivery semantics via idempotent producers.  
*Closes: RG-03 (events are not lost before analysis).*

**F03 — Agent Activity Log Channel**  
Dedicated ingestion channel for AEGIS's own agent communications. Every inter-agent message, tool call, and decision is itself treated as a security log event and fed into the same analysis pipeline.  
*Closes: RG-01, RG-07. This is how we detect owner-harm from our own agents — a feature no paper reviewed has implemented.*

**F04 — Cloud-Native Connector Library**  
Pre-built connectors for AWS (GuardDuty, CloudTrail, VPC Flow), Azure Sentinel, GCP Security Command Center, and on-prem SIEM APIs (Splunk, IBM QRadar). Token-exchange authentication, never long-lived credentials stored in config.  
*Closes: RG-06.*

**F05 — PCAP Deep Inspection Adapter**  
Accepts PCAP files, extracts protocol-level events (DNS queries, HTTP requests, TLS handshakes, SMB operations) and emits them as normalised JSON log events. Identifies beaconing patterns and anomalous JA3 fingerprints before handing off to the detection pipeline.  
*Closes: RG-11 (protocol-level attacker behaviour).*

**F06 — Live Threat Feed Ingestion**  
Ingests STIX/TAXII-compatible threat intelligence feeds (CISA KEV, FS-ISAC, AlienVault OTX, Shodan), dark web CTI alerts (via MAD-CTI-style pipeline, P46), and CVE NVD feeds. All external CTI documents pass through the Adversarial RAG Hardening module (see F38) before entering the knowledge base.  
*Closes: RG-04, RG-09.*

**F07 — Endpoint Agent Collector**  
Lightweight osquery-based endpoint agents deployed on monitored hosts. Sends process creation, network connection, file modification, and registry change events as structured logs. Supports Windows, Linux, macOS.  
*Closes: RG-06.*

**F08 — Schema-on-Read Dynamic Parser**  
For unknown log formats, uses an LLM-powered parser to infer schema from a sample of 10–20 log lines, generate a parsing rule, and normalise subsequent logs. The generated rule is validated against a test set before activation.  
*Closes: RG-06, RG-03 (novel log sources are not silently dropped).*

**F09 — Ingestion Integrity Verification**  
Every ingested log batch is hash-stamped (SHA-256 of batch content + ingestion timestamp + source identifier). This hash is stored in the audit chain. Any tampering with historical logs invalidates the audit chain — detected automatically on next read.  
*Closes: RG-01. Directly supports hash-chained audit logging architecture from Sid's prior EDITH system.*

---

### AREA B: Normalisation and Enrichment (F10–F18)

**F10 — OCSF/ECS Schema Mapping Engine**  
Maps all ingested events to the Open Cybersecurity Schema Framework (OCSF) and Elastic Common Schema (ECS). Provides a unified event model that any downstream agent can query without format-specific logic.  
*Closes: RG-06.*

**F11 — Timestamp Normalisation and Clock Skew Correction**  
Converts all timestamps to UTC, detects and corrects clock skew across log sources (common in distributed systems), and flags events where clock skew exceeds a configurable threshold (default: 5 seconds) as potentially tampered.  
*Closes: RG-06.*

**F12 — Entity Extraction and Asset Enrichment**  
Extracts entities (IP addresses, hostnames, usernames, process names, file hashes, URLs, CVE IDs) from log events and enriches them with context from the Asset Inventory (internal) and Threat Intelligence Knowledge Graph (TI-KG). A hostname tagged as "Domain Controller" gets elevated criticality automatically.  
*Closes: RG-06, RG-09.*

**F13 — Deduplication Engine**  
Log deduplication using MinHash LSH to identify near-duplicate events (e.g., repeated failed login from same source within 1 second) and collapse them into a single annotated event with a frequency count. This is the first line of false-positive reduction.  
*Closes: RG-03.*

**F14 — Sensitivity Classification and PII Redaction**  
Classifies log fields for sensitivity level (PII, PHI, credentials, API keys). Redacts sensitive values before they enter storage or analysis. Analyst dashboard shows redacted tokens with role-based reveal capability.  
*Closes: RG-01 (agents cannot leak PII via their own analysis output).*

**F15 — Log Volume and Velocity Baseline Tracker**  
Maintains a rolling baseline of log volume, velocity, and source distribution per asset, per service, per time-of-day bucket. Statistical deviations from baseline (z-score > 3σ) are flagged as pre-anomaly signals even before log content is analysed.  
*Closes: RG-03. This is a pre-alert filter that reduces downstream false positives architecturally.*

**F16 — Geolocation and ASN Enrichment**  
Augments IP-based events with GeoIP city/country, ASN, and hosting provider data. Cross-references against baseline of expected geolocations per user account and service. Logins from new countries or Tor exit nodes are automatically escalated.  
*Closes: RG-06.*

**F17 — Vulnerability Context Injection**  
For events involving CVE IDs or software version strings, automatically injects CVSS score, EPSS probability, CISA KEV status, and known exploit availability from the TI-KG. An event about Apache 2.4.49 is immediately tagged with CVE-2021-41773 context without analyst intervention.  
*Closes: RG-05, RG-09.*

**F18 — Log Schema Drift Detector**  
Monitors for changes in log schema over time (new fields appearing, existing fields changing type, fields disappearing). Schema drift is an indicator of either system change (benign) or log tampering/spoofing (malicious). Alerts on unexpected drift with a confidence score.  
*Closes: RG-01, RG-07.*

---

### AREA C: Log Analysis Agent (F19–F26)

**F19 — Multi-Modal Sequence Anomaly Detection**  
Combines BERT-based semantic anomaly detection on log text with LSTM/Transformer-based temporal anomaly detection on event sequences. Anomalies in either dimension or their conjunction are scored independently and combined into a unified anomaly score. Addresses the gap (P10) where no single system handles both dimensions.  
*Closes: RG-06.*

**F20 — Behavioural Baseline Learning per Entity**  
Learns entity-level behavioural baselines for users, service accounts, hosts, and network segments using unsupervised clustering (DBSCAN + time-series decomposition). Deviations from established baseline — not just from global rules — are the primary detection signal.  
*Closes: RG-03 (reduces false positives by personalising detection thresholds).*

**F21 — Log Template Extraction and Novelty Detection**  
Parses logs into templates + variable components using Drain3 + LLM hybrid parser. New templates that do not match any known pattern are flagged as high-interest events. This catches zero-day attacks that produce novel log patterns not seen in training data.  
*Closes: RG-06.*

**F22 — Insider Threat Scoring (Audit-LLM Architecture)**  
Implements a three-sub-agent architecture inspired by Audit-LLM (P12): one agent analyses access patterns, one analyses data movement, one analyses communication patterns. Their outputs are correlated to produce an insider threat confidence score with supporting evidence citations.  
*Closes: RG-06.*

**F23 — Lateral Movement Chain Detector**  
Tracks authentication events, process spawning, and network connections across multiple hosts to reconstruct lateral movement chains. Uses a directed graph where nodes are assets and edges are observed connections. Paths that match known lateral movement patterns (Pass-the-Hash, WMI pivoting, SMB relay) are highlighted.  
*Closes: RG-06, RG-05.*

**F24 — Ransomware Behaviour Signature Engine**  
Detects pre-encryption staging behaviours: mass file enumeration, shadow copy deletion, backup system access, unusual encryption API calls, and credential dumping sequences. Raises a critical alert within 30 seconds of behavioural signature match — before encryption begins.  
*Closes: RG-06.*

**F25 — LLM-Assisted Log Cluster Narrative**  
For each anomaly cluster identified, the Log Analysis Agent generates a 2–3 sentence natural language narrative describing what the cluster represents, what assets are involved, and why it is anomalous. This replaces raw log dumps in analyst workflows.  
*Closes: RG-02.*

**F26 — Confidence-Calibrated Output with Uncertainty Quantification**  
Every detection output includes a confidence score and an uncertainty estimate. Detections below configurable confidence thresholds are queued for human review rather than auto-escalated. This is the second layer of false positive suppression.  
*Closes: RG-03.*

---

### AREA D: Threat Detection and Investigation Agent (F27–F36)

**F27 — MITRE ATT&CK Automated Technique Mapping**  
Maps detected behaviours to MITRE ATT&CK techniques, tactics, and procedures (TTPs) in real time. Mapping is done in under 10 seconds using a fine-tuned classification head over a domain-adapted LLM, replacing the 2+ hours of manual analyst effort (per P34). ATT&CK Navigator layer is auto-generated showing current coverage and gaps.  
*Closes: RG-05.*

**F28 — Multi-Stage Attack Chain Reconstruction**  
Correlates events across time, asset, and log source to reconstruct complete kill-chain sequences (Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defence Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration → Impact). Incomplete chains are tracked as "in-progress" investigations with confidence decay over time.  
*Closes: RG-06, RG-10.*

**F29 — Risk Score Composer with Evidence Weighting**  
Produces a composite risk score (0–100) for each detected incident using a weighted formula incorporating: base CVSS of exploited vulnerability, asset criticality, attack chain completeness, lateral spread factor, data sensitivity of accessed assets, and attacker dwell time. Every score component is individually explainable.  
*Closes: RG-02.*

**F30 — Attacker Intent Modelling**  
Using the ATT&CK technique sequence observed, models the attacker's probable strategic intent (financial/ransomware, espionage/APT, destructive, insider/data theft) using a Bayesian inference model seeded with historical APT campaign profiles from the TI-KG. This feature closes gap RG-11 from P30 and P36.  
*Closes: RG-11.*

**F31 — Campaign Correlation Engine**  
Groups individual incidents that share TTPs, infrastructure (IP/domain/certificate overlaps), timing patterns, and tool signatures into campaign clusters. Enables detection of distributed, slow-burn APT campaigns that appear as isolated low-severity events individually.  
*Closes: RG-06.*

**F32 — Zero-Day TTP Anticipation Module**  
Based on recent ATT&CK additions, CISA KEV entries, and observed attacker pivot patterns in the TI-KG, generates hunt hypotheses for TTPs not yet observed in the organisation's environment but statistically likely given current threat landscape. Output is a set of proactive hunt queries in Sigma/SPL/KQL format.  
*Closes: RG-05, RG-11.*

**F33 — Prompt Injection and Confused Deputy Detector**  
A specialised sub-agent that monitors all content entering the AEGIS pipeline from external sources (log events containing URLs, document attachments referenced in email logs, CTI feed content) for embedded instruction patterns. Implements spotlighting (P43) and Task Shield (P45) defences. Any detected prompt injection attempt is itself logged as a security incident.  
*Closes: RG-12.*

**F34 — LLM-Generated Attack Signature Detector**  
Detects attack signatures characteristic of LLM-assisted attackers: unusual phrasing in social engineering events, code that combines exploit components in novel syntax not matching known tool signatures, and network traffic patterns consistent with LLM reasoning latency (P47, P48). This is a new detection category that no existing SIEM product covers.  
*Closes: RG-07.*

**F35 — Cross-Source Event Correlation with Provenance Tracking**  
For every correlated event set, maintains a provenance graph tracing each evidence item back to its source log line, ingestion batch hash, and original log file. This enables full audit of why a detection was made. Closes the RAG grounding gap (RG-10) by ensuring all narrative claims are anchored to specific log evidence.  
*Closes: RG-10.*

**F36 — Adaptive Detection Threshold Tuning**  
Uses online learning to adjust detection thresholds per asset and per detection rule based on analyst feedback (true positive / false positive labelling from the dashboard). Thresholds drift toward lower false positive rates without reducing true positive coverage.  
*Closes: RG-03.*

---

### AREA E: Threat Intelligence Agent (F37–F43)

**F37 — Cybersecurity Knowledge Graph (TI-KG) with Live Update**  
Maintains a neo4j-backed knowledge graph containing: CVEs, APT groups, malware families, TTPs, IOCs (IPs, domains, hashes, certificates), affected products, and remediation references. The graph is updated continuously from live threat feeds (F06) and from new incidents detected by AEGIS itself. This closes RG-09 — no reviewed system feeds live detections back into its own knowledge graph.  
*Closes: RG-09.*

**F38 — Adversarial RAG Hardening (PageRank Trust Scoring)**  
Before any external CTI document is ingested into the TI-KG or RAG corpus, it passes through a trust scoring pipeline implementing RAGRank (P32): PageRank-derived trust score based on the document's citation network, source reputation, and semantic consistency with established knowledge. Documents below a trust threshold are quarantined for human review.  
*Closes: RG-04.*

**F39 — Hybrid Retrieval Architecture (AGRAG)**  
Implements the AGRAG architecture from P27: primary graph-based retrieval for structured factual queries (CVE details, APT group TTPs, affected versions), secondary semantic RAG for natural language queries (analyst questions), and agentic repair loops that rephrase failed graph queries and retry. All claims in LLM outputs are citation-locked to specific KG nodes or RAG chunks.  
*Closes: RG-10.*

**F40 — Dark Web CTI Monitor**  
Monitors dark web forums (Tor-accessible) for mentions of the organisation's assets, credential dumps, and advance notice of planned attacks. Implements a multi-agent CTI extraction pipeline (MAD-CTI-inspired, P46) with trust scoring and adversarial content detection. All dark web CTI is treated as untrusted by default.  
*Closes: RG-04, RG-09.*

**F41 — CVE Exploit Probability Tracker (EPSS Integration)**  
Integrates FIRST EPSS scores, CISA KEV catalog, and ExploitDB entries to maintain a real-time exploitability score for every CVE referenced in the TI-KG. Assets running software with high EPSS + KEV-listed CVEs are automatically prioritised in the risk queue.  
*Closes: RG-05.*

**F42 — STIX/TAXII CTI Feed Normaliser**  
Translates incoming STIX 2.1 bundles into TI-KG schema, resolving entity alignment conflicts using a disambiguation agent (inspired by TACTIC-KG's modular agents, P28). Maintains versioning of CTI objects so historical threat intelligence remains accessible.  
*Closes: RG-09.*

**F43 — Threat Actor Profiling and Attribution Engine**  
Builds and maintains profiles of threat actors based on observed TTPs, infrastructure overlaps, timing patterns, and campaign objectives. Attribution confidence is expressed as a probability distribution across known threat actor groups, not a single label. Profiles are updated as new evidence is collected.  
*Closes: RG-11.*

---

### AREA F: Orchestrator Agent — EDITH-SEC (F44–F47)

**F44 — Zero-Trust Agent Communication Gateway**  
Every inter-agent message passes through a cryptographic validation gateway. Each agent has an asymmetric keypair; outgoing messages are signed, incoming messages are signature-verified before being processed. An agent whose signing key is compromised cannot silently inject malicious instructions into the pipeline.  
*Closes: RG-01. This is EDITH-paper's zero-trust architecture applied to SOC multi-agent systems — directly leveraging Sid's existing research.*

**F45 — STRIDE Threat Model Evaluator**  
Before each agent task execution, the Orchestrator applies a lightweight STRIDE evaluation (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to the proposed action. Actions with unacceptably high STRIDE scores are escalated to a human operator rather than auto-executed.  
*Closes: RG-01. Directly from Sid's EDITH system.*

**F46 — Hash-Chained Audit Log**  
Every agent action, tool call, decision, and inter-agent message is recorded in a hash-chained append-only audit log. Each log entry includes: timestamp, agent ID, action type, input hash, output hash, and the hash of the previous entry. Tampering with any entry breaks the chain and is detected on next integrity check.  
*Closes: RG-01, RG-08 (audit log is the evidentiary foundation of the incident report).*

**F47 — Dynamic Agent Orchestration with Priority Scheduling**  
The Orchestrator dynamically assigns tasks to available agents based on current load, task urgency (critical incidents skip queues), and agent specialisation match. If an agent fails or times out, the Orchestrator reassigns the task and logs the failure as an anomaly.  
*Closes: RG-01.*

---

### AREA G: Report Generation Agent (F48–F52)

**F48 — Dual-Tier Incident Report Generator**  
Generates two versions of each incident report automatically:
- **Executive Report:** 1–2 page non-technical summary, business impact, risk level, and recommended board-level decision. Formatted for CISO/executive consumption.
- **Technical Report:** Full forensic detail — event timeline, affected assets, attack chain, evidence citations locked to specific log lines, MITRE ATT&CK mapping, IOC list, and recommended remediation steps.  
*Closes: RG-08.*

**F49 — Citation-Locked Report Grounding**  
Every factual claim in the generated report is anchored to a specific log entry (with ingestion hash), a specific TI-KG node, or a specific RAG chunk. No claim can appear in the report without a traceable evidence source. This structurally suppresses hallucination in report content.  
*Closes: RG-10.*

**F50 — Downloadable Multi-Format Report Export**  
Reports are exportable as: PDF (structured, court-admissible formatting), DOCX (editable for analyst annotation), JSON (machine-readable for SOAR/SIEM import), and STIX 2.1 bundle (for sharing with external partners/CERTs). Directly satisfies the deliverable requirement for downloadable incident report.  
*Closes: RG-08.*

**F51 — Compliance-Aligned Report Templating**  
Report templates align with specific compliance frameworks: NIST CSF 2.0, ISO 27001, DPDP Act (India), GDPR, and PCI-DSS. Selecting a template auto-populates framework-specific fields and control mappings from the detected incident.  
*Closes: RG-08.*

**F52 — Continuous Incident Update and Versioning**  
For ongoing incidents, the report is versioned automatically as new evidence is collected. Each version is timestamped and signed. Analysts can see how the investigation evolved, and the audit chain links each report version to the corresponding agent actions that produced it.  
*Closes: RG-08.*

---

### AREA H: Response Recommendation Agent (F53–F56)

**F53 — Playbook-Driven Response Recommendation Engine**  
Maps each incident classification to a response playbook from a curated library covering: ransomware containment, account compromise response, lateral movement quarantine, DDoS mitigation, insider threat escalation, and supply chain incident handling. Recommends the top-3 most applicable playbook actions with priority ordering.  
*Closes: RG-05.*

**F54 — SOAR Integration Layer**  
Generates SOAR-executable action bundles for Splunk SOAR, Palo Alto XSOAR, and Microsoft Sentinel SOAR. Bundles include: firewall rule addition requests, account suspension actions, endpoint isolation commands, and evidence preservation snapshots. All SOAR actions require analyst confirmation before execution (human-in-the-loop by default).  
*Closes: RG-05.*

**F55 — Automated IOC Dissemination**  
On incident confirmation, automatically formats IOCs (malicious IPs, domains, hashes, certificates) into STIX 2.1 indicators and pushes them to TAXII servers for sharing with ISACs and partner organisations. Respects TLP (Traffic Light Protocol) marking from the source intelligence.  
*Closes: RG-09.*

**F56 — Response Action Risk Scorer**  
Before recommending a response action (e.g., blocking an IP, isolating a host), scores the potential operational impact of that action using an asset dependency graph. Blocking an IP that is also the primary DNS resolver would cause widespread outage — this is flagged prominently before the recommendation is presented.  
*Closes: RG-05.*

---

### AREA I: Explainability Agent (F57–F60)

**F57 — Natural Language Evidence Translator**  
Translates raw feature attribution scores (SHAP values, attention weights) from the detection models into analyst-readable English sentences. "This authentication event is anomalous because it occurred at 03:17 UTC (6.2σ from this account's typical login time) from an IP in a country this user has never accessed from before." Every explanation is specific, not generic.  
*Closes: RG-02.*

**F58 — Interactive Evidence Explorer**  
Dashboard widget allowing analysts to drill into any detection and see: the exact log lines that triggered it, the MITRE technique they match, the SHAP contribution of each feature, and the chain of agent decisions that led to the alert. Bidirectional navigation — from alert back to raw log and from raw log forward to attack chain.  
*Closes: RG-02.*

**F59 — Counterfactual Explanation Generator**  
For any detection, generates a counterfactual: "This alert would NOT have been raised if [specific condition]. To avoid triggering this detection, the attacker would need to [specific alternative behaviour]." This helps analysts understand detection logic and identify potential evasion blind spots.  
*Closes: RG-02.*

**F60 — Analyst Feedback and Explanation Quality Loop**  
Analysts can rate the quality of each explanation (1–5 stars) and provide freetext feedback. Explanation quality scores are used to fine-tune the explanation generation prompts over time. Explanation quality is tracked as a KPI alongside detection metrics.  
*Closes: RG-02.*

---

### AREA J: SOC Dashboard (F61–F65)

**F61 — Real-Time Streaming SOC Dashboard**  
Live dashboard with WebSocket-based real-time updates. Displays: current incident queue by severity, live event velocity graph, entity risk heat map, active attack chains, agent status panel, and TI-KG coverage meter. Designed for wall-display use in physical SOC environments.  
*Directly satisfies deliverable: working dashboard.*

**F62 — Incident Timeline Visualiser**  
Interactive Gantt-style timeline showing the progression of each active incident: when each event occurred, which assets were involved, which ATT&CK techniques were observed at each stage, and the current investigation status. Analysts can annotate any point on the timeline.  
*Closes: RG-02.*

**F63 — ATT&CK Coverage Heat Map**  
Shows the organisation's current detection coverage mapped onto the ATT&CK matrix. Green = covered, yellow = partial, red = gap. Cells can be clicked to see which detection rules cover that technique and which assets provide telemetry for it. Automatically updated as new incidents close gaps or new telemetry is added.  
*Closes: RG-05.*

**F64 — Risk Score Trend Dashboard**  
Tracks the organisation's aggregate risk score over time, broken down by asset category, business unit, and threat type. Shows risk score changes triggered by newly discovered vulnerabilities, new threat intelligence, and confirmed incidents. Useful for board-level security posture reporting.  
*Closes: RG-08.*

**F65 — Sample-Log Pipeline Demo Mode**  
A dedicated demo mode that loads a curated set of sample security logs representing a realistic multi-stage attack scenario (initial access via phishing → credential dump → lateral movement → data staging → exfiltration). Walks evaluators through the complete AEGIS workflow in a self-contained sandbox, directly satisfying the deliverable requirement for a sample-log pipeline with full demonstration capability.  
*Directly satisfies deliverable: sample-log pipeline.*

---

## 7. Agent Roles and Responsibilities

| Agent | Role | Technology | Key Capability |
|---|---|---|---|
| **Log Analysis Agent** | Ingestion, normalisation, sequence anomaly detection | BERT + Drain3 + LSTM, Kafka consumer | Multimodal anomaly: semantic + temporal |
| **Threat Detection Agent** | ATT&CK mapping, kill-chain reconstruction, risk scoring | Fine-tuned LLM + Bayesian intent model | Campaign correlation, zero-day anticipation |
| **Threat Intelligence Agent** | CTI KG management, RAG retrieval, IOC enrichment | Neo4j + AGRAG + RAGRank | Adversarially hardened KG, live updates |
| **Orchestrator Agent (EDITH-SEC)** | Agent task dispatch, zero-trust gate, STRIDE eval, audit log | Asymmetric cryptography + hash chain | Zero-trust inter-agent communication |
| **Report Generation Agent** | Dual-tier report synthesis, citation locking, export | LLM + provenance graph + Pandoc | Hallucination-suppressed, compliance-aligned reports |
| **Response Agent** | Playbook matching, SOAR bundle generation, IOC dissemination | Rule engine + STIX generator | Human-in-the-loop SOAR integration |
| **Explainability Agent** | SHAP translation, counterfactual generation, evidence drill-down | SHAP + LLM + React frontend | Analyst-grade natural language explanations |

---

## 8. Technology Stack

| Layer | Technology |
|---|---|
| **Ingestion** | Apache Kafka, Logstash, custom adapters |
| **Storage** | Elasticsearch (log index), Neo4j (TI-KG), PostgreSQL (audit chain), Redis (real-time state) |
| **ML Models** | BERT (semantic), LSTM/Transformer (sequence), DBSCAN (clustering), Drain3 (log parsing) |
| **LLM Layer** | Local deployment: Mistral 7B / Llama 3.1 8B (sensitive log processing); API: Claude Sonnet 4.6 (report generation, explanation) |
| **Agent Framework** | LangGraph (stateful multi-agent orchestration), custom STRIDE-gated message bus |
| **RAG Backend** | LlamaIndex + Neo4j GraphRAG for AGRAG architecture |
| **Frontend** | React + Recharts + D3 (ATT&CK heat map) |
| **SOAR Integration** | Splunk SOAR API, XSOAR REST, Sentinel Logic Apps |
| **CTI Standards** | STIX 2.1, TAXII 2.1, OCSF, ECS, MITRE ATT&CK Navigator |
| **Auth/ZTA** | OAuth 2.0 + mTLS inter-agent, RBAC on dashboard, agent keypair rotation |
| **Audit** | SHA-256 hash chain, append-only PostgreSQL log, exportable audit bundles |

---

## 9. Deliverables Mapping

| Required Deliverable | AEGIS Feature(s) | Status |
|---|---|---|
| Working prototype | All 65 features, demo mode (F65) | Fully specified |
| Sample-log pipeline | F65 + F01–F09 ingestion layer | Fully specified |
| Threat classification/risk score | F27–F30, F29 (risk composer) | Fully specified |
| Evidence-backed explanation | F57–F60, F35 (provenance tracking) | Fully specified |
| Recommended response | F53–F56 (response agent) | Fully specified |
| Downloadable incident report | F48–F52, F50 (multi-format export) | Fully specified |
| Working dashboard | F61–F65 | Fully specified |
| At least two specialised AI agents | Seven agents (Log, Threat Detect, TI, Orchestrator, Report, Response, Explain) | Exceeds requirement |

---

## 10. Why This Is Different

Every system reviewed in the 50 papers either:

1. **Detects well but explains poorly** — ML models with 99%+ accuracy produce binary verdicts with no narrative (P19's gap).
2. **Explains well but detects narrowly** — XAI approaches work only on specific log types or attack classes.
3. **Orchestrates agents but trusts them blindly** — No reviewed multi-agent system applies zero-trust controls to its own agent communication bus.
4. **Has a knowledge graph but no live feedback** — TI-KGs are built offline and not updated from live detection events (RG-09).
5. **Generates reports but cannot prove them** — LLM-generated reports hallucinate details not in the evidence (RG-10).

**AEGIS closes all five simultaneously.** The combination of:
- Zero-trust inter-agent communication with STRIDE evaluation and hash-chain audit logging (Sid's EDITH architecture applied to SOC)
- Citation-locked, provenance-grounded report generation that structurally suppresses hallucination
- Adversarially hardened RAG pipeline with PageRank trust scoring for CTI ingestion
- Live feedback from detections back into the TI-KG
- Attacker intent modelling at the campaign level

...is not present in any single system in the reviewed literature. This is a genuine research contribution, not a feature combination exercise.

The EDITH paper (Sid's nine-layer zero-trust architecture for multi-agent LLM systems) is the direct architectural foundation of AEGIS's Orchestrator Agent. The CogniScan IEEE Q1 publication demonstrates the team's ability to take multi-agent AI system proposals to production-quality research.

---

*Document prepared by Sid | AIML Club Ambassador, APSIT Thane | SIH26 Submission*  
*Architecture influenced by: EDITH Zero-Trust Multi-Agent Architecture (IJIS target), CogniScan Multimodal AI Platform (IEEE Q1 published)*
