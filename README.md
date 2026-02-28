# 🛡️ Bayezid Cognitive SOAR V2

![Version](https://img.shields.io/badge/Version-2.0-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Dual_Engine-orange.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

**Next-Generation, High-Availability Security Orchestration, Automation, and Response (SOAR).**

Bayezid Cognitive SOAR V2 is an intelligent, automated cybersecurity operations platform designed to drastically reduce Mean Time To Respond (MTTR). By leveraging a unique **Dual-Engine AI Architecture** (Cloud + Local Fallback) and integrating semantic caching, OSINT enrichment, and MITRE ATT&CK RAG capabilities, Bayezid transforms raw logs into actionable, automated defense mechanisms.



---

## 🌟 Business Value & Core Features

For modern SOCs (Security Operations Centers) and MSSPs, downtime and false positives are expensive. Bayezid is built to address these core business challenges:

* **🔀 Dual-Engine High Availability (Auto-Failover):** Never lose cognitive analysis. If the primary Cloud AI (Vertex/Gemini) experiences downtime or rate limits, the system seamlessly and instantly fails over to the Local AI (e.g., Qwen via Ollama), ensuring zero-downtime threat analysis.
* **⚡ Semantic Caching (Fast-Path):** Reduces API costs and response times by caching identical recent threats (e.g., repeated DDoS or brute-force attempts from the same IP) and instantly returning the previous cognitive analysis.
* **🧠 RAG with MITRE ATT&CK:** Automatically maps detected threats to the MITRE ATT&CK framework for standardized threat intelligence.
* **🌍 OSINT Enrichment:** Automatically gathers intelligence on malicious IPs before passing data to the AI, providing maximum context.
* **🤖 Automated Playbook Execution:** Takes immediate action on Critical/High severity alerts (e.g., IP blocking, firewall updates) without waiting for human intervention.
* **📱 Mobile SOC (Telegram Integration):** Real-time, formatted alerts sent directly to security teams via Telegram.
* **🖥️ Web Dashboard & Simulation:** Built-in UI to view alert history and run attack simulations (JSON/Raw Logs) for training and testing.

---

## 🏗️ Technical Architecture

Bayezid operates on a highly modular, event-driven architecture using **Node.js** and **Express**, with a database managed by **Prisma ORM**.

1.  **Ingestion:** Accepts Raw Logs or structured JSON payloads via REST API.
2.  **Pre-processing & Caching:** Checks the database for recent identical threats. Extracts IPs.
3.  **Enrichment:** Queries OSINT APIs for IP reputation.
4.  **Cognitive Analysis:** Routes data to the selected AI Engine (Vertex AI, Gemini, or Local LLM).
5.  **Post-processing:** Saves results, maps to MITRE, and updates the database.
6.  **Response:** Triggers Playbooks and sends Telegram notifications.

---

## 🎛️ Supported AI Engines

Bayezid is model-agnostic and currently supports:
* **Cloud Models:** Google Vertex AI, Google Gemini API.
* **Local Models:** Any model running via Ollama (e.g., `qwen2.5:7b`, `llama3`).
