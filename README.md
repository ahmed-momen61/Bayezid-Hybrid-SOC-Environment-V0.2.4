# 🛡️ Bayezid Cognitive SOAR V0.3.1 (The Intel Update)

![Version](https://img.shields.io/badge/Version-2.1-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Dual_Engine-orange.svg)
![Threat Intel](https://img.shields.io/badge/Intel-AlienVault_OTX-red.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

**Next-Generation, High-Availability Security Orchestration, Automation, and Response (SOAR).**

Bayezid Cognitive SOAR V2.1 is an intelligent, automated cybersecurity operations platform designed to drastically reduce Mean Time To Respond (MTTR). By leveraging a unique **Dual-Engine AI Architecture** (Cloud + Local Fallback) combined with **Global Threat Intelligence (AlienVault OTX)**, Bayezid transforms raw logs into actionable, automated defense mechanisms with zero downtime.

---

## 🌟 Business Value & Core Features

For modern SOCs (Security Operations Centers) and MSSPs, downtime and false positives are expensive. Bayezid is built to address these core business challenges:

* **🔀 Dual-Engine High Availability (Auto-Failover):** Never lose cognitive analysis. If the primary Cloud AI (Google Gemini 1.5 Flash) experiences downtime or rate limits, the system seamlessly and instantly fails over to the Local AI (e.g., Qwen 2.5 Multi-Role via Ollama), ensuring zero-downtime threat analysis.
* **🌍 Global Threat Intelligence (AlienVault OTX):** Deep OSINT and CTI enrichment. Automatically queries AlienVault OTX for malicious IPs and File Hashes (SHA256/MD5), retrieving real-time threat pulses, reputation scores, and malware families *before* passing data to the AI for maximum context.
* **⚡ Semantic Caching (Fast-Path):** Reduces API costs and response times by caching identical recent threats (e.g., repeated DDoS or brute-force attempts from the same IP) and instantly returning the previous cognitive analysis.
* **🧠 RAG with MITRE ATT&CK:** Automatically maps detected threats to the MITRE ATT&CK framework for standardized threat intelligence and extraction of relevant IoCs (IPs, Domains, Hashes, CVEs).
* **🤖 Automated Playbook Execution:** Takes immediate, autonomous action on Critical/High severity alerts (e.g., automated IP blocking on firewalls, creating high-priority incident tickets) without waiting for human intervention.
* **📱 Mobile SOC (Telegram & Slack Integration):** Real-time, formatted alerts sent directly to security teams.
* **🖥️ Web Dashboard & Simulation:** Built-in UI to view alert history and run attack simulations (JSON/Raw Logs) for training and testing.

---

## 🏗️ Technical Architecture

Bayezid operates on a highly modular, event-driven architecture using **Node.js** and **Express**, with a database managed by **Prisma ORM (PostgreSQL)**.

1.  **Ingestion:** Accepts Raw Logs or structured JSON payloads via REST API.
2.  **Pre-processing & Caching:** Checks the database for recent identical threats. Extracts IPs.
3.  **Intel Enrichment:** Queries **AlienVault OTX API** for global IP and Hash reputation scores.
4.  **Cognitive Analysis:** Routes data to the selected AI Engine (Gemini 1.5 Flash via strict JSON schema, or Local LLM).
5.  **Post-processing:** Saves results, maps to MITRE, and updates the database.
6.  **Response:** Triggers Playbooks and sends Slack/Telegram notifications.

---

## 🎛️ Supported AI Engines

Bayezid is model-agnostic and currently supports:
* **Cloud Models:** Google Gemini 1.5 Flash (Optimized with `responseMimeType` for strict JSON outputs).
* **Local Models:** Any model running via Ollama (e.g., `qwen2.5-coder:7b` utilizing a Multi-Role Forensic/Commander prompt system).

---

## 🔑 Environment Variables (.env)
To run the full pipeline including Threat Intel and Cloud AI, ensure the following are set in your `.env`:
```env
DATABASE_URL="postgresql://user:password@localhost:5432/bayezid_db"
GOOGLE_API_KEY="your_gemini_api_key"
OTX_API_KEY="your_alienvault_otx_api_key"
