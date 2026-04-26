# Bayezid Hybrid SOC Environment V0.2.2 (The Red Team Update)

![Version](https://img.shields.io/badge/Version-2.2-red.svg)
![Node.js](https://img.shields.io/badge/Node.js-18.x-green.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Multi_Agent-orange.svg)
![Threat Intel](https://img.shields.io/badge/Intel-AlienVault_OTX-red.svg)
![Deception](https://img.shields.io/badge/Defense-Active_Deception-blue.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

**Next-Generation, High-Availability Security Operations Center (SOC) Environment blending SOAR with Active Defense.**

Bayezid V2.2 transcends traditional SOAR platforms by acting as a comprehensive Hybrid SOC environment. It merges automated defense mechanisms (SOAR) with proactive Red Teaming and Active Deception tactics. By leveraging a **Multi-Agent AI Architecture** and **Global Threat Intelligence**, Bayezid not only blocks threats with zero downtime but also deceives attackers to extract valuable intelligence.

---

## Business Value & Core Features

For modern SOCs (Security Operations Centers) and MSSPs, alert fatigue, false positives, and manual tuning are expensive. Bayezid is built to address these core business challenges:

* **Hybrid Decision Matrix (Auto-Kill vs. HITL):** Intelligently separates deterministic threats (e.g., DDoS, Brute Force) for instant, zero-touch auto-remediation, from probabilistic anomalies that require human validation via a Human-In-The-Loop (HITL) Digital War Room.

* **Active Deception & Honeypots (Red-Ops):** Shifts defense from passive to active. Instead of merely blocking confirmed attackers, Bayezid dynamically reroutes malicious traffic to isolated honeypots to monitor TTPs and gather proprietary threat intel.

* **Smart Tuning Agent (DevSecOps):** Eliminates manual XML rule editing. SOC analysts use Natural Language Processing (NLP) in the chat UI to command the agent to whitelist IPs, adjust alert thresholds, or modify SIEM rules on the fly.

* **Multi-Agent SOC Room:** Facilitates real-time collaboration. Human analysts work alongside three specialized AI agents (L1 Analyst, L2 Hunter, L3 Commander) in a unified chat interface to manage complex incidents.

* **Dual-Engine High Availability (Auto-Failover):** Never lose cognitive analysis. If the primary Cloud AI (Google Gemini 1.5 Flash) experiences downtime or rate limits, the system seamlessly and instantly fails over to the Local AI (e.g., Qwen 2.5 Multi-Role), ensuring continuous threat analysis.

* **Global Threat Intelligence (AlienVault OTX):** Deep OSINT and CTI enrichment. Automatically queries AlienVault OTX for malicious IPs and File Hashes (SHA256/MD5), retrieving real-time threat pulses before passing data to the AI for maximum context.

* **RAG with MITRE ATT&CK:** Automatically maps detected threats to the MITRE ATT&CK framework for standardized threat intelligence and extraction of relevant IoCs.

---

## Technical Architecture

Bayezid operates on a highly modular, event-driven architecture using **Node.js** and **Express**, with a database managed by **Prisma ORM (PostgreSQL)**. The architecture is divided into three functional wings:

1. **The SOAR Wing (Automated Defense):**
   * **Ingestion:** Accepts Raw Logs or structured JSON payloads via REST API endpoints in `server.js`.
   
   * **Pre-processing & Caching:** Checks the database for recent identical threats and extracts IPs to prevent redundant processing.
   
   * **Intel Enrichment:** Queries **AlienVault OTX API** for global IP and Hash reputation scores via `otxService.js`.
   
   * **Cognitive Analysis:** Routes data to the selected AI Engine where the "Detective" agent extracts artifacts and the "Commander" agent formulates the execution playbook (`aiService.js`).
   
   * **Execution:** Triggers dynamic Playbooks via `playbookService.js` and sends Slack/Telegram notifications.

2. **The Red Team Wing (Offense & Deception):**
   * **Attack Simulation:** A built-in engine (`/api/v1/simulation/run`) to inject simulated JSON/Raw log attacks to test SIEM rules and SOC readiness.
   
   * **Deception Logic:** AI-driven protocol designed to redirect flagged attackers to honeypots instead of dropping their packets.

3. **The Smart Tuning Wing (DevSecOps):**
   * **NLP Configuration:** An autonomous agent interface that parses human chat commands to rewrite Wazuh SIEM rules and update database whitelists dynamically without restarting the server.

---

## Supported AI Engines

Bayezid is model-agnostic and currently supports:
* **Cloud Models:** Google Gemini 1.5 Flash (Optimized with `responseMimeType` for strict JSON outputs).

* **Local Models:** Any model running via Ollama (e.g., `qwen2.5-coder:7b` utilizing a Multi-Role Forensic/Commander prompt system and NLP command parsing for the Smart Tuning Agent).

---

## Environment Variables (.env)
To run the full pipeline including Threat Intel, Cloud AI, and Active Defense features, ensure the following are set in your `.env`:
```env
# Database & Core
DATABASE_URL="postgresql://user:password@localhost:5432/bayezid_db"

# AI & Intelligence
GOOGLE_API_KEY="your_gemini_api_key"
OTX_API_KEY="your_alienvault_otx_api_key"

# Automation & Active Defense
AUTO_BLOCK_CONFIDENCE_THRESHOLD=90
DECEPTION_ENABLED=true
