# Bayezid Hybrid SOC Environment V0.3.4 (The Cognitive & Autonomous Swarm Update)

![Version](https://img.shields.io/badge/Version-3.4-red.svg)
![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Cognitive_Multi_Agent-orange.svg)
![WebSockets](https://img.shields.io/badge/RealTime-Socket.io-blue.svg)
![Vector-DB](https://img.shields.io/badge/Memory-pgvector-purple.svg)
![Encryption](https://img.shields.io/badge/Security-AES_256_CBC-yellow.svg)

**Bayezid V0.3.4 is a revolutionary Cognitive SOC Orchestrator that transcends traditional SOAR boundaries. It is a self-evolving security ecosystem that thinks, remembers, and acts with sub-millisecond precision.**

By merging **Vector-Based Institutional Memory** with a **Multi-Agent AI Architecture**, Bayezid transforms the SOC from a reactive ticketing system into an autonomous digital guardian. It features a unique hybrid engine that balances elite Cloud Intelligence with robust Local LLM fallbacks, ensuring that defense never sleeps—even during network outages.

---

## Core Value Propositions

Bayezid is engineered to solve the "Big Three" SOC challenges: Alert Fatigue, Vendor Lock-in, and Cognitive Overhead, while introducing state-of-the-art offensive capabilities.

* **Institutional Memory (Semantic Deduplication):** Using `pgvector`, Bayezid "memorizes" every incident. If an attack pattern repeats—even with a different IP or timestamp—the system recognizes the semantic similarity and applies historical playbooks instantly, saving thousands in API costs and human hours.
* **Agentic Shared Memory (Cognitive Continuity):** Agents continuously read a "Mental Ledger" of the team's successes and failures. Later-stage agents adapt their strategies dynamically based on the specific footprints left by early-stage agents, demonstrating advanced collective reasoning.
* **Zero-Code Dynamic Playbooks & Execution:** True vendor neutrality. The AI synthesizes execution code (e.g., `cURL` for Palo Alto, LotL commands for Linux/Windows) on-the-fly, adapting to the specific infrastructure context without relying on static, hardcoded scripts.
* **Asynchronous Smart Execution (`smartExec`):** An intelligent execution engine that spawns detached background processes for heavy operations (like full port scans), preventing server lockups while salvaging partial outputs if a command times out.
* **Real-Time Collaborative War Room:** Integrated **Socket.io** enables a live environment where human analysts and AI agents interact. Analysts can summon the AI via `@Bayezid-Action` for immediate isolation or forensic tasks.
* **Hybrid Resilience (Auto-Failover):** The system prioritizes **Google Gemini 2.5 Flash** but features an instantaneous, transparent failover to **Local AI (Qwen 2.5 / Ollama)** if the cloud experiences latency or quota limits.
* **Ironclad Data Privacy:** All sensitive security payloads, API keys, and playbooks are encrypted using **AES-256-CBC** before storage. Proprietary intelligence remains unreadable even if the underlying database is compromised.

---

## Architectural Pillars

The system is built on a modular, event-driven architecture designed for high-throughput security telemetry and elite offensive simulations.

### 1. The Blue Team Engine (Cognitive Defense)

* **Ingestion & Vectorization:** Logs are received, normalized, and immediately compared against the Vector DB for semantic matches.
* **Artifact Extraction (Detective Agent):** Performs deep RAG (Retrieval-Augmented Generation) against a RAM-cached **MITRE ATT&CK Enterprise Database** to map threats to specific TTPs.
* **Strategic Orchestration (Commander Agent):** Formulates the JSON-based threat report, calculates confidence scores, and determines the escalation path.

### 2. The Red Team Swarm (Autonomous Offensive APT)

When toggled to **RED MODE**, Bayezid activates a proactive, fully autonomous offensive squad capable of executing complex kill-chains with intelligent fallback mechanisms:

* **The Scout (Reconnaissance):** Masters Operational Security (OpSec). Formulates sophisticated WAF-bypass commands (injecting `X-Forwarded-For` headers, rate-limiting) and autonomously routes heavy enumeration tasks to background processes.
* **The Breacher (Initial Access):** Displays high exploitation resilience via autonomous retry loops. If an initial payload fails, it dynamically pivots (e.g., transitioning from XXE file inclusion to SSRF attempts) to secure a foothold.
* **The Phantom (Privilege Escalation):** An OS internals ghost. Capable of analyzing compromised contexts to deploy Docker container breakouts, SUID enumeration, and Living off the Land (LotL) tactics to achieve root/SYSTEM.
* **The Chameleon (Stealth & Anti-Forensics):** The cognitive masterpiece of the swarm. Utilizes the *Shared Memory* ledger to cross-reference previous agent actions. It can autonomously detect deceptive user prompts (e.g., realizing the target is Linux despite the user claiming it is Windows) to execute flawless, zero-code log wiping and track-clearing maneuvers.
* **The Overlord (Commander):** The supreme orchestrator. Manages the mental ledger, triggers the next agent in the sequence, and commands immediate evasive action if EDR/WAF systems are triggered.
* **The Scribe (Documentation):** Operates seamlessly in the background, consuming success/failure logs to generate highly professional, structured Markdown Penetration Testing reports in real-time.

### 3. Memory & Intelligence Services

* **Embedding Engine:** Converts security logs into 768-dimensional vectors.
* **Global Intel Enrichment:** Real-time OSINT queries from **AlienVault OTX**, **MISP**, and **OpenCTI** provide the AI with the latest global reputation scores.

---

## Service Breakdown (The Micro-Service Logic)

| Service | Responsibility | Technology |
| :--- | :--- | :--- |
| **`server.js`** | The Central Nervous System (Orchestrator) | Node.js / Socket.io / Express |
| **`aiService.js`** | Multi-Agent Logic, Smart Exec & Intent Analysis | Gemini / Qwen / RAG / Child Process |
| **`memoryService.js`** | Vector Storage & Semantic Similarity Search | pgvector / Embeddings |
| **`playbookService.js`** | Zero-Code Synthesis & API Execution | AI Synthesis / Shell Exec |
| **`cryptoService.js`** | Payload Encryption & Key Management | Node Crypto (AES-256) |
| **`tuningService.js`** | Natural Language Configuration (NLP) | Dynamic Config Engine |

---

## Resilience & Self-Healing

Bayezid is built to thrive in "broken" or unstable environments:

1.  **AI Fallback Logic:** If the cloud engine returns a 503 (High Demand) or 429 (Quota), the `aiService` automatically re-routes the request to the local `qwen2.5-coder` model.
2.  **Autonomous Execution Retry Loop:** Red agents do not halt on command failures. They analyze the terminal error output and autonomously cycle through pre-generated alternative tactics.
3.  **SLA Escalation Watcher:** A persistent background job monitors "Pending" alerts and triggers automatic escalations if the defined SLA is breached.
4.  **Graceful Degradation:** If OSINT APIs fail, the system proceeds with internal heuristic analysis rather than stalling the pipeline.

---

## Getting Started

### Prerequisites
* **Node.js:** v20.x or higher.
* **Database:** PostgreSQL with the `pgvector` extension (Supabase highly recommended).
* **Local AI (Optional):** Ollama installed for the local fallback engine.

### Quick Start
```bash
# Clone the repository
git clone https://github.com/ahmed-momen61/bayezid-soar-engine.git

# Install core dependencies
npm install

# Push the schema to your Vector-enabled DB
npx prisma db push
npx prisma generate

# Fire up the engine
node server.js
```

---

## Environment Variables (.env)
```env

PORT=3000
DATABASE_URL="postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>"
DIRECT_URL="postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>"

AI_MODE=CLOUD
GEMINI_API_KEY="AIzaSy_YOUR_GEMINI_API_KEY_HERE"
GOOGLE_API_KEY="AIzaSy_YOUR_GOOGLE_API_KEY_HERE"
LOCAL_MODEL_NAME="qwen2.5-coder:7b"
OLLAMA_BASE_URL="http://localhost:11434"

TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID_HERE"

ENCRYPTION_KEY="your_64_character_hex_string_here"
ENCRYPTION_IV="your_32_character_hex_string_here"
OTX_API_KEY="your_alienvault_otx_api_key_here"
OPENCTI_URL="https://your-opencti-instance-url"
OPENCTI_TOKEN="your_opencti_token_here"

SLA_TIMEOUT_MINUTES=5
```
NOTE : you can check the Test showcases for the blue and red sides, please download the RAR file 
---

**Bayezid Fighter** — **Yildirim Logic — The Strike Before the Signal**

Developed by: **Ahmed Mo'men Ahmed** | 2026.