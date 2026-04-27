# Bayezid Hybrid SOC Environment V0.2.4 (The Cognitive & Real-Time Update)

![Version](https://img.shields.io/badge/Version-3.0-red.svg)
![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Cognitive_Multi_Agent-orange.svg)
![WebSockets](https://img.shields.io/badge/RealTime-Socket.io-blue.svg)
![Vector-DB](https://img.shields.io/badge/Memory-pgvector-purple.svg)
![Encryption](https://img.shields.io/badge/Security-AES_256_CBC-yellow.svg)

**Bayezid V0.3.0 is a revolutionary Cognitive SOC Orchestrator that transcends traditional SOAR boundaries. It is a self-evolving security ecosystem that thinks, remembers, and acts with sub-millisecond precision.**

By merging **Vector-Based Institutional Memory** with a **Multi-Agent AI Architecture**, Bayezid transforms the SOC from a reactive ticketing system into an autonomous digital guardian. It features a unique hybrid engine that balances elite Cloud Intelligence with robust Local LLM fallbacks, ensuring that defense never sleeps—even during network outages.

---

## Core Value Propositions

Bayezid is engineered to solve the "Big Three" SOC challenges: Alert Fatigue, Vendor Lock-in, and Cognitive Overhead.

* **Institutional Memory (Semantic Deduplication):** Using `pgvector`, Bayezid "memorizes" every incident. If an attack pattern repeats—even with a different IP or timestamp—the system recognizes the semantic similarity and applies historical playbooks instantly, saving thousands in API costs and human hours.

* **Zero-Code Dynamic Playbooks:** True vendor neutrality. The AI doesn't rely on static scripts; it synthesizes execution code (e.g., `cURL` for Palo Alto, Fortinet, or CrowdStrike) on-the-fly, adapting to your specific infrastructure context.

* **Real-Time Collaborative War Room:** Integrated **Socket.io** enables a live environment where human analysts and AI agents (Detective, Commander) interact. Analysts can summon the AI via `@Bayezid-Action` for immediate isolation or forensic tasks.

* **Hybrid Resilience (Auto-Failover):** Cognitive continuity. The system prioritizes **Google Gemini 1.5/2.5 Flash** but features an instantaneous, transparent failover to **Local AI (Qwen 2.5)** via Ollama if the cloud experiences latency or quota limits.

* **Ironclad Data Privacy:** All sensitive security payloads, API keys, and playbooks are encrypted using **AES-256-CBC** before storage. Proprietary intelligence remains unreadable even if the underlying database is compromised.

---

## Architectural Pillars

The system is built on a modular, event-driven architecture designed for high-throughput security telemetry.

### 1. The Blue Team Engine (Cognitive Defense)

* **Ingestion & Vectorization:** Logs are received, normalized, and immediately compared against the Vector DB for semantic matches.

* **Artifact Extraction (Detective Agent):** Performs deep RAG (Retrieval-Augmented Generation) against a RAM-cached **MITRE ATT&CK Enterprise Database** to map threats to specific TTPs.

* **Strategic Orchestration (Commander Agent):** Formulates the JSON-based threat report, calculates confidence scores, and determines the escalation path.

### 2. The Red Team Swarm (Offensive Intelligence)

When toggled to **RED MODE**, Bayezid activates a proactive offensive squad:

* **The Breacher:** Simulates initial access and payload delivery attempts.

* **The Phantom:** Executes stealthy lateral movement and evasion simulations.

* **The Overlord:** Orchestrates the attack chain and generates executive readiness summaries.

### 3. Memory & Intelligence Services

* **Embedding Engine:** Converts security logs into 768-dimensional vectors using `text-embedding-004`.

* **Global Intel Enrichment:** Real-time OSINT queries from **AlienVault OTX**, **MISP**, and **OpenCTI** provide the AI with the latest global reputation scores.

---

## Service Breakdown (The Micro-Service Logic)

| Service | Responsibility | Technology |
| :--- | :--- | :--- |
| **`server.js`** | The Central Nervous System (Orchestrator) | Node.js / Socket.io / Express |
| **`aiService.js`** | Multi-Agent Logic & Intent Analysis | Gemini / Qwen / RAG |
| **`memoryService.js`** | Vector Storage & Semantic Similarity Search | pgvector / Embeddings |
| **`playbookService.js`** | Zero-Code Synthesis & API Execution | AI Synthesis / Shell Exec |
| **`cryptoService.js`** | Payload Encryption & Key Management | Node Crypto (AES-256) |
| **`tuningService.js`** | Natural Language Configuration (NLP) | Dynamic Config Engine |

---

## 🛠️ Resilience & Self-Healing

Bayezid is built to thrive in "broken" or unstable environments:

1.  **AI Fallback Logic:** If Gemini returns a 503 (High Demand) or 429 (Quota), the `aiService` automatically re-routes the request to the local `qwen2.5-coder` model.

2.  **SLA Escalation Watcher:** A persistent background job monitors "Pending" alerts and triggers automatic escalations if the defined SLA (e.g., 10 minutes) is breached.

3.  **Graceful Degradation:** If OSINT APIs fail, the system proceeds with internal heuristic analysis rather than stalling the pipeline.

---

## 🚦 Getting Started

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

## 📱 Environment Variables (.env)
```env
# Infrastructure
DATABASE_URL="postgresql://user:pass@host:6543/postgres?pgvector=true"
PORT=3000

# Cognitive Keys
GOOGLE_API_KEY="AIza..."
LOCAL_MODEL_NAME="qwen2.5-coder:7b"

# Security & Intel
ENCRYPTION_KEY="your_32_byte_hex_key"
OTX_API_KEY="your_otx_api_key"

# Tuning
SLA_TIMEOUT_MINUTES=10
AUTO_BLOCK_CONFIDENCE=90
```

---

**Bayezid Fighter** — *The system that remembers...The intelligence that acts.*

Developed by: **Ahmed Mo'men Ahmed** | 2026.
