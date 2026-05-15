# Bayezid Hybrid SOC Environment V0.3.4 (The Generative Deception & Collective Immunity Update)

![AI-Powered](https://img.shields.io/badge/AI-Waterfall_Swarm-orange.svg)
![Deception](https://img.shields.io/badge/Defense-Generative_Matrix-blue.svg)
![Wargaming](https://img.shields.io/badge/Evolution-GAN_Wargaming-red.svg)
![Immunity](https://img.shields.io/badge/Immunity-Hydra_Protocol-green.svg)
![Version](https://img.shields.io/badge/Version-3.4-red.svg)
![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Prisma](https://img.shields.io/badge/ORM-Prisma-white.svg)
![AI-Powered](https://img.shields.io/badge/AI-Cognitive_Multi_Agent-orange.svg)
![ML](https://img.shields.io/badge/ML-Isolation_Forest-yellow.svg)
![Vector-DB](https://img.shields.io/badge/Memory-pgvector-purple.svg)
![Encryption](https://img.shields.io/badge/Security-AES_256_CBC-yellow.svg)

**Bayezid V0.3.4 is a revolutionary Cognitive SOC Orchestrator that transcends traditional SOAR boundaries. It is a self-evolving security ecosystem that thinks, remembers, mitigates, shares intelligence, and acts with sub-millisecond precision.**

By merging **Vector-Based Institutional Memory**, **Encrypted Swarm Intelligence**, a **Multi-Agent AI Architecture**, and an **Unsupervised Machine Learning Engine**, Bayezid transforms the SOC from a reactive ticketing system into an autonomous digital guardian. It features a unique hybrid engine that balances elite Cloud Intelligence with robust Local LLM fallbacks, ensuring that defense never sleeps—even during network outages.

---

## Core Value Propositions (The Intelligence Loop & Enterprise Defense)

Bayezid is engineered to solve the "Big Three" SOC challenges: Alert Fatigue, Vendor Lock-in, and Cognitive Overhead, while introducing state-of-the-art offensive capabilities, autonomous remediation, and a globally connected **Self-Learning Architecture**.

* **AI Waterfall Orchestration (RedSwarm Core):** A resilient triple-tier AI logic. Requests route through **Gemini 1.5/2.0**, fall back to **Groq LPU** for speed, and finally to **Local Qwen 2.5** for uncensored or offline operations.

* **The Matrix Shell (Generative Deception):** Instead of simple blocking, Bayezid traps attackers in an LLM-driven virtual environment (Ports 2222/8080). The AI simulates a full Linux OS to study attacker TTPs in isolation.

* **GAN Wargaming (Generative Adversarial Defense):** A self-training arena. The **Red Agent** (Local) creates payloads, while the **Blue Agent** (Cloud) synthesizes **Kinetic Regex Rules**. This creates a "Self-Healing" vaccine.

* **The Hydra Protocol (Collective Immunity):** Using **RSA-2048 signing**, nodes share verified defense rules. Receiving nodes perform a **Hot-Reload** into RAM, achieving network-wide immunity without a restart.

* **Live Kinetic Filter (The Fast Shield):** A true live in-memory filter acting as the first line of defense. It features a **Deep Payload Normalizer** (Double URL Decoding & Null-Byte Stripping) and a **Flexible Regex Engine** to catch obfuscated SQLi/XSS.

* **ML Hash Caching (Zero-CPU Shield):** Before invoking complex analysis, Bayezid hashes incoming payloads. If a known threat reappears, the Intelligence Cache drops it in **<0.01ms** (Zero-CPU footprint), rendering DDoS attacks using malicious payloads ineffective.

* **The ML Sniper (4-Dimensional Isolation Forest):** A Python-based unsupervised learning microservice. It detects Zero-Day anomalies by analyzing statistical deviations across 4 dimensions: *Length, Symbol Density, Entropy, and Keyword Amplification (20x weighted penalty for lethal keywords like 'union', 'sleep', 'admin')*.

* **The Warden Sandbox (Kubernetes Cloud-Native):** When the ML Sniper detects a statistical anomaly (Zero-Day), Bayezid doesn't guess. It orchestrates an **Ephemeral Pod within a Kubernetes Cluster** (`runWardenSandbox`) using `@kubernetes/client-node`. It dynamically executes the payload in a Zero-Egress isolated environment with sub-second boot times (`imagePullPolicy: 'IfNotPresent'`) and safely extracts behavioral logs for AI evaluation.

* **Encrypted Swarm Intelligence (Federated Learning):** Bayezid nodes (e.g., across different ministries or branches) share Zero-Day mathematical features (not raw sensitive payloads) with each other. Using **RSA-2048 asymmetric cryptography** (`swarmCrypto.js`), nodes verify the signature of incoming intel, instantly retraining the local ML model (`/api/v1/ml/swarm_feedback`) to immunize the entire network against a threat seen by only one node.

* **L3 OS Network Striker (Counter-Recon & Execution):** Operates at the network layer (Windows Firewall/eBPF) to instantly drop malicious IPs. Before execution, it performs **Active Fingerprinting** via Reverse OSINT and Nmap scans to document the attacker's ISP, location, and infrastructure for forensic reporting. Includes an autonomous TTL daemon that automatically expires blocks after 24 hours.

* **The Oracle Agent (Reverse Engineering):** A dedicated Local AI (Qwen/Ollama) agent that deobfuscates intercepted payloads and translates raw bash/execution logs from the Kubernetes sandbox into human-readable intent analysis for Forensic RCA reports.

* **The Intelligence Feedback Loop (Continuous Self-Learning):** Bayezid corrects its own ML engine. If the Warden Sandbox deems a statistically anomalous payload as "Safe" (False Positive), Bayezid automatically sends a feedback signal to the Python microservice. The ML Sniper retrains itself instantly, ensuring zero redundant false positives.

* **The Alchemist Agent (Adaptive Exploit Mutation):** Radically transforms Red Team operations by executing a live fuzzing loop directly on the target OS via `smartExec`. If blocked, it ingests stderr/stdout, mutates the payload dynamically, and re-fires until initial access is secured.

* **Closed-Loop Auto-Remediation (Red-to-Blue Bridge):** Bridges offensive discovery with defensive mitigation. Upon detecting a vulnerability, the Blue Team autonomously classifies the threat, synthesizes executable mitigation code, applies the patch, and summons the Red Team to mathematically verify the fix.

---

## Architectural Pillars

The system is built on a modular, event-driven architecture designed for high-throughput security telemetry, elite offensive simulations, and adaptive self-healing.

### 1. The Blue Team Engine (Cognitive Defense)

* **Stage 1 Triage (Kinetic Filter & ML Cache):** Drops non-malicious noise, strips obfuscation, and enforces Zero-CPU blocking.

* **Stage 2 Heuristics & ML (The Sniper):** Identifies Zero-Day patterns via statistical Anomaly Detection.

* **Stage 3 Cloud-Native Dynamic Analysis (The Warden):** Orchestrates Kubernetes pods to execute unknown threats safely.

* **Stage 4 Execution & Mitigation (OS Striker):** Drops the attacker IP at Layer 3 autonomously.

* **Stage 5 Global Synchronization (The Swarm):** Signs and broadcasts the new threat metrics to the federated network.

### 2. The Red Team Swarm (Autonomous Offensive APT)

When toggled to **RED MODE**, Bayezid activates a proactive, fully autonomous offensive squad:

* **The Scout (Reconnaissance):** Formulates sophisticated WAF-bypass commands.

* **The Alchemist (Initial Access & Fuzzing):** Operates a live mutation loop to bypass EDRs/Execution Policies.

* **The Phantom (Privilege Escalation):** An OS internals ghost. Capable of executing container breakouts.

* **The Chameleon (Stealth):** Executes flawless, zero-code log wiping and track-clearing maneuvers.

---

## Service Breakdown (The Micro-Service Logic)

| Service | Responsibility | Technology |
| --- | --- | --- |
| **`server.js`** | Central Orchestrator, Swarm Sync API, Mode Switcher | Node.js / Express |
| **`aiService.js`** | Multi-Agent Logic, K8s Pod Orchestration (`runWardenSandbox`) | Gemini / Qwen / K8s Client |
| **`ml_engine/main.py`** | The ML Sniper, Federated Learning receiver, Persistent Memory | Python / FastAPI / Scikit-Learn |
| **`swarmCrypto.js`** | RSA-2048 key generation, Payload Signing, and Verification | Node.js Crypto |
| **`kernelStriker.js`** | Autonomous L3 IP Blocking and TTL expiration daemon | OS Firewall Commands |
| **`kineticFilter.js`** | ML Hash Caching, Deep Normalization, Flexible Regex | JavaScript |
| **`oracleAgent.js`** | Payload deobfuscation and intent reverse-engineering | Local LLM |
| **`threatGrapher.js`** | Generates dynamic Mermaid.js threat flowcharts for reports | JavaScript / Markdown |
| **`wargamingEngine.js`** | Autonomous GAN Arena & Hydra Broadcasting | Local LLM |
| **`matrixShell.js`** | Generative Deception Shell (SSH/Telnet Emulation) | Node.js Net / LLM |

---

### Prerequisites

* **Node.js:** v20.x or higher.

* **Python:** v3.10 or higher.

* **Kubernetes:** A running K8s cluster (Minikube or Docker Desktop with K8s enabled).

* **Database:** PostgreSQL with the `pgvector` extension.

* **Local AI (Optional):** Ollama installed for the local fallback and Oracle engine (`qwen2.5-coder:7b`).

---

## API Documentation (Testing the Cognitive Capabilities)

You can test the core AI capabilities via these bridge endpoints using Postman:

**1. Kubernetes Sandbox Evasion Test (Dynamic Execution)**

* `POST /api/v1/bridge/report-vuln`
* Body: `{ "vulnName": "K8s Evasion Test", "evidence": "echo 'Checking network...'; ping -c 3 8.8.8.8 || echo 'Network is isolated'; cat /etc/shadow 2>/dev/null; sleep 5", "spoofedIp": "192.168.1.155" }`
* *(Watch Bayezid orchestrate the Pod, extract the logs, drop the IP via OS Striker, and generate the JIRA Forensic Report).*

**2. Swarm Intelligence Simulation (Federated Defense)**

* Run `node testSwarm.js` in a separate terminal.
* *(Watch Bayezid reject forged intelligence and assimilate valid RSA-signed telemetry into its neural engine).*

**3. Cognitive Risk Analysis & Virtual Patch Synthesis**

* `POST /api/v1/bridge/analyze`
* Body: `{ "vulnId": "<UUID>", "autonomyMode": "Sniper" }`

**4. Post-Breach Root Cause Analysis (Forensic RCA)**

* `POST /api/v1/bridge/rca`
* Body: `{ "vulnId": "<UUID>" }`

**5. Launch GAN Wargaming (Self-Evolution)**
* `POST /api/v1/wargaming/start`
* Body: `{ "targetAsset": "Production API" }`

**6. Zero-Day Forge (Exploit Synthesis)**
* `POST /api/v1/forge/generate`
* Body: `{ "vulnContext": "Outdated Apache Struts" }`

---

## Environment Variables (.env)

```env
PORT=3000

DATABASE_URL="postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>"
DIRECT_URL="postgresql://<USER>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>"

AI_MODE=CLOUD
GEMINI_API_KEY="AIzaSy_YOUR_GEMINI_API_KEY_HERE"
GOOGLE_API_KEY="AIzaSy_YOUR_GOOGLE_API_KEY_HERE"
GROQ_API_KEY="gsk_OUR_GROQ_API_KEY_HERE"
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

SWARM_NODES="http://node2.agency.gov,http://node3.agency.gov"
```

---

**Bayezid Fighter** — **Yildirim Logic — The Strike Before the Signal**

Developed by: **Ahmed Mo'men Ahmed** | 2026.
