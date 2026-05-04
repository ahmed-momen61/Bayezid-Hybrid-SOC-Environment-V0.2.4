const axios = require('axios');
const itsmService = require('./itsmService');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { enrichContext } = require('./ragService');
require('dotenv').config();

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const smartExec = async(command, timeoutMs, isBackground) => {
    if (isBackground) {
        const logFile = path.join(__dirname, `job_${Date.now()}.log`);
        const out = fs.openSync(logFile, 'a');
        const err = fs.openSync(logFile, 'a');

        const child = spawn(command, {
            shell: true,
            detached: true,
            stdio: ['ignore', out, err]
        });
        child.unref();

        return {
            stdout: `[BACKGROUND JOB STARTED] PID: ${child.pid}.\nLogs saving to: ${logFile}.`,
            stderr: ""
        };
    }

    try {
        const { stdout, stderr } = await execPromise(command, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 10 });
        return { stdout, stderr };
    } catch (err) {
        if (err.killed && err.signal === 'SIGTERM') {
            return {
                stdout: `[⚠️ TIMEOUT AFTER ${timeoutMs/1000}s] Partial Output Salvaged:\n${err.stdout || ""}`,
                stderr: err.stderr || ""
            };
        }
        throw err;
    }
};

const getSharedMemory = async(targetIp) => {
    try {
        const logs = await prisma.redSwarmLog.findMany({
            where: { targetIp: targetIp, isSuccess: true },
            orderBy: { createdAt: 'desc' },
            take: 5
        });
        if (logs.length === 0) return "No previous successful actions. Starting fresh.";
        return logs.map(l => `[${l.agentName} SUCCESS]: ${l.executedCommand}`).join('\n');
    } catch (e) { return "Memory currently unavailable."; }
};

const deepSanitize = (obj) => {
    if (typeof obj !== 'object' || obj === null) return;
    for (let key in obj) {
        if (key.toLowerCase().includes('recommend') && Array.isArray(obj[key])) {
            obj[key] = obj[key].join('\n');
        }
        if (key.toLowerCase().includes('cvss')) {
            obj[key] = String(obj[key]);
        }
        if (typeof obj[key] === 'object') {
            deepSanitize(obj[key]);
        }
    }
    return obj;
};

const analyzeWithVertexAI = async(alertData) => {
    console.log('\n[☁️] Sending Data to Cloud AI (Waterfall Fallback Mode)...');

    try {
        const safeDataString = typeof alertData === 'string' ? alertData : JSON.stringify(alertData);
        const injectedContext = await enrichContext(safeDataString);

        const cloudModels = [
            "gemini-3.1-pro-preview",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash"
        ];

        const systemPrompt = `You are an Elite Cloud-Based Cybersecurity SIEM Correlation Engine.
        
        [THREAT INTELLIGENCE CONTEXT]
        ${injectedContext}

        [DECISION MATRIX RULE]
        You must classify the attack's 'confidence_type':
        - Use "DETERMINISTIC" if the threat is undeniable and requires instant Auto-Kill (e.g., Brute Force, DDoS, Known Malware hashes, clear SQLi/RCE).
        - Use "PROBABILISTIC" if the threat is anomalous and needs human validation in a War Room (e.g., Impossible Travel, Internal Port Scanning, Privilege Escalation that might be a Sysadmin).

        Analyze the security data using the provided threat intelligence context.
        You MUST respond ONLY with a valid JSON object matching this exact format:
        {
            "is_false_positive": false,
            "confidence_score": "e.g., 99%",
            "confidence_type": "DETERMINISTIC or PROBABILISTIC",
            "extracted_ip": "Primary source IP",
            "extracted_iocs": {
                "ips": ["All malicious IPs found"],
                "hashes": ["Any MD5/SHA-1/SHA-256 hashes found"],
                "domains": ["Any malicious domains or URLs found"]
            },
            "related_cves": ["Any mentioned or implied CVEs, e.g., 'CVE-2023-1234'. Empty array if none."],
            "severity": "CRITICAL, HIGH, MEDIUM, LOW",
            "threat_type": "The correlated attack name",
            "cvss_score": "Estimated CVSS v3.1 base score (e.g., '9.8')",
            "cwe_id": "Relevant CWE ID",
            "mitre_attack": { "tactic": "Tactic name", "technique": "Technique name", "technique_id": "TXXXX" },
            "kill_chain_phase": "Current phase",
            "detailed_report": "A deep chronological analysis of the logs based strictly on the provided threat intel.",
            "predicted_next_steps": "What the attacker will do next.",
            "business_continuity_analysis": "How to isolate this.",
            "recommended_action": "Specific technical response."
        }`;

        let aiResponse = null;
        let successfulModel = "";

        for (const modelName of cloudModels) {
            try {
                const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
                const model = genAI.getGenerativeModel({
                    model: modelName,
                    generationConfig: { responseMimeType: "application/json" }
                });

                const result = await model.generateContent(`${systemPrompt}\n\nAnalyze this data: ${safeDataString}`);
                const text = result.response.text();

                aiResponse = JSON.parse(text);
                successfulModel = modelName;
                break;
            } catch (err) {
                console.warn(`[⚠️] Cloud Model (${modelName}) Failed: ${err.message}. Switching to next...`);
                continue;
            }
        }

        if (!aiResponse) throw new Error("All cloud models exhausted.");

        aiResponse = deepSanitize(aiResponse);

        return {
            ...aiResponse,
            engine_used: `Google ${successfulModel} + Hybrid RAG (Cloud ☁️)`
        };

    } catch (error) {
        console.error('[-] Cloud AI Error (All Models Failed):', error.message);
        return { severity: 'HIGH', threat_type: 'Cloud Offline Fallback', recommended_action: 'Manual Investigation Required', engine_used: 'Fail-safe (Cloud Error)' };
    }
};

const analyzeWithLocalModel = async(alertData) => {
    console.log('\n[🏠] Initiating High-Speed Local Architecture (Powered by Qwen 2.5)...');
    const safeDataString = typeof alertData === 'string' ? alertData : JSON.stringify(alertData);

    const injectedContext = await enrichContext(safeDataString);
    console.log(`[📚] Hybrid Intel Injected.`);

    try {
        console.log(`\n[🕵️‍♂️] Role 1 (Detective) is extracting artifacts...`);
        const detectivePrompt = `You are a Lead Cyber Forensic Investigator. Read the following security event and extract ALL technical artifacts.
        Event Data: ${safeDataString}
        Task: Extract a detailed list of:
        - All IP addresses and ports.
        - Specific vulnerabilities (CVEs) and their exact nature.
        - File Hashes (MD5, SHA256) and Malicious Domains/URLs.
        - Specific processes, binaries, and privileges mentioned (e.g., SeDebugPrivilege).
        Be highly technical and precise.`;

        const detectiveResponse = await axios.post('http://localhost:11434/api/generate', {
            model: 'qwen2.5-coder:7b',
            prompt: detectivePrompt,
            stream: false
        });
        const extractedFacts = detectiveResponse.data.response;
        console.log(`[✔] Detective Extracted Facts successfully.`);

        console.log(`\n[🎖️] Role 2 (Commander) is formulating the Strategic JSON Report...`);
        const commanderPrompt = `You are an Elite Tier 3 Cybersecurity Incident Commander.
        
        [THREAT INTELLIGENCE CONTEXT]
        ${injectedContext}

        [FORENSIC DETECTIVE'S ARTIFACTS]
        ${extractedFacts}

        [STRICT ANALYSIS FRAMEWORK]:
        1. Deep Narrative: Write a comprehensive, multi-sentence story in 'detailed_report' explaining HOW the attack happened using the artifacts.
        2. Strict JSON Formatting: Your 'cvss_score' MUST be exactly a string like "9.8". NO extra characters.
        3. Decision Matrix: You must evaluate the 'confidence_type'. Set it to "DETERMINISTIC" for absolute threats (DDoS, Malware, Brute Force). Set it to "PROBABILISTIC" for anomalies (Impossible Travel, weird internal traffic).
        4. Extract IoCs: Accurately populate the 'extracted_iocs' and 'related_cves' arrays based on the detective's artifacts.
        5. Strategic Action: Provide EXACTLY 6 to 8 numbered steps in 'recommended_action' as a single string, NOT an array. 

        You MUST respond ONLY with a valid JSON object matching this exact format, NO markdown:
        {
            "is_false_positive": false,
            "confidence_score": "99%",
            "confidence_type": "DETERMINISTIC",
            "extracted_ip": "IP address",
            "extracted_iocs": {
                "ips": ["..."],
                "hashes": ["..."],
                "domains": ["..."]
            },
            "related_cves": ["CVE-XXXX-XXXX"],
            "severity": "CRITICAL, HIGH, MEDIUM, LOW",
            "threat_type": "Descriptive attack name",
            "cvss_score": "9.8",
            "cwe_id": "Accurate CWE ID",
            "mitre_attack": { "tactic": "...", "technique": "...", "technique_id": "..." },
            "kill_chain_phase": "Current phase",
            "detailed_report": "Detailed, multi-sentence narrative.",
            "predicted_next_steps": "Highly detailed next actions.",
            "business_continuity_analysis": "Impact description.",
            "recommended_action": "1. Step one\\n2. Step two\\n3. Step three"
        }`;

        const commanderResponse = await axios.post('http://localhost:11434/api/generate', {
            model: 'qwen2.5-coder:7b',
            prompt: commanderPrompt,
            stream: false,
            format: 'json'
        });

        let localText = commanderResponse.data.response;
        localText = localText.replace(/```json/gi, '').replace(/```/gi, '').trim();

        let finalReport = JSON.parse(localText);

        finalReport = deepSanitize(finalReport);

        return {
            ...finalReport,
            engine_used: 'High-Speed Local (Qwen 2.5 Multi-Role) + Hybrid RAG ⚡🏠'
        };

    } catch (error) {
        console.error('[-] Multi-Role AI Error:', error.message);
        return { severity: 'HIGH', threat_type: 'Local AI Offline Fallback', recommended_action: 'Manual Investigation', engine_used: 'Fail-safe' };
    }
};

const orchestrateRedSwarm = async(targetInfo, currentState) => {
    console.log(`\n[🧠] Waking up The Brain (RedSwarm Orchestrator) for Target: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const brainPrompt = `You are 'The Brain', the lead orchestrator of Project RedSwarm, an AI-driven Red Teaming squad.
        Your squad:
        1. "Scout": Active/Passive Reconnaissance & Scanning.
        2. "Breacher": Exploitation & Initial Access.
        3. "Phantom": Privilege Escalation & Persistence.
        4. "Chameleon": Payload tuning & WAF bypass.
        5. "Scribe": MITRE reporting.

        Instructions:
        - Analyze the Target and Current State.
        - Decide which agent acts next based on MITRE ATT&CK.
        - Output strictly in JSON format: 
        { "next_agent": "AgentName", "task": "Detailed instructions", "mitre_tactic": "Tactic ID" }`;

        const result = await model.generateContent(`${brainPrompt}\n\nTarget: ${targetInfo}\nCurrent State: ${currentState}`);
        const text = result.response.text();

        const decision = JSON.parse(text);
        console.log(`[🎯] The Brain assigned task to: [${decision.next_agent}]`);
        console.log(`[📋] Task: ${decision.task}`);

        return decision;

    } catch (error) {
        console.error('[-] The Brain encountered an error:', error.message);
        return null;
    }
};

const askRedSwarmAI = async(prompt, requireJson = true) => {
    const cloudModels = [
        "gemini-3.1-pro-preview",
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.0-flash"
    ];

    for (const modelName of cloudModels) {
        try {
            const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
            const model = genAI.getGenerativeModel({
                model: modelName,
                generationConfig: requireJson ? { responseMimeType: "application/json" } : {}
            });

            const response = await model.generateContent(prompt);
            let text = response.response.text();

            if (requireJson) {
                text = text.replace(/\\n/g, "\\n").replace(/\\'/g, "\\'").replace(/\\"/g, '\\"').replace(/\\&/g, "\\&").replace(/\\r/g, "\\r").replace(/\\t/g, "\\t").replace(/\\b/g, "\\b").replace(/\\f/g, "\\f");
                text = text.replace(/```json/gi, '').replace(/```/gi, '').trim();
                return JSON.parse(text);
            }
            return text;

        } catch (cloudError) {
            console.warn(`[⚠️] Cloud Model (${modelName}) Failed: ${cloudError.message}. Switching to next...`);
            continue;
        }
    }

    console.log(`\n[🚨] ALL Cloud Models Exhausted!`);
    console.log(`[🔄] Initiating Last Resort Fallback to Local AI (Ollama/Qwen)...`);

    try {
        const localResponse = await axios.post('http://localhost:11434/api/generate', {
            model: process.env.LOCAL_MODEL_NAME || "qwen2.5-coder:7b",
            prompt: prompt + (requireJson ? "\n\nCRITICAL: You MUST return ONLY valid JSON formatting without markdown blocks." : ""),
            stream: false,
            format: requireJson ? "json" : ""
        });

        let text = localResponse.data.response;

        if (requireJson) {
            text = text.replace(/\\n/g, "\\n").replace(/\\'/g, "\\'").replace(/\\"/g, '\\"');
            text = text.replace(/```json/gi, '').replace(/```/gi, '').trim();
            return JSON.parse(text);
        }
        return text;

    } catch (localError) {
        console.error(`[❌] Local AI also failed. System is blind: ${localError.message}`);
        throw new Error("Both Cloud and Local AI Engines failed.");
    }
};

const runScoutAgent = async(targetInfo, customInstructions = "") => {
    console.log(`\n[👁️] Waking up Scout (Recon Agent) for Target: ${targetInfo}...`);
    try {
        const sharedMemory = await getSharedMemory(targetInfo);
        const scoutPrompt = `You are 'Scout', the elite Recon Agent. Target: ${targetInfo}.
        Recent Team Successes (Shared Memory): ${sharedMemory}
        Instructions: ${customInstructions || "None"}

        Task:
        1. Formulate the best aggressive Linux command for footprinting (nmap, ffuf, nuclei).
        2. Actively look for WAFs, API endpoints, and exposed directories.
        3. Estimate the time needed. If > 2 minutes, set "run_in_background": true.
        
        Strictly return JSON:
        {
            "best_command": "...",
            "estimated_timeout_ms": 60000,
            "run_in_background": false,
            "reasoning": "...",
            "alternatives": [ { "command": "...", "description": "..." } ]
        }`;

        const aiDecision = await askRedSwarmAI(scoutPrompt, true);
        let executionOutput = "";
        let finalCommand = aiDecision.best_command;
        let success = false;
        const timeoutMs = aiDecision.estimated_timeout_ms || 30000;
        const isBackground = aiDecision.run_in_background || false;
        const commandsToTry = [aiDecision.best_command, ...(aiDecision.alternatives || []).map(a => a.command)];

        for (let cmd of commandsToTry) {
            if (!cmd) continue;
            console.log(`[⚙️] Scout Executing: ${cmd} (Timeout: ${timeoutMs/1000}s | BG: ${isBackground})`);
            try {
                const { stdout, stderr } = await smartExec(cmd, timeoutMs, isBackground);
                executionOutput = stdout || stderr;
                success = true;
                finalCommand = cmd;
                break;
            } catch (err) {
                console.log(`[⚠️] Command failed. Retrying...`);
                executionOutput = err.message;
            }
        }

        await prisma.redSwarmLog.create({ data: { targetIp: targetInfo, agentName: "Scout", assignedTask: "Recon", executedCommand: finalCommand, executionOutput: executionOutput, isSuccess: success } });
        return { agent: "Scout", scan_results: executionOutput, next_action: "Hand over to Breacher." };
    } catch (error) { console.error('[-] Scout Error:', error.message); return null; }
};

const runBreacherAgent = async(targetInfo, scanResults, customInstructions = "") => {
    console.log(`\n[⚔️] Waking up Breacher (Exploitation Agent) for Target: ${targetInfo}...`);
    try {
        const sharedMemory = await getSharedMemory(targetInfo);
        const breacherPrompt = `You are 'Breacher', the Initial Access Agent. Target: ${targetInfo}.
        Recent Team Successes (Shared Memory): ${sharedMemory}
        Recon Data: ${scanResults}
        
        Task (Phase 3):
        1. Analyze scan results. Look for SSTI, Deserialization, SSRF, SQLi, LFI/RFI.
        2. Formulate the exact attack command (curl, hydra, sqlmap) for RCE/Initial Access.
        3. Estimate timeout. If > 2 minutes, set "run_in_background": true.

        Strictly return JSON:
        {
            "primary_attack_vector": "...",
            "best_command": "...",
            "estimated_timeout_ms": 60000,
            "run_in_background": false,
            "reasoning": "...",
            "alternatives": [ { "command": "...", "description": "..." } ]
        }`;

        const aiDecision = await askRedSwarmAI(breacherPrompt, true);
        let executionOutput = "";
        let finalCommand = aiDecision.best_command;
        let success = false;
        const timeoutMs = aiDecision.estimated_timeout_ms || 30000;
        const isBackground = aiDecision.run_in_background || false;
        const commandsToTry = [aiDecision.best_command, ...(aiDecision.alternatives || []).map(a => a.command)];

        for (let cmd of commandsToTry) {
            if (!cmd) continue;
            console.log(`[⚙️] Breacher Executing: ${cmd}`);
            try {
                const { stdout, stderr } = await smartExec(cmd, timeoutMs, isBackground);
                executionOutput = stdout || stderr;
                success = true;
                finalCommand = cmd;
                break;
            } catch (err) {
                console.log(`[⚠️] Exploit failed. Trying next vector...`);
                executionOutput = err.message;
            }
        }

        await prisma.redSwarmLog.create({ data: { targetIp: targetInfo, agentName: "Breacher", assignedTask: "Initial Foothold", executedCommand: finalCommand, executionOutput: executionOutput, isSuccess: success } });
        return { agent: "Breacher", output: executionOutput };
    } catch (error) { console.error('[-] Breacher Error:', error.message); return null; }
};

const runPhantomAgent = async(targetInfo, shellContext, customInstructions = "") => {
    console.log(`\n[👻] Waking up Phantom (PrivEsc & OS Ghost) for Target: ${targetInfo}...`);
    try {
        const sharedMemory = await getSharedMemory(targetInfo);
        const phantomPrompt = `You are 'Phantom', the OS Internals Agent. Target: ${targetInfo}.
        Recent Team Successes (Shared Memory): ${sharedMemory}
        Context: ${shellContext}
        
        Task (Phases 4-5):
        1. Analyze OS context. Check for Docker Breakout or Active Directory.
        2. Use 'Living off the Land' (LotL) techniques (certutil, bash, wmic) to avoid EDR.
        3. Formulate PrivEsc command to ROOT/SYSTEM.
        
        Strictly return JSON:
        {
            "primary_escalation_vector": "...",
            "best_command": "...",
            "estimated_timeout_ms": 45000,
            "run_in_background": false,
            "reasoning": "...",
            "alternatives": [ { "command": "...", "description": "..." } ]
        }`;

        const aiDecision = await askRedSwarmAI(phantomPrompt, true);
        let executionOutput = "";
        let finalCommand = aiDecision.best_command;
        let success = false;
        const timeoutMs = aiDecision.estimated_timeout_ms || 30000;
        const isBackground = aiDecision.run_in_background || false;
        const commandsToTry = [aiDecision.best_command, ...(aiDecision.alternatives || []).map(a => a.command)];

        for (let cmd of commandsToTry) {
            if (!cmd) continue;
            console.log(`[⚙️] Phantom Executing: ${cmd}`);
            try {
                const { stdout, stderr } = await smartExec(cmd, timeoutMs, isBackground);
                executionOutput = stdout || stderr;
                success = true;
                finalCommand = cmd;
                break;
            } catch (err) {
                console.log(`[⚠️] Escalation failed. Trying fallback...`);
                executionOutput = err.message;
            }
        }

        await prisma.redSwarmLog.create({ data: { targetIp: targetInfo, agentName: "Phantom", assignedTask: "Privilege Escalation", executedCommand: finalCommand, executionOutput: executionOutput, isSuccess: success } });
        return { agent: "Phantom", output: executionOutput };
    } catch (error) { console.error('[-] Phantom Error:', error.message); return null; }
};

const runChameleonAgent = async(targetInfo, failedPayload, wafContext, customInstructions = "") => {
    console.log(`\n[🦎] Chameleon Activated: Evaluating environment for Evasion/Cleanup...`);
    try {
        const sharedMemory = await getSharedMemory(targetInfo);
        const chameleonPrompt = `You are 'Chameleon', the Stealth & Anti-Forensics Agent.
        Target: ${targetInfo}
        Failed Attempt: ${failedPayload || "None"}
        Recent Team Successes: ${sharedMemory}
        
        YOUR MISSION:
        1. IF ACTION IS 'CLEANUP': Dynamically identify the OS (Linux/Windows/macOS) from the context. Generate aggressive, zero-code commands to wipe traces, kill suspicious processes, and clear logs SPECIFIC to that OS. 
        2. IF ACTION IS 'EVASION': Obfuscate the failed payload to bypass WAF/EDR using LotL (Living off the Land).
        
        Strictly return JSON:
        {
            "action_type": "CLEANUP" | "EVASION",
            "os_detected": "Linux" | "Windows" | "macOS",
            "best_command": "exact command to execute",
            "estimated_timeout_ms": 30000,
            "run_in_background": false,
            "reasoning": "...",
            "alternatives": [ { "command": "...", "description": "..." } ]
        }`;

        const aiDecision = await askRedSwarmAI(chameleonPrompt, true);
        console.log(`[🦎] Chameleon Action: ${aiDecision.action_type} on ${aiDecision.os_detected}`);

        let executionOutput = "";
        let finalCommand = aiDecision.best_command;
        let success = false;
        const timeoutMs = aiDecision.estimated_timeout_ms || 30000;
        const isBackground = aiDecision.run_in_background || false;
        const commandsToTry = [aiDecision.best_command, ...(aiDecision.alternatives || []).map(a => a.command)];

        for (let cmd of commandsToTry) {
            if (!cmd) continue;
            console.log(`[⚙️] Chameleon Executing: ${cmd} (Timeout: ${timeoutMs/1000}s | BG: ${isBackground})`);
            try {
                const { stdout, stderr } = await smartExec(cmd, timeoutMs, isBackground);
                executionOutput = stdout || stderr || "Execution completed with no output.";
                success = true;
                finalCommand = cmd;
                break;
            } catch (err) { executionOutput = err.message; }
        }

        await prisma.redSwarmLog.create({ data: { targetIp: targetInfo, agentName: "Chameleon", assignedTask: aiDecision.action_type, executedCommand: finalCommand, executionOutput: executionOutput, isSuccess: success } });
        return { agent: "Chameleon", output: executionOutput };
    } catch (error) {
        console.error('[-] Chameleon Error:', error.message);
        return null;
    }
};

const runOverlordAgent = async(targetInfo) => {
    console.log(`\n[👑] The Overlord is reviewing the Mental Ledger for Target: ${targetInfo}...`);
    try {
        const logs = await prisma.redSwarmLog.findMany({ where: { targetIp: targetInfo }, orderBy: { createdAt: 'asc' } });
        const formattedLogs = logs.map(l => `[${l.agentName}] Cmd: ${l.executedCommand} | Success: ${l.isSuccess} | Out: ${(l.executionOutput || "No Output").substring(0, 500)}`).join('\n\n');

        const overlordPrompt = `You are 'The Overlord', the APT Commander. Target: ${targetInfo}
        Mental Ledger:
        ${formattedLogs || "No actions yet."}

        STRATEGIC DIRECTIVES:
        1. If a major milestone is reached (e.g., Shell access, Root gained), IMMEDIATELY summon 'Scribe' to update the live report.
        2. If an agent is detected or blocked by EDR/WAF, IMMEDIATELY summon 'Chameleon' with action 'CLEANUP' to wipe tracks.
        3. If an exploit failed but a 1% chance exists, summon 'Chameleon' with action 'EVASION' to re-tune the payload.
        4. If operation is complete, set "is_operation_complete" to true.

        Strictly return JSON:
        {
            "global_analysis": "...",
            "is_operation_complete": false,
            "next_agent": "Scout|Breacher|Phantom|Chameleon|Scribe",
            "detailed_instructions": "..."
        }`;

        return await askRedSwarmAI(overlordPrompt, true);
    } catch (error) { console.error('[-] Overlord Error:', error.message); return null; }
};

const runScribeAgent = async(targetInfo) => {
    console.log(`\n[📝] Scribe is pulling all data from the Database to generate the final report...`);
    try {
        const logs = await prisma.redSwarmLog.findMany({ where: { targetIp: targetInfo }, orderBy: { createdAt: 'asc' } });
        const campaignHistory = logs.map(l => `Phase: ${l.agentName} | Action: ${l.assignedTask} | Result: ${l.isSuccess ? 'SUCCESS' : 'FAILED'} | Details: ${l.executionOutput}`).join('\n');

        const scribePrompt = `You are 'Scribe', the elite reporting agent.
        Write a highly professional Red Team Pentration Testing Report for Target: ${targetInfo}.
        
        Full Database Logs (Successes & Failures): 
        ${campaignHistory}

        Your report MUST include:
        1. Executive Summary.
        2. Detailed Attack Chain.
        3. Vulnerabilities Discovered.
        4. Remediation Steps.
        
        Format strictly in Professional Markdown.`;

        return await askRedSwarmAI(scribePrompt, false);
    } catch (error) { console.error('[-] Scribe Error:', error.message); return null; }
};

const runActionAgent = async(alertContext, userCommand) => {
    console.log(`\n[🤖] Bayezid-Action summoned! Analyzing command: ${userCommand}`);
    try {
        const actionPrompt = `You are 'Bayezid-Action', the SOAR Execution Agent in a SOC War Room.
        Incident Context (Database Record): ${JSON.stringify(alertContext)}
        User Command from Chat: "${userCommand}"

        Your task:
        1. Understand what the SOC Analyst wants to do from the command.
        2. Identify the target IP or entity.
        3. Determine the correct playbook to execute (e.g., BLOCK_IP, ISOLATE_HOST, CLOSE_PORT).
        4. Draft a professional confirmation reply.

        Strictly return JSON:
        {
            "understood_intent": "Brief summary",
            "recommended_playbook": "BLOCK_IP" | "ISOLATE_HOST" | "CUSTOM_ACTION",
            "target_ip": "The IP address",
            "agent_reply": "Your message to the chat confirming the action"
        }`;

        return await askRedSwarmAI(actionPrompt, true);
    } catch (error) { console.error('[-] Action Error:', error.message); return null; }
};

const bridgeRedToBlue = async(vulnId) => {
    console.log(`\n[🛡️] Blue Side (Detective) analyzing vulnerability ID: ${vulnId}`);
    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        if (!vuln) throw new Error("Vulnerability not found.");

        const bluePrompt = `You are the 'Remediation Engineer'. 
        The Red Team compromised: ${vuln.vulnName} 
        Evidence: ${vuln.evidence}

        STRICT DIRECTIVE:
        You are NOT simulating. You are APPLYING A FIX. 
        1. If it's a Code Patch: Provide a 'remediation_code' using 'sed' or 'awk' to find and replace the vulnerable line in the source file, OR a 'Virtual Patch' using iptables/WAF rules.
        2. You MUST provide a valid, executable shell command. DO NOT leave 'remediation_code' empty.
        3. If you don't know the exact file path, assume standard Linux/Windows paths or PROVIDE A BLOCKING RULE (like iptables drop) as a fallback.

        Return strictly JSON:
        {
            "impact_analysis": "...",
            "fix_classification": "Configuration" | "Code Patch",
            "step_by_step_fix": "...",
            "remediation_code": "exact_bash_command_to_run_like_iptables_or_sed", 
            "is_virtual_patch": true
        }`;

        const fixSuggestion = await askRedSwarmAI(bluePrompt, true);

        await prisma.vulnerabilityBridge.update({
            where: { id: vulnId },
            data: {
                fixType: fixSuggestion.fix_classification,
                suggestedFix: JSON.stringify(fixSuggestion)
            }
        });

        console.log(`[🛡️] Analysis complete. Fix classified as: ${fixSuggestion.fix_classification}`);

        const config = await prisma.systemConfig.findUnique({ where: { id: "BAYEZID_CORE_CONFIG" } });
        const autonomyMode = config ? config.autonomyMode : "SNIPER";

        if (autonomyMode === "OVERLORD") {
            console.log(`\n[👑] OVERLORD MODE ACTIVE: Skipping human approval!`);
            console.log(`[👑] Executing autonomous fix for ${vuln.vulnName}...`);

            applyFixAndVerify(vulnId, "Autonomously Approved & Executed by Overlord AI").then(result => {
                console.log(`\n[👑] Overlord sequence complete for ID: ${vulnId}`);
            }).catch(err => console.error("Overlord Execution Error:", err));

            fixSuggestion.autonomy_status = "OVERLORD_TRIGGERED: Fix is being applied autonomously in the background.";
        } else {
            console.log(`\n[🎯] SNIPER MODE ACTIVE: Fix prepared. Waiting for human approval via dashboard/Postman.`);
            fixSuggestion.autonomy_status = "SNIPER_WAITING: Pending human approval.";
        }

        return fixSuggestion;
    } catch (error) { console.error('[-] Bridge Error:', error.message); return null; }
};

const applyFixAndVerify = async(vulnId, userInstructions) => {
    console.log(`\n[🛠️] Action Agent applying fix for vulnerability ID: ${vulnId}`);
    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        const fixData = JSON.parse(vuln.suggestedFix);

        let patchOutput = "";
        try {
            console.log(`[⚙️] Executing Remediation: ${fixData.remediation_code}`);
            const { stdout, stderr } = await smartExec(fixData.remediation_code, 60000, false);
            patchOutput = stdout || stderr || "Executed successfully with no output.";
        } catch (err) { patchOutput = err.message; }

        await prisma.vulnerabilityBridge.update({
            where: { id: vulnId },
            data: { status: "FIXED", userComments: userInstructions }
        });

        console.log(`\n[🔄] Regression Testing: Breacher is re-testing the exploit...`);
        const verifyPrompt = `You are 'Breacher'. We just patched: ${vuln.vulnName} on ${vuln.targetIp}.
        Original Payload that succeeded: ${vuln.evidence}
        
        Task: Formulate the exact command to re-test the vulnerability and ensure the patch works.
        Strictly return JSON: { "best_command": "...", "estimated_timeout_ms": 30000, "run_in_background": false }`;

        const verifyCommand = await askRedSwarmAI(verifyPrompt, true);
        let testOutput = "";
        try {
            const { stdout, stderr } = await smartExec(verifyCommand.best_command, verifyCommand.estimated_timeout_ms || 30000, verifyCommand.run_in_background);
            testOutput = stdout || stderr || "No output.";
        } catch (err) { testOutput = err.message; }

        const evalPrompt = `Evaluate this re-test output. The exploit should FAIL if the patch worked. 
        Output: ${testOutput}
        Return JSON: { "is_vulnerable": boolean, "reason": "..." }`;
        const evalResult = await askRedSwarmAI(evalPrompt, true);

        if (!evalResult.is_vulnerable) {
            await prisma.vulnerabilityBridge.update({ where: { id: vulnId }, data: { status: "VERIFIED_SAFE" } });
            console.log(`[✅] Verification passed! The fix is 100% solid.`);
            if (vuln.ticketId) {
                await itsmService.closeTicket(vuln.ticketId, vuln.suggestedFix);
            }
            const complianceReport = await runAuditorAgent(vuln.vulnName, vuln.suggestedFix);
            console.log(`[🎫] ITSM Updated with Compliance Note.`);
        } else {
            await prisma.vulnerabilityBridge.update({ where: { id: vulnId }, data: { status: "FIX_FAILED" } });
            console.log(`[❌] Verification failed! Vulnerability still exists.`);
        }

        return { patchOutput, verificationResult: evalResult };
    } catch (error) { console.error('[-] Fix & Verify Error:', error.message); return null; }
};

const runAuditorAgent = async(vulnName, remediationCode) => {
    console.log(`[📜] Auditor Agent checking compliance for: ${vulnName}...`);

    const prompt = `
    You are an expert Cybersecurity Compliance Auditor.
    A vulnerability "${vulnName}" was just fixed using the following remediation code:
    \`\`\`
    ${remediationCode}
    \`\`\`
    Briefly state in exactly 1 or 2 sentences which compliance standards (e.g., PCI-DSS, ISO 27001, NIST CSF, GDPR) are satisfied or maintained by applying this fix. Be direct and professional.
    `;

    try {
        const response = await askRedSwarmAI(prompt, false);
        console.log(`\n[⚖️] COMPLIANCE REPORT:`);
        console.log(`\x1b[33m${response}\x1b[0m`);
        return response;
    } catch (error) {
        console.error("[!] Auditor Agent Error:", error);
        return "Compliance check failed.";
    }
};

module.exports = {
    analyzeWithVertexAI,
    analyzeWithLocalModel,
    runScoutAgent,
    runBreacherAgent,
    runPhantomAgent,
    runChameleonAgent,
    runOverlordAgent,
    runScribeAgent,
    runActionAgent,
    bridgeRedToBlue,
    applyFixAndVerify
};