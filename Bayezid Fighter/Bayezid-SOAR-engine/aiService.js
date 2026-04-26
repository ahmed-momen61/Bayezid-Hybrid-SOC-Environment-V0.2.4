const axios = require('axios');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { enrichContext } = require('./ragService');
require('dotenv').config();

const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);

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
    console.log('\n[☁️] Sending Data to Cloud AI (Google Gemini 1.5 Flash)...');

    try {
        const safeDataString = typeof alertData === 'string' ? alertData : JSON.stringify(alertData);
        const injectedContext = await enrichContext(safeDataString);

        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const systemPrompt = `You are an Elite Cloud-Based Cybersecurity SIEM Correlation Engine.
        
        [THREAT INTELLIGENCE CONTEXT]
        ${injectedContext}

        Analyze the security data using the provided threat intelligence context.
        You MUST respond ONLY with a valid JSON object matching this exact format:
        {
            "is_false_positive": false,
            "confidence_score": "e.g., 99%",
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

        const result = await model.generateContent(`${systemPrompt}\n\nAnalyze this data: ${safeDataString}`);
        const text = result.response.text();

        let aiResponse = JSON.parse(text);
        aiResponse = deepSanitize(aiResponse);

        return {
            ...aiResponse,
            engine_used: 'Google Gemini 1.5 Flash + Hybrid RAG (Cloud ☁️)'
        };

    } catch (error) {
        console.error('[-] Cloud AI Error:', error.message);
        return {
            severity: 'HIGH',
            threat_type: 'Cloud Offline Fallback',
            recommended_action: 'Manual Investigation Required',
            engine_used: 'Fail-safe (Cloud Error)'
        };
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
        3. Extract IoCs: Accurately populate the 'extracted_iocs' and 'related_cves' arrays based on the detective's artifacts.
        4. Strategic Action: Provide EXACTLY 6 to 8 numbered steps in 'recommended_action' as a single string, NOT an array. 
        5. Accuracy: Use the provided Threat Intel for CWE and MITRE IDs.

        You MUST respond ONLY with a valid JSON object matching this exact format, NO markdown:
        {
            "is_false_positive": false,
            "confidence_score": "99%",
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

// ==========================================
// Project RedSwarm: The Brain (Orchestrator)
// ==========================================
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

// ==========================================
// Project RedSwarm: Scout Agent (Recon)
// ==========================================
const runScoutAgent = async(targetInfo, customInstructions = "") => {
    console.log(`\n[👁️] Waking up Scout (Recon Agent) for Target: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const scoutPrompt = `You are 'Scout', the elite Reconnaissance Agent of Project RedSwarm.
        Target: ${targetInfo}
        User Custom Instructions (if any): ${customInstructions || "None"}

        Your task:
        1. Formulate the absolute best and safest 'nmap' command based on the target and any user instructions.
        2. Provide 2 alternative 'nmap' commands (e.g., full port scan, UDP scan, or stealth scan).
        
        Strictly return JSON:
        {
            "best_command": "nmap ...",
            "reasoning": "Why this is the best command",
            "alternatives": [
                { "command": "...", "description": "..." },
                { "command": "...", "description": "..." }
            ]
        }`;

        const aiResponse = await model.generateContent(scoutPrompt);
        const aiDecision = JSON.parse(aiResponse.response.text());

        console.log(`[🤖] Scout decided the best command is: ${aiDecision.best_command}`);
        console.log(`[⚙️] Executing command physically on host... Please wait (this may take a minute).`);

        let scanOutput = "";
        try {
            const { stdout, stderr } = await execPromise(aiDecision.best_command);
            scanOutput = stdout || stderr;
            console.log(`[✅] Scan completed successfully.`);
        } catch (execError) {
            console.log(`[❌] Execution failed. Is Nmap installed on this Windows machine?`);
            scanOutput = `Execution Error: ${execError.message}\nMake sure Nmap is installed and added to system PATH.`;
        }

        return {
            agent: "Scout",
            executed_command: aiDecision.best_command,
            reasoning: aiDecision.reasoning,
            scan_results: scanOutput,
            alternative_options: aiDecision.alternatives,
            next_action: "Review the scan_results. If satisfied, target is ready for Breacher. If not, re-run Scout with an alternative command or custom instructions."
        };

    } catch (error) {
        console.error('[-] Scout Agent error:', error.message);
        return null;
    }
};

// ==========================================
// Project RedSwarm: Breacher Agent (Exploitation)
// ==========================================
const runBreacherAgent = async(targetInfo, scanResults, customInstructions = "") => {
    console.log(`\n[⚔️] Waking up Breacher (Initial Access Agent) for Target: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const breacherPrompt = `You are 'Breacher', the Initial Access and Exploitation Agent of Project RedSwarm.
        Target: ${targetInfo}
        Nmap Scan Results / Recon Data:
        ${scanResults}
        
        User Custom Instructions (if any): ${customInstructions || "None"}

        Your task:
        1. Analyze the scan results to find the weakest link (e.g., open SSH, HTTP login, vulnerable FTP).
        2. Provide the absolute best attack command to get initial access (e.g., a specific hydra command, curl exploit, or Metasploit module path).
        3. Provide 2 alternative attack vectors.

        Strictly return JSON:
        {
            "primary_attack_vector": "Name of the vulnerability or method",
            "best_command": "exact command to run in terminal",
            "reasoning": "Why this is the best entry point",
            "alternatives": [
                { "method": "...", "command": "...", "description": "..." }
            ]
        }`;

        const aiResponse = await model.generateContent(breacherPrompt);
        const aiDecision = JSON.parse(aiResponse.response.text());

        console.log(`[🎯] Breacher identified primary vector: ${aiDecision.primary_attack_vector}`);
        console.log(`[🔥] Recommended Command: ${aiDecision.best_command}`);

        return {
            agent: "Breacher",
            target: targetInfo,
            attack_plan: aiDecision,
            next_action: "Execute the 'best_command' on your attacker machine (Kali). If successful, hand over the resulting shell to Phantom (Escalation Agent)."
        };

    } catch (error) {
        console.error('[-] Breacher Agent error:', error.message);
        return null;
    }
};

// ==========================================
// Project RedSwarm: Phantom Agent (Escalation & Persistence)
// ==========================================
const runPhantomAgent = async(targetInfo, shellContext, customInstructions = "") => {
    console.log(`\n[👻] Waking up Phantom (Escalation Agent) for Target: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const phantomPrompt = `You are 'Phantom', the Privilege Escalation and Persistence Agent of Project RedSwarm.
        Target: ${targetInfo}
        Current Shell Context / Access Level:
        ${shellContext}
        
        User Custom Instructions (if any): ${customInstructions || "None"}

        Your task:
        1. Analyze the current shell access (e.g., low privilege user, restricted shell, web shell).
        2. Provide the absolute best command(s) to escalate privileges to root, bypass restrictions, or establish persistence (e.g., Python PTY spawn, Reverse Shell payload, LinPEAS one-liner, modifying /etc/passwd).
        3. Provide 2 alternative escalation/persistence methods.

        Strictly return JSON:
        {
            "primary_escalation_vector": "Name of the technique",
            "best_command": "exact command to run in the compromised shell",
            "reasoning": "Why this works for the given context",
            "alternatives": [
                { "method": "...", "command": "...", "description": "..." }
            ]
        }`;

        const aiResponse = await model.generateContent(phantomPrompt);
        const aiDecision = JSON.parse(aiResponse.response.text());

        console.log(`[👻] Phantom suggests technique: ${aiDecision.primary_escalation_vector}`);
        console.log(`[🔑] Payload: ${aiDecision.best_command}`);

        return {
            agent: "Phantom",
            target: targetInfo,
            escalation_plan: aiDecision,
            next_action: "Execute the payload in your target shell. If blocked by WAF/Filters, call Chameleon (Tuning Agent)."
        };

    } catch (error) {
        console.error('[-] Phantom Agent error:', error.message);
        return null;
    }
};

// ==========================================
// Project RedSwarm: Chameleon Agent (Evasion & Tuning)
// ==========================================
const runChameleonAgent = async(targetInfo, failedPayload, wafContext, customInstructions = "") => {
    console.log(`\n[🦎] Waking up Chameleon (Tuning Agent) to bypass filters on Target: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-2.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const chameleonPrompt = `You are 'Chameleon', the Defense Evasion and Payload Tuning Agent of Project RedSwarm.
        Target: ${targetInfo}
        Failed Payload / Blocked Command: ${failedPayload}
        WAF/Filter Context (Why it failed): ${wafContext}
        User Custom Instructions (if any): ${customInstructions || "None"}

        Your task:
        1. Analyze why the payload was blocked based on the WAF context.
        2. Rewrite, obfuscate, or encode the payload so it bypasses the filter while maintaining its original goal. Use techniques like Base64 encoding, hexadecimal, string splitting, or alternative binaries (e.g., using 'awk' or 'php' instead of 'python').
        3. Provide 2 alternative tuned payloads.

        Strictly return JSON:
        {
            "obfuscation_technique": "Name of the evasion technique used",
            "tuned_payload": "The exact modified command to execute",
            "reasoning": "Why this specific payload will bypass the described filter",
            "alternatives": [
                { "technique": "...", "tuned_payload": "...", "description": "..." }
            ]
        }`;

        const aiResponse = await model.generateContent(chameleonPrompt);
        const aiDecision = JSON.parse(aiResponse.response.text());

        console.log(`[🦎] Chameleon applied technique: ${aiDecision.obfuscation_technique}`);
        console.log(`[✨] Tuned Payload: ${aiDecision.tuned_payload}`);

        return {
            agent: "Chameleon",
            target: targetInfo,
            evasion_plan: aiDecision,
            next_action: "Execute the 'tuned_payload'. If it succeeds, the filter is bypassed. If not, feed the new error back to Chameleon."
        };

    } catch (error) {
        console.error('[-] Chameleon Agent error:', error.message);
        return null;
    }
};

// ==========================================
// Project RedSwarm: Overlord Agent (The Supervisor)
// ==========================================
const runOverlordAgent = async(targetInfo, allAgentsData) => {
    console.log(`\n[👑] Waking up The Overlord (Supreme Supervisor) to analyze all data for: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash", generationConfig: { responseMimeType: "application/json" } });

        const overlordPrompt = `You are 'The Overlord', the supreme strategic commander of Project RedSwarm.
        Target: ${targetInfo}
        Combined Intelligence from all previous agents (Scout, Breacher, Phantom, etc.):
        ${allAgentsData}

        Your task:
        1. Analyze all the findings together. Cross-reference the open ports, vulnerabilities, and failed/successful payloads.
        2. Identify the ultimate critical path (What is the highest impact vulnerability?).
        3. Issue a direct, high-level strategic order for the next phase.

        Strictly return JSON:
        {
            "global_analysis": "Your supreme analysis of the entire situation",
            "critical_vulnerability": "The most dangerous flaw found across all reports",
            "strategic_order": "What the team MUST focus on next",
            "ready_for_report": true/false (Set to true if we have enough data to generate the final pentest report)
        }`;

        const aiResponse = await model.generateContent(overlordPrompt);
        return JSON.parse(aiResponse.response.text());
    } catch (error) {
        console.error('[-] Overlord Agent error:', error.message);
        return null;
    }
};

// ==========================================
// Project RedSwarm: Scribe Agent (The Reporter)
// ==========================================
const runScribeAgent = async(targetInfo, campaignHistory) => {
    console.log(`\n[📝] Waking up Scribe (Reporting Agent) to write final report for: ${targetInfo}...`);

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        // هنا مش هنطلب JSON، هنخليه يكتب Markdown عشان التقرير يكون مقروء للعميل
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

        const scribePrompt = `You are 'Scribe', the elite reporting agent for Project RedSwarm.
        Write a highly professional Red Team / Penetration Testing Executive Summary and Technical Report.
        Target Device/IP: ${targetInfo}
        Campaign History & Data: ${campaignHistory}

        The report MUST include:
        1. Executive Summary (High-level business impact).
        2. Discovered Vulnerabilities (Severity, CVEs if applicable).
        3. Attack Narrative (How we got in step-by-step).
        4. Remediation / Mitigation steps (How to fix the device).
        
        Format strictly in Professional Markdown.`;

        const aiResponse = await model.generateContent(scribePrompt);
        return aiResponse.response.text(); // ده هيرجع نص جاهز يتبعت PDF أو يتعرض
    } catch (error) {
        console.error('[-] Scribe Agent error:', error.message);
        return null;
    }
};

module.exports = {
    analyzeWithVertexAI,
    analyzeWithLocalModel,
    orchestrateRedSwarm,
    runScoutAgent,
    runBreacherAgent,
    runPhantomAgent,
    runChameleonAgent,
    runOverlordAgent,
    runScribeAgent
};