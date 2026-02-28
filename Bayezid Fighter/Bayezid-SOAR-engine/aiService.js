const axios = require('axios');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { enrichContext } = require('./ragService'); // محرك الـ Hybrid RAG
require('dotenv').config();

// ============================================================================
// 🛡️ دالة التعقيم العميقة (Deep Data Sanitizer)
// بتلف جوه الـ JSON بالكامل وتصلح أي هلوسة في أي مستوى
// ============================================================================
const deepSanitize = (obj) => {
    if (typeof obj !== 'object' || obj === null) return;
    for (let key in obj) {
        // لو لقى أي مصفوفة في أي مفتاح يخص الـ Action، يدمجها فوراً
        if (key.toLowerCase().includes('recommend') && Array.isArray(obj[key])) {
            obj[key] = obj[key].join('\n');
        }
        // لو لقى أي مفتاح يخص الـ CVSS، يحوله لنص إجباري
        if (key.toLowerCase().includes('cvss')) {
            obj[key] = String(obj[key]);
        }
        // لو الموديل عامل Nested Object، الدالة تدخل تعقمه من جوه
        if (typeof obj[key] === 'object') {
            deepSanitize(obj[key]);
        }
    }
    return obj;
};

// ============================================================================
// ☁️ 1. محرك الكلاود المدعوم بالاستخبارات (Google Gemini 2.5 Flash + RAG)
// ============================================================================
const analyzeWithVertexAI = async(alertData) => {
    console.log('\n[☁️] Sending Data to Cloud AI (Google Gemini 2.5 Flash)...');

    try {
        const safeDataString = typeof alertData === 'string' ? alertData : JSON.stringify(alertData);
        const injectedContext = await enrichContext(safeDataString);

        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

        const systemPrompt = `You are an Elite Cloud-Based Cybersecurity SIEM Correlation Engine.
        
        [THREAT INTELLIGENCE CONTEXT]
        ${injectedContext}

        Analyze the security data using the provided threat intelligence context.
        You MUST respond ONLY with a valid JSON object matching this exact format, with NO markdown formatting, NO \`\`\`json tags, and NO extra text:
        {
            "is_false_positive": false,
            "confidence_score": "e.g., 99%",
            "extracted_ip": "Primary source IP",
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
        let text = result.response.text();

        text = text.replace(/```json/gi, '').replace(/```/gi, '').trim();
        let aiResponse = JSON.parse(text);

        // تفعيل درع الحماية العميق
        aiResponse = deepSanitize(aiResponse);

        return {
            ...aiResponse,
            engine_used: 'Google Gemini 2.5 Flash + Hybrid RAG (Cloud ☁️)'
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

// ============================================================================
// 🏠🔥 2. محرك اللوكال الصاروخي (Single-Model Multi-Role: Qwen 2.5 + Deep RAG)
// ============================================================================
const analyzeWithLocalModel = async(alertData) => {
    console.log('\n[🏠] Initiating High-Speed Local Architecture (Powered by Qwen 2.5)...');
    const safeDataString = typeof alertData === 'string' ? alertData : JSON.stringify(alertData);

    // سحب الاستخبارات 
    const injectedContext = await enrichContext(safeDataString);
    console.log(`[📚] Hybrid Intel Injected.`);

    try {
        // --- 🕵️‍♂️ الدور الأول (المحقق - Qwen 2.5 Coder) ---
        console.log(`\n[🕵️‍♂️] Role 1 (Detective) is extracting artifacts...`);
        const detectivePrompt = `You are a Lead Cyber Forensic Investigator. Read the following security event and extract ALL technical artifacts.
        Event Data: ${safeDataString}
        Task: Extract a detailed list of:
        - All IP addresses and ports.
        - Specific vulnerabilities (CVEs) and their exact nature.
        - Specific processes, binaries, and privileges mentioned (e.g., SeDebugPrivilege).
        Be highly technical and precise.`;

        const detectiveResponse = await axios.post('http://localhost:11434/api/generate', {
            model: 'qwen2.5-coder:7b',
            prompt: detectivePrompt,
            stream: false
        });
        const extractedFacts = detectiveResponse.data.response;
        console.log(`[✔] Detective Extracted Facts successfully.`);

        // --- 🎖️ الدور الثاني (الجنرال - Qwen 2.5 Coder) ---
        console.log(`\n[🎖️] Role 2 (Commander) is formulating the Strategic JSON Report...`);
        const commanderPrompt = `You are an Elite Tier 3 Cybersecurity Incident Commander.
        
        [THREAT INTELLIGENCE CONTEXT]
        ${injectedContext}

        [FORENSIC DETECTIVE'S ARTIFACTS]
        ${extractedFacts}

        [STRICT ANALYSIS FRAMEWORK]:
        1. Deep Narrative: Write a comprehensive, multi-sentence story in 'detailed_report' explaining HOW the attack happened using the artifacts.
        2. Strict JSON Formatting: Your 'cvss_score' MUST be exactly a string like "9.8". NO extra characters.
        3. Strategic Action: Provide EXACTLY 6 to 8 numbered steps in 'recommended_action' as a single string, NOT an array. 
        4. Accuracy: Use the provided Threat Intel for CWE and MITRE IDs.

        You MUST respond ONLY with a valid JSON object matching this exact format, NO markdown:
        {
            "is_false_positive": false,
            "confidence_score": "99%",
            "extracted_ip": "IP address",
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

        // تفعيل درع الحماية العميق
        finalReport = deepSanitize(finalReport);

        return {
            ...finalReport,
            engine_used: `High-Speed Local (Qwen 2.5 Multi-Role) + Hybrid RAG ⚡🏠`
        };

    } catch (error) {
        console.error('[-] Multi-Role AI Error:', error.message);
        return { severity: 'HIGH', threat_type: 'Local AI Offline Fallback', recommended_action: 'Manual Investigation', engine_used: 'Fail-safe' };
    }
};

module.exports = {
    analyzeWithVertexAI,
    analyzeWithLocalModel
};