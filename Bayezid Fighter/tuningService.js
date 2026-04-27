const { GoogleGenerativeAI } = require('@google/generative-ai');
const { PrismaClient } = require('@prisma/client');
const axios = require('axios');
const prisma = new PrismaClient();

require('dotenv').config();

let liveConfig = {
    SLA_TIMEOUT_MINUTES: 1,
    AI_ENGINE: "CLOUD",
    FEATURES: {
        AUTO_ESCALATION: true,
        TELEGRAM_NOTIFICATIONS: true
    }
};

const processTuningCommand = async(userCommand, userRole) => {
    console.log(`\n[🧠] Tuning Request received from: ${userRole}`);

    if (userRole !== 'SOC_MANAGER') {
        return { action: "REJECTED", reply: "ma3lsh ya handasa da sho8l elqyadh el3ozmh bs" };
    }

    const tuningPrompt = `You are the 'System Developer Agent' for Bayezid SOAR. 
    Current State: ${JSON.stringify(liveConfig)}
    Command: "${userCommand}"
    
    Task: Output JSON to update SLA_TIMEOUT_MINUTES, AI_ENGINE, or FEATURES.
    Format: { "action": "UPDATE_CONFIG"|"TOGGLE_FEATURE", "target": "key", "value": "val", "reply": "msg" }`;

    try {
        console.log(`[☁️] Attempting Cloud Tuning (Gemini 1.5 Flash)...`);
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-1.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const response = await model.generateContent(tuningPrompt);
        const plan = JSON.parse(response.response.text());

        return await executePlan(plan);

    } catch (cloudError) {
        console.warn(`\n[⚠️] Cloud Tuning Failed (Quota/Network). Switching to Local AI...`);

        try {
            const localResponse = await axios.post('http://localhost:11434/api/generate', {
                model: process.env.LOCAL_MODEL_NAME || "qwen2.5-coder:7b",
                prompt: tuningPrompt + "\n\nCRITICAL: Return ONLY valid JSON.",
                stream: false,
                format: "json"
            });

            const plan = JSON.parse(localResponse.data.response);
            return await executePlan(plan);

        } catch (localError) {
            console.error(`[❌] Total System Blindness: Both AI engines failed.`);
            return { action: "ERROR", reply: "The system is currently unable to achieve any artificial intelligence." };
        }
    }
};

const executePlan = async(plan) => {
    if (plan.action === "UPDATE_CONFIG") {
        liveConfig[plan.target] = Number(plan.value) || plan.value;
    } else if (plan.action === "TOGGLE_FEATURE") {
        liveConfig.FEATURES[plan.target] = plan.value;
    }

    try {
        await prisma.systemConfig.upsert({
            where: { key: plan.target },
            update: { value: String(plan.value) },
            create: { key: plan.target, value: String(plan.value) }
        });
        console.log(`[💾] Config persisted to DB: ${plan.target} = ${plan.value}`);
    } catch (dbError) {
        console.error("[-] DB Save Error:", dbError.message);
    }

    console.log(`[✔] LIVE UPDATE SUCCESS:`, liveConfig);
    return plan;
};

module.exports = { processTuningCommand, liveConfig };