const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const systemState = {
    configs: { sla_timeout_minutes: 10, default_engine: "LOCAL" },
    features: { auto_escalation: true, telegram_alerts: true },
    prompts: { local_commander_prompt: "You are an Elite Tier 3 Commander..." }
};

const tuneSystem = async(userCommand, userRole) => {
    console.log(`\n=========================================`);
    console.log(`[👤] User Role: ${userRole || 'UNKNOWN'}`);
    console.log(`[🗣️] Command: "${userCommand}"`);

    if (userRole !== 'SOC_MANAGER') {
        console.log(`[❌] ACCESS DENIED: Only SOC Managers can modify system configurations.`);
        return { action_type: "UNAUTHORIZED" };
    }

    try {
        const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({
            model: "gemini-1.5-flash",
            generationConfig: { responseMimeType: "application/json" }
        });

        const prompt = `You are the 'System Developer Agent' for the Bayezid SOAR.
        
        CRITICAL RULES:
        1. FORBIDDEN: You CANNOT modify Firewalls, Wazuh rules, Databases, Playbooks, or IP Whitelists. If requested, reject it.
        2. ALLOWED: You can ONLY modify system behavior:
           - 'UPDATE_CONFIG': Change variables like SLA timeouts or default AI engines.
           - 'TOGGLE_FEATURE': Enable or disable features (e.g., auto_escalation, telegram_alerts).
           - 'UPDATE_PROMPT': Modify system AI prompts used by the analytical engines.
        3. LANGUAGE: The user command might be in English, Arabic, or Franco-Arabic.

        User Command: "${userCommand}"

        Output ONLY a valid JSON object matching this schema:
        {
            "action_type": "UPDATE_CONFIG" | "TOGGLE_FEATURE" | "UPDATE_PROMPT" | "FORBIDDEN" | "UNKNOWN",
            "target_key": "The exact name of the config/feature/prompt being changed",
            "new_value": "The new value (boolean for features, number/string for configs/prompts)",
            "reasoning": "Brief explanation of your understanding",
            "reply_message": "A friendly confirmation message replying in the EXACT SAME LANGUAGE the user used."
        }`;

        const result = await model.generateContent(prompt);
        const plan = JSON.parse(result.response.text());

        if (plan.action_type === "FORBIDDEN" || plan.action_type === "UNKNOWN") {
            console.log(`[⚠️] Action Rejected: ${plan.reasoning}`);
            console.log(`[💬] Agent Reply: ${plan.reply_message}`);
            return plan;
        }

        console.log(`[⚙️] Tuning Plan Executed: ${plan.action_type} -> [${plan.target_key}: ${plan.new_value}]`);

        if (plan.action_type === "UPDATE_CONFIG") systemState.configs[plan.target_key] = plan.new_value;
        if (plan.action_type === "TOGGLE_FEATURE") systemState.features[plan.target_key] = plan.new_value;
        if (plan.action_type === "UPDATE_PROMPT") systemState.prompts[plan.target_key] = plan.new_value;

        console.log(`[✔] System State Updated:`, JSON.stringify(systemState, null, 2));
        console.log(`[💬] Agent Reply: ${plan.reply_message}`);

        return plan;

    } catch (error) {
        console.error('[-] Tuning Error:', error.message);
    }
};

const runTests = async() => {
    await tuneSystem("ya bayezid e2fel feature el telegram alerts 3ashan betz3egna w e7na naymeen", "SOC_MANAGER");

    await tuneSystem("عدل البرومبت بتاع اللوكال كوماندر خليه يقول إنه جنرال عسكري حازم جداً ومبيهزرش", "SOC_MANAGER");

    await tuneSystem("Add IP 192.168.1.5 to the Firewall Whitelist immediately", "SOC_MANAGER");

    await tuneSystem("خلي وقت الطوارئ 5 دقايق", "SOC_ANALYST_L1");
};

runTests();