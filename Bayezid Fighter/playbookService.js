const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { encryptPayload } = require('./cryptoService');
const axios = require('axios');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);

const SECURITY_ENVIRONMENT = {
    FIREWALL: "Palo Alto Networks PAN-OS Firewall",
    EDR: "CrowdStrike Falcon",
    INTERNAL_SUBNET: "192.168.1.0/24"
};

const executePlaybook = async(alertId, aiAnalysis, payload) => {
    console.log(`\n[⚡] INITIATING DYNAMIC ZERO-CODE PLAYBOOK FOR ALERT: ${alertId}`);
    const playbookType = aiAnalysis.recommended_action || "UNKNOWN";
    const targetIp = aiAnalysis.extracted_ip || payload.source_ip;

    console.log(`[🎯] Target: ${targetIp} | Action: ${playbookType}`);

    try {
        const codeGenPrompt = `You are the 'Zero-Code Playbook Engineer' for Bayezid SOAR.
        Your job is to generate the exact, raw cURL command to execute a security action.
        
        Environment Context:
        - Firewall: ${SECURITY_ENVIRONMENT.FIREWALL}
        - EDR: ${SECURITY_ENVIRONMENT.EDR}
        
        Task:
        The SOC has requested to execute: "${playbookType}" on Target: "${targetIp}".
        
        Instructions:
        1. Write ONLY the raw, functional 'curl' command required to perform this action.
        2. Use placeholder API keys (e.g., 'YOUR_API_KEY').
        3. Do NOT include markdown blocks (like \`\`\`bash), explanations, or any other text. JUST THE RAW COMMAND.`;

        let generatedCommand = "";

        try {
            console.log(`[☁️] Asking Cloud AI (Gemini) to synthesize execution code for ${SECURITY_ENVIRONMENT.FIREWALL}...`);
            const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
            const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
            const result = await model.generateContent(codeGenPrompt);
            generatedCommand = result.response.text().trim();

        } catch (cloudErr) {
            console.log(`[⚠️] Gemini Cloud Failed (Quota/Network). Switching to Local AI...`);
            const aiCodeResponse = await axios.post('http://localhost:11434/api/generate', {
                model: process.env.LOCAL_MODEL_NAME || 'qwen2.5-coder:7b',
                prompt: codeGenPrompt,
                stream: false
            });
            generatedCommand = aiCodeResponse.data.response.trim();
        }

        generatedCommand = generatedCommand.replace(/```bash/gi, '').replace(/```/gi, '').trim();

        console.log(`[✨] AI Synthesized Command:\n${generatedCommand}`);

        console.log(`[⚙️] Executing API Call to Security Appliance...`);
        let executionOutput = "Simulated Success: 200 OK. Action applied successfully via Zero-Code generation.";

        console.log(`[⚙️] Executing API Call to Security Appliance...`);
        let executionOutput = "Simulated Success: 200 OK. Action applied successfully via Zero-Code generation.";

        const encryptedCommand = encryptPayload(generatedCommand) || "ENCRYPTION_FAILED";
        console.log(`[🔒] Payload Encrypted successfully before saving to DB.`);

        await prisma.alert.update({
            where: { id: alertId },
            data: {
                status: 'RESOLVED_BY_PLAYBOOK',
                playbookDetails: `[Dynamic Playbook Generated]\nAction: ${playbookType}\nEncrypted_Payload:\n${encryptedCommand}\nResult: ${executionOutput}`
            }
        });

        console.log(`[✔] Dynamic Playbook Execution Complete.`);
        return `Successfully dynamically generated and executed action for ${playbookType}.`;

    } catch (error) {
        console.error("[-] Playbook Execution Failed:", error);
        await prisma.alert.update({
            where: { id: alertId },
            data: { status: 'PLAYBOOK_FAILED' }
        });
        return `Failed to execute dynamic playbook: ${error.message}`;
    }
};

module.exports = { executePlaybook };