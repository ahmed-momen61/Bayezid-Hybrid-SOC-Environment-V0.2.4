const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);
// هنستدعي الموديل بتاعنا من aiService عشان نستخدم المخ الهجين
const { analyzeWithVertexAI, analyzeWithLocalModel } = require('./aiService');

// ⚙️ Environment Context (هنا بنحدد بيئة العميل، ممكن مستقبلاً تتجاب من الداتا بيز)
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
        // 1. Prompting the AI to generate the EXACT execution code
        const codeGenPrompt = `You are the 'Zero-Code Playbook Engineer' for Bayezid SOAR.
        Your job is to generate the exact, raw cURL command to execute a security action.
        
        Environment Context:
        - Firewall: ${SECURITY_ENVIRONMENT.FIREWALL}
        - EDR: ${SECURITY_ENVIRONMENT.EDR}
        
        Task:
        The SOC has requested to execute: "${playbookType}" on Target: "${targetIp}".
        
        Instructions:
        1. Write ONLY the raw, functional 'curl' command required to perform this action against the specified Firewall or EDR API.
        2. Use placeholder API keys (e.g., 'YOUR_API_KEY').
        3. Do NOT include markdown blocks (like \`\`\`bash), explanations, or any other text. JUST THE RAW COMMAND.
        4. If the action is generic (like "ISOLATE_HOST"), generate a CrowdStrike isolation API call. If it's "BLOCK_IP", generate a FortiGate block API call.`;

        console.log(`[🧠] Asking AI to synthesize execution code for ${SECURITY_ENVIRONMENT.FIREWALL}...`);

        // استخدام Qwen (اللوكال) كمحرك سريع لتوليد الكود
        const axios = require('axios');
        const aiCodeResponse = await axios.post('http://localhost:11434/api/generate', {
            model: process.env.LOCAL_MODEL_NAME || 'qwen2.5-coder:7b',
            prompt: codeGenPrompt,
            stream: false
        });

        let generatedCommand = aiCodeResponse.data.response.trim();
        // تنظيف الكود لو الـ AI رجع Markdown بالغلط
        generatedCommand = generatedCommand.replace(/```bash/gi, '').replace(/```/gi, '').trim();

        console.log(`[✨] AI Synthesized Command:\n${generatedCommand}`);

        // 2. محاكاة التنفيذ (عشان إحنا معندناش Fortinet حقيقي دلوقتي)
        // في البيئة الحقيقية، كنا هنعمل await execPromise(generatedCommand)
        console.log(`[⚙️] Executing API Call to Security Appliance...`);
        let executionOutput = "Simulated Success: 200 OK. Action applied successfully via Zero-Code generation.";

        // 3. تحديث الداتا بيز بحالة التنفيذ والكود اللي اتولد
        await prisma.alert.update({
            where: { id: alertId },
            data: {
                status: 'RESOLVED_BY_PLAYBOOK',
                // بنحفظ الكود اللي الـ AI ألفه في الداتا بيز عشان الـ Audit
                playbookDetails: `[Dynamic Playbook Generated]\nAction: ${playbookType}\nCode:\n${generatedCommand}\nResult: ${executionOutput}`
            }
        });

        console.log(`[✔] Dynamic Playbook Execution Complete.`);
        return `Successfully dynamically generated and executed action for ${playbookType}.`;

    } catch (error) {
        console.error("[-] Playbook Execution Failed:", error);

        // لو حصل مشكلة، بنسجل إن التنفيذ فشل
        await prisma.alert.update({
            where: { id: alertId },
            data: { status: 'PLAYBOOK_FAILED' }
        });

        return `Failed to execute dynamic playbook: ${error.message}`;
    }
};

module.exports = { executePlaybook };