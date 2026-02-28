const express = require('express');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const path = require('path');

// استدعاء كل المحركات والخدمات
const { analyzeWithVertexAI, analyzeWithLocalModel } = require('./aiService');
const { executePlaybook } = require('./playbookService');
const { enrichWithOSINT } = require('./osintService');
const { sendTelegramAlert } = require('./notificationService');
const { loadMitreDatabase } = require('./ragService');

dotenv.config();

const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.use(express.text());

// --- [ 🖥️ تشغيل الـ Web Dashboard ] ---
app.use(express.static(path.join(__dirname, 'public')));

// --- [ 📊 Endpoint للداشبورد عشان تسحب الأحداث لايف (History) ] ---
app.get('/api/v1/alerts', async(req, res) => {
    try {
        const alerts = await prisma.alert.findMany({
            orderBy: { createdAt: 'desc' },
            take: 50
        });
        res.json({ status: 'success', data: alerts });
    } catch (error) {
        console.error("[-] Dashboard API Error:", error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch alerts' });
    }
});

// --- [ 🛡️ معالجة الهجمات ] ---
const handleSecurityAlert = async(req, res) => {
    let source_ip, event_type, target_server;
    let rawData = req.body;

    let requested_engine = process.env.AI_MODE || 'LOCAL';
    const isJson = req.headers['content-type'] === 'application/json';

    if (isJson) {
        source_ip = req.body.source_ip;
        event_type = req.body.event_type || "Security Alert";
        target_server = req.body.target_server || "Unknown";

        if (req.body.engine) {
            requested_engine = req.body.engine.toUpperCase();
        }
        console.log(`\n[+] Received Structured Alert: ${event_type} from ${source_ip}`);
        console.log(`[🎛️] Engine Selected: ${requested_engine}`);

    } else {
        const logPreview = typeof rawData === 'string' ? rawData.substring(0, 50) : 'Invalid Format';
        console.log(`\n[+] Received Raw Log Data: ${logPreview}...`);
        source_ip = "Extracting...";
        event_type = "Raw Log Analysis";
        target_server = "Detecting...";

        if (req.query.engine) {
            requested_engine = req.query.engine.toUpperCase();
            console.log(`[🎛️] Engine Selected by URL: ${requested_engine}`);
        }
    }

    try {
        if (isJson && source_ip !== "Extracting...") {
            const recentAnalysis = await prisma.alert.findFirst({
                where: {
                    sourceIp: source_ip,
                    status: { in: ["ANALYZED", "FALSE_POSITIVE"] },
                    createdAt: { gte: new Date(Date.now() - 10 * 60 * 1000) }
                },
                orderBy: { createdAt: 'desc' }
            });

            if (recentAnalysis) {
                console.log(`[⚡] Cache Hit! Reusing recent analysis for ${source_ip}`);
                return res.status(200).json({
                    status: 'success',
                    cached: true,
                    is_false_positive: recentAnalysis.status === "FALSE_POSITIVE",
                    analysis: {
                        severity: recentAnalysis.severity,
                        threat_type: recentAnalysis.threatType,
                        recommended_action: recentAnalysis.recommendedAction,
                        cvss_score: recentAnalysis.cvssScore,
                        cwe_id: recentAnalysis.cweId,
                        mitre_attack: { tactic: recentAnalysis.mitreTactic, technique: recentAnalysis.mitreTechnique },
                        kill_chain_phase: recentAnalysis.killChainPhase,
                        predicted_next_steps: recentAnalysis.predictedSteps,
                        business_continuity_analysis: recentAnalysis.businessContinuity,
                        engine_used: 'Semantic Cache (Fast Path ⚡)'
                    },
                    osint: recentAnalysis.osintData ? recentAnalysis.osintData : null,
                    playbook_executed: false,
                    playbook_details: "Skipped (Action already taken in previous alert)"
                });
            }
        }

        const savedAlert = await prisma.alert.create({
            data: { sourceIp: source_ip, targetServer: target_server, eventType: event_type, status: "NEW" }
        });
        console.log(`[*] Logged to Cloud DB (ID: ${savedAlert.id})`);

        let osintData = null;
        if (isJson && source_ip !== "Extracting...") {
            osintData = await enrichWithOSINT(source_ip);
        }

        const payloadForAI = isJson ? req.body : rawData;
        let aiResponse;

        if (requested_engine === 'CLOUD' || requested_engine === 'VERTEX' || requested_engine === 'GEMINI') {
            console.log(`[🚀] Primary Engine Route: CLOUD AI`);
            aiResponse = await analyzeWithVertexAI(payloadForAI);

            if (aiResponse.engine_used.includes('Fail-safe')) {
                console.log('\n[🚨] CLOUD DOWN! Auto-switching to Local AI (Standby Mode)...');
                aiResponse = await analyzeWithLocalModel(payloadForAI);
                aiResponse.engine_used += ' (Recovered from Cloud Failure 🔁)';
            }
        } else {
            console.log(`[🚀] Primary Engine Route: LOCAL AI`);
            aiResponse = await analyzeWithLocalModel(payloadForAI);

            if (aiResponse.engine_used.includes('Fail-safe')) {
                console.log('\n[🚨] LOCAL DOWN! Auto-switching to Cloud AI (Standby Mode)...');
                aiResponse = await analyzeWithVertexAI(payloadForAI);
                aiResponse.engine_used += ' (Recovered from Local Failure 🔁)';
            }
        }

        if (!isJson && aiResponse.extracted_ip && aiResponse.extracted_ip !== "Unknown" && aiResponse.extracted_ip !== "Extracting...") {
            osintData = await enrichWithOSINT(aiResponse.extracted_ip);
        }

        const updatedAlert = await prisma.alert.update({
            where: { id: savedAlert.id },
            data: {
                sourceIp: aiResponse.extracted_ip || source_ip,
                severity: aiResponse.severity,
                threatType: aiResponse.threat_type,
                recommendedAction: aiResponse.recommended_action,
                cvssScore: aiResponse.cvss_score,
                cweId: aiResponse.cwe_id,
                mitreTactic: aiResponse.mitre_attack ? aiResponse.mitre_attack.tactic : null,
                mitreTechnique: aiResponse.mitre_attack ? aiResponse.mitre_attack.technique : null,
                killChainPhase: aiResponse.kill_chain_phase,
                predictedSteps: aiResponse.predicted_next_steps,
                businessContinuity: aiResponse.business_continuity_analysis,
                osintData: osintData,
                status: aiResponse.is_false_positive ? "FALSE_POSITIVE" : "ANALYZED"
            }
        });
        console.log(`[✔] Cognitive Analysis Saved: ${aiResponse.threat_type}`);

        let playbookResult = null;
        if (!aiResponse.is_false_positive && (aiResponse.severity === 'HIGH' || aiResponse.severity === 'CRITICAL')) {
            playbookResult = await executePlaybook(updatedAlert.id, aiResponse, isJson ? req.body : { source_ip: aiResponse.extracted_ip });
            sendTelegramAlert(aiResponse, osintData);
        } else {
            console.log(`[!] Playbook & Alert Skipped: ${aiResponse.is_false_positive ? "False Positive" : "Low Severity"}`);
        }

        return res.status(200).json({
            status: 'success',
            cached: false,
            is_false_positive: aiResponse.is_false_positive,
            confidence: aiResponse.confidence_score,
            analysis: aiResponse,
            osint: osintData,
            playbook_executed: !!playbookResult,
            playbook_details: playbookResult
        });

    } catch (error) {
        console.error('[-] Error processing alert:', error);
        return res.status(500).json({ status: 'error', message: 'Failed to process security data' });
    }
};

app.post('/api/v1/alerts/ingest', handleSecurityAlert);

// --- [ 🎯 Endpoint جديد للـ Simulation ] ---
const handleSimulationRun = async(req, res) => {
    const { attackType, logFormat, logData, parameters } = req.body;

    console.log(`\n[🧪] Received Simulation Request: ${attackType}`);

    try {
        let parsedLogs;

        // معالجة نوع اللوجات (Raw أو JSON)
        if (logFormat === 'json') {
            try {
                parsedLogs = typeof logData === 'string' ? JSON.parse(logData) : logData;
            } catch (e) {
                return res.status(400).json({ error: 'Invalid JSON format in logData' });
            }
        } else if (logFormat === 'raw') {
            // تحويل الـ Raw logs لمصفوفة سطور
            parsedLogs = logData.split('\n').filter(line => line.trim() !== '');
        } else {
            return res.status(400).json({ error: 'Invalid log format selected' });
        }

        // حفظ محاولة السيميوليشن في الداتابيز عشان تظهر في الداشبورد
        const simulationAlert = await prisma.alert.create({
            data: {
                sourceIp: "SIMULATION-TEST",
                targetServer: "Local-Env",
                eventType: `Simulated: ${attackType}`,
                status: "ANALYZED",
                severity: "INFO", // ممكن تخليها ديناميك لو حابب
                threatType: "Simulation Activity",
                recommendedAction: "Review simulated logs and parameters",
                // حطينا البرامترز كداتا إضافية في حقل الـ osintData أو ممكن تخليها في حقل مخصص لو موجود
                osintData: parameters ? { custom_parameters: parameters } : null
            }
        });

        console.log(`[✔] Simulation Logged to DB (ID: ${simulationAlert.id})`);

        // الرد على الفرونت إند بنجاح العملية
        res.status(200).json({
            status: 'success',
            message: 'Simulation executed and logged successfully',
            data: {
                attackType,
                parsedLogs,
                recordId: simulationAlert.id
            }
        });

    } catch (error) {
        console.error('[-] Simulation Error:', error);
        res.status(500).json({ error: 'Simulation processing failed' });
    }
};

// ربط الفانكشن بالـ Route الخاص بيها
app.post('/api/v1/simulation/run', handleSimulationRun);


const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, async() => {
    console.log(`=================================`);
    console.log(`[+] Bayezid Cognitive SOAR V2 LIVE`);
    console.log(`[+] Dual-Engine Ready (Local/Cloud) 🔀`);
    console.log(`[+] High Availability (Auto-Failover) Active 🛡️`);
    console.log(`[+] Mobile SOC (Telegram): CONNECTED 📱`);
    console.log(`[+] Web Dashboard Running on http://localhost:${PORT} 🖥️`);
    console.log(`=================================`);

    await loadMitreDatabase();
});

server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`\n[!] ERROR: Port ${PORT} is currently in use! (A Zombie server is running).`);
        console.error(`[!] Please close the old server or run: npx kill-port ${PORT}\n`);
    } else {
        console.error('\n[-] Server Crash:', error.message);
    }
});