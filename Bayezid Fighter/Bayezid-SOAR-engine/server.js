const express = require('express');
const readline = require('readline');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const path = require('path');

const { analyzeWithVertexAI, analyzeWithLocalModel, orchestrateRedSwarm, runScoutAgent, runBreacherAgent, runPhantomAgent, runChameleonAgent, runOverlordAgent, runScribeAgent } = require('./aiService');
const { executePlaybook } = require('./playbookService');
const { enrichWithOSINT } = require('./osintService');
const { sendTelegramAlert } = require('./notificationService');
const { loadMitreDatabase } = require('./ragService');
const { enrichWithCTI } = require('./ctiService');

dotenv.config();

const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.use(express.text());

app.use(express.static(path.join(__dirname, 'public')));

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

        let ctiData = null;
        if (aiResponse.extracted_iocs || (aiResponse.related_cves && aiResponse.related_cves.length > 0)) {
            ctiData = await enrichWithCTI(aiResponse.extracted_iocs, aiResponse.related_cves);
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
                osintData: {
                    osint: osintData,
                    cti: ctiData
                },
                status: aiResponse.is_false_positive ? "FALSE_POSITIVE" : "ANALYZED"
            }
        });
        console.log(`[✔] Cognitive Analysis & CTI Saved: ${aiResponse.threat_type}`);

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
            cti: ctiData,
            playbook_executed: !!playbookResult,
            playbook_details: playbookResult
        });

    } catch (error) {
        console.error('[-] Error processing alert:', error);
        return res.status(500).json({ status: 'error', message: 'Failed to process security data' });
    }
};

app.post('/api/v1/alerts/ingest', handleSecurityAlert);

const handleSimulationRun = async(req, res) => {
    const { attackType, logFormat, logData, parameters } = req.body;

    console.log(`\n[🧪] Received Simulation Request: ${attackType}`);

    try {
        let parsedLogs;

        if (logFormat === 'json') {
            try {
                parsedLogs = typeof logData === 'string' ? JSON.parse(logData) : logData;
            } catch (e) {
                return res.status(400).json({ error: 'Invalid JSON format in logData' });
            }
        } else if (logFormat === 'raw') {
            parsedLogs = logData.split('\n').filter(line => line.trim() !== '');
        } else {
            return res.status(400).json({ error: 'Invalid log format selected' });
        }

        const simulationAlert = await prisma.alert.create({
            data: {
                sourceIp: "SIMULATION-TEST",
                targetServer: "Local-Env",
                eventType: `Simulated: ${attackType}`,
                status: "ANALYZED",
                severity: "INFO",
                threatType: "Simulation Activity",
                recommendedAction: "Review simulated logs and parameters",
                osintData: parameters ? { custom_parameters: parameters } : null
            }
        });

        console.log(`[✔] Simulation Logged to DB (ID: ${simulationAlert.id})`);

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

app.post('/api/v1/simulation/run', handleSimulationRun);
// ==========================================
// REDSWARM OFFENSIVE API ROUTE
// ==========================================
app.post('/api/v1/redswarm/engage', async(req, res) => {
    const { targetInfo, currentState } = req.body;

    if (!targetInfo) {
        return res.status(400).json({ error: 'Missing targetInfo in request body' });
    }

    console.log(`\n[🔥] RedSwarm Engagement Requested! Target: ${targetInfo}`);

    try {
        const state = currentState || "Starting new engagement. Need initial reconnaissance.";
        const decision = await orchestrateRedSwarm(targetInfo, state);

        if (decision) {
            res.status(200).json({
                status: 'success',
                message: 'The Brain has evaluated the target and assigned a task.',
                data: decision
            });
        } else {
            res.status(500).json({ status: 'error', message: 'The Brain failed to generate a strategy.' });
        }
    } catch (error) {
        console.error('[-] RedSwarm API Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error during orchestration.' });
    }
});

// ==========================================
// REDSWARM: SCOUT AGENT API
// ==========================================
app.post('/api/v1/redswarm/scout', async(req, res) => {
    const { targetInfo, customInstructions } = req.body;

    if (!targetInfo) {
        return res.status(400).json({ error: 'Missing targetInfo in request body' });
    }

    console.log(`\n[🔍] Deploying Scout to scan: ${targetInfo}`);
    if (customInstructions) console.log(`[🗣️] User Instruction provided: ${customInstructions}`);

    try {
        const result = await runScoutAgent(targetInfo, customInstructions);

        if (result) {
            res.status(200).json({
                status: 'success',
                message: 'Scout has completed the reconnaissance mission.',
                data: result
            });
        } else {
            res.status(500).json({ status: 'error', message: 'Scout failed to execute.' });
        }
    } catch (error) {
        console.error('[-] Scout API Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error during scan.' });
    }
});

// ==========================================
// REDSWARM: BREACHER AGENT API
// ==========================================
app.post('/api/v1/redswarm/breach', async(req, res) => {
    const { targetInfo, scanResults, customInstructions } = req.body;

    if (!targetInfo || !scanResults) {
        return res.status(400).json({ error: 'Missing targetInfo or scanResults in request body' });
    }

    console.log(`\n[⚔️] Deploying Breacher against: ${targetInfo}`);

    try {
        const result = await runBreacherAgent(targetInfo, scanResults, customInstructions);

        if (result) {
            res.status(200).json({
                status: 'success',
                message: 'Breacher has formulated the attack plan.',
                data: result
            });
        } else {
            res.status(500).json({ status: 'error', message: 'Breacher failed to formulate a plan.' });
        }
    } catch (error) {
        console.error('[-] Breacher API Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error during breach planning.' });
    }
});

// ==========================================
// REDSWARM: PHANTOM AGENT API
// ==========================================
app.post('/api/v1/redswarm/phantom', async(req, res) => {
    const { targetInfo, shellContext, customInstructions } = req.body;

    if (!targetInfo || !shellContext) {
        return res.status(400).json({ error: 'Missing targetInfo or shellContext in request body' });
    }

    console.log(`\n[👻] Deploying Phantom for privilege escalation on: ${targetInfo}`);

    try {
        const result = await runPhantomAgent(targetInfo, shellContext, customInstructions);

        if (result) {
            res.status(200).json({
                status: 'success',
                message: 'Phantom has generated the escalation payloads.',
                data: result
            });
        } else {
            res.status(500).json({ status: 'error', message: 'Phantom failed to generate payloads.' });
        }
    } catch (error) {
        console.error('[-] Phantom API Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error during escalation planning.' });
    }
});

// ==========================================
// REDSWARM: CHAMELEON AGENT API
// ==========================================
app.post('/api/v1/redswarm/chameleon', async(req, res) => {
    const { targetInfo, failedPayload, wafContext, customInstructions } = req.body;

    if (!targetInfo || !failedPayload || !wafContext) {
        return res.status(400).json({ error: 'Missing targetInfo, failedPayload, or wafContext in request body' });
    }

    console.log(`\n[🦎] Deploying Chameleon to bypass WAF for: ${targetInfo}`);

    try {
        const result = await runChameleonAgent(targetInfo, failedPayload, wafContext, customInstructions);

        if (result) {
            res.status(200).json({
                status: 'success',
                message: 'Chameleon has successfully tuned the payload.',
                data: result
            });
        } else {
            res.status(500).json({ status: 'error', message: 'Chameleon failed to tune the payload.' });
        }
    } catch (error) {
        console.error('[-] Chameleon API Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error during payload tuning.' });
    }
});

// ==========================================
// REDSWARM: OVERLORD & SCRIBE APIs
// ==========================================
app.post('/api/v1/redswarm/overlord', async(req, res) => {
    const { targetInfo, allAgentsData } = req.body;
    if (!targetInfo || !allAgentsData) return res.status(400).json({ error: 'Missing data' });

    console.log(`\n[👑] Overlord requested for: ${targetInfo}`);
    try {
        const result = await runOverlordAgent(targetInfo, allAgentsData);
        res.status(200).json({ status: 'success', data: result });
    } catch (error) {
        console.error('[-] Overlord API Crash:', error); // ضفنا دي
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.post('/api/v1/redswarm/scribe', async(req, res) => {
    const { targetInfo, campaignHistory } = req.body;
    if (!targetInfo || !campaignHistory) return res.status(400).json({ error: 'Missing data' });

    console.log(`\n[📝] Scribe is generating final report for: ${targetInfo}`);
    try {
        const report = await runScribeAgent(targetInfo, campaignHistory);
        res.status(200).json({ status: 'success', report_markdown: report });
    } catch (error) {
        console.error('[-] Overlord API Crash:', error); // ضفنا دي
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// ==========================================
// REDSWARM: THE AUTONOMOUS HEART 🦅
// ==========================================
app.post('/api/v1/redswarm/auto-pilot', async(req, res) => {
    const { targetInfo } = req.body;
    if (!targetInfo) return res.status(400).json({ error: 'Target IP is required' });

    console.log(`\n[🚀] INITIATING FULL AUTO-PILOT CAMPAIGN AGAINST: ${targetInfo}`);
    res.status(200).json({ status: 'success', message: 'Campaign started. Overlord is now in control.' });

    // الحلقة المستقلة
    (async() => {
        let campaignActive = true;
        let lastScanResults = "";

        while (campaignActive) {
            // 1. المايسترو يحلل الداتا بيز ويقرر الخطوة الجاية
            const decision = await runOverlordAgent(targetInfo);

            if (!decision || decision.is_operation_complete) {
                console.log(`[👑] Overlord: Operation Finished. Scribe is writing the report.`);
                await runScribeAgent(targetInfo);
                campaignActive = false;
                break;
            }

            console.log(`[👑] Overlord Order: Activate [${decision.next_agent}]`);

            // 2. تنفيذ الأوامر وتحديث الداتا بيز
            if (decision.next_agent === 'Scout') {
                const scoutData = await runScoutAgent(targetInfo, decision.detailed_instructions);
                lastScanResults = scoutData.scan_results;
            } else if (decision.next_agent === 'Breacher') {
                await runBreacherAgent(targetInfo, lastScanResults, decision.detailed_instructions);
            } else if (decision.next_agent === 'Phantom') {
                await runPhantomAgent(targetInfo, "Previous session logs in DB", decision.detailed_instructions);
            } else if (decision.next_agent === 'Chameleon') {
                await runChameleonAgent(targetInfo, "Failed payloads in DB", "WAF Bypass needed", decision.detailed_instructions);
            }

            // انتظار بسيط عشان ميعملش Spam للـ API
            await new Promise(r => setTimeout(r, 5000));
        }
    })();
});

const PORT = process.env.PORT || 3000;
// ==========================================
// BAYEZID STARTUP SEQUENCE & MODE SELECTION
// ==========================================
const startBayezidServer = () => {
    const server = app.listen(PORT, async() => {
        console.log(`\n=================================`);
        console.log(`[+] Bayezid Cognitive Engine V3 LIVE`);

        if (global.BAYEZID_MODE === 'RED') {
            console.log(`[🔥] MODE: RED TEAM (Offensive Pentesting Active)`);
            console.log(`[+] Project RedSwarm Squad is standing by.`);
        } else {
            console.log(`[🛡️] MODE: BLUE TEAM (Defensive SOAR Active)`);
            console.log(`[+] Dual-Engine Ready (Local/Cloud) 🔀`);
            console.log(`[+] Global Threat Intel (CTI): ENABLED 🌍`);
        }

        console.log(`[+] Web Dashboard Running on http://localhost:${PORT} 🖥️`);
        console.log(`=================================\n`);

        if (typeof loadMitreDatabase === 'function' && global.BAYEZID_MODE === 'BLUE') {
            await loadMitreDatabase();
        }
    });

    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
            console.error(`\n[!] ERROR: Port ${PORT} is currently in use!`);
        } else {
            console.error('\n[-] Server Crash:', error.message);
        }
    });
};

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log(`\n=============================================`);
console.log(` 🦅 WELCOME TO BAYEZID CYBER SYSTEM 🦅 `);
console.log(`=============================================`);
console.log(`Please select operational mode:`);
console.log(`[1] 🛡️  BLUE TEAM (Defensive SOAR & Log Analysis)`);
console.log(`[2] ⚔️  RED TEAM (Offensive AI Pentesting)`);

rl.question('\nEnter your choice (1 or 2): ', (answer) => {
    if (answer.trim() === '2') {
        global.BAYEZID_MODE = 'RED';
    } else {
        global.BAYEZID_MODE = 'BLUE';
    }
    rl.close();
    startBayezidServer();
});