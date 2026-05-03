const express = require('express');
const cors = require('cors');
const readline = require('readline');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const path = require('path');
const { processTuningCommand, liveConfig } = require('./tuningService');
const { analyzeWithVertexAI, analyzeWithLocalModel, runScoutAgent, runBreacherAgent, runPhantomAgent, runChameleonAgent, runOverlordAgent, runScribeAgent, runActionAgent, bridgeRedToBlue, applyFixAndVerify } = require('./aiService');
const { executePlaybook } = require('./playbookService');
const { enrichWithOSINT } = require('./osintService');
const { sendTelegramAlert } = require('./notificationService');
const { loadMitreDatabase } = require('./ragService');
const { enrichWithCTI } = require('./ctiService');
const { findSimilarIncidents, saveIncidentToMemory } = require('./memoryService');



dotenv.config();

const prisma = new PrismaClient();
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.text());
const http = require('http');
const { Server } = require('socket.io');
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "http://localhost:5173",
        methods: ["GET", "POST"]
    }
});
global.io = io;
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
            const timeLimit = new Date(Date.now() - 60 * 60 * 1000);

            const existingAlert = await prisma.alert.findFirst({
                where: {
                    sourceIp: source_ip,
                    createdAt: { gte: timeLimit }
                },
                orderBy: { createdAt: 'desc' }
            });

            if (existingAlert) {
                console.log(`\n[♻️] CACHE HIT: Attack from ${source_ip} is already tracked! (Alert ID: ${existingAlert.id})`);
                console.log(`[!] Current Status: ${existingAlert.status}. Skipping AI Analysis & Playbooks.`);

                await prisma.alert.update({
                    where: { id: existingAlert.id },
                    data: { attempts: (existingAlert.attempts || 1) + 1 }
                });

                return res.status(200).json({
                    status: 'success',
                    cached: true,
                    message: "Threat is already tracked and handled by the SOC.",
                    alert_status: existingAlert.status,
                    analysis: {
                        threat_type: existingAlert.threatType,
                        severity: existingAlert.severity
                    },
                    playbook_executed: false,
                    playbook_details: "Skipped (Duplicate Activity)"
                });
            }
        }


        if (isJson) {
            const logsToEmbed = typeof rawData === 'string' ? rawData : JSON.stringify(rawData);
            const pastIncident = await findSimilarIncidents(logsToEmbed);

            if (pastIncident) {
                console.log(`\n[♻️] MEMORY HIT: Similar attack found! Match: ${(pastIncident.similarity * 100).toFixed(1)}%`);
                console.log(`[♻️] Past Incident ID: ${pastIncident.id} | Threat: ${pastIncident.threatType}`);

                const vectorAlert = await prisma.alert.create({
                    data: {
                        sourceIp: source_ip,
                        targetServer: target_server,
                        eventType: event_type,
                        status: "RESOLVED_BY_MEMORY",
                        threatType: pastIncident.threatType
                    }
                });

                return res.status(200).json({
                    status: 'success',
                    cached: true,
                    message: "Similar threat identified in institutional memory.",
                    similarity_score: `${(pastIncident.similarity * 100).toFixed(1)}%`,
                    historical_reference: pastIncident.id,
                    action_taken: "Applied historical playbook implicitly.",
                    alert_id: vectorAlert.id
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

        let alertStatus = "ANALYZED";
        if (aiResponse.is_false_positive) {
            alertStatus = "FALSE_POSITIVE";
        } else if (aiResponse.confidence_type === 'PROBABILISTIC') {
            alertStatus = "WAITING_FOR_APPROVAL";
        }

        const updatedAlert = await prisma.alert.update({
            where: { id: savedAlert.id },
            data: {
                sourceIp: aiResponse.extracted_ip || source_ip,
                severity: aiResponse.severity,
                threatType: aiResponse.threat_type,
                recommendedAction: aiResponse.recommended_action,
                confidenceType: aiResponse.confidence_type || "PROBABILISTIC",
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
                status: alertStatus
            }
        });
        console.log(`[✔] Cognitive Analysis Saved. Status: ${alertStatus} | Type: ${aiResponse.confidence_type}`);

        let playbookResult = null;

        const shouldExecutePlaybook = !aiResponse.is_false_positive &&
            (aiResponse.severity === 'HIGH' || aiResponse.severity === 'CRITICAL') &&
            (aiResponse.confidence_type === 'DETERMINISTIC');

        if (shouldExecutePlaybook) {
            console.log(`[⚡] DETERMINISTIC Threat Detected: Auto-executing Playbook...`);
            playbookResult = await executePlaybook(updatedAlert.id, aiResponse, isJson ? req.body : { source_ip: aiResponse.extracted_ip });
            sendTelegramAlert(aiResponse, osintData);
        } else {
            if (aiResponse.confidence_type === 'PROBABILISTIC') {
                console.log(`[✋] PROBABILISTIC Threat Detected: Execution Halted. Sent to War Room for Human Approval.`);
            } else {
                console.log(`[!] Playbook Skipped: ${aiResponse.is_false_positive ? "False Positive" : "Low Severity"}`);
            }
        }

        const logsToSave = isJson ? (typeof rawData === 'string' ? rawData : JSON.stringify(rawData)) : rawData;
        await saveIncidentToMemory(updatedAlert.id, logsToSave);

        return res.status(200).json({
            status: 'success',
            cached: false,
            is_false_positive: aiResponse.is_false_positive,
            confidence: aiResponse.confidence_score,
            alert_status: alertStatus,
            analysis: aiResponse,
            osint: osintData,
            cti: ctiData,
            playbook_executed: !!playbookResult,
            playbook_details: playbookResult || "Skipped (Sent to War Room / Low Severity / False Positive)"
        });

    } catch (error) {
        console.error('[-] Error processing alert:', error);
        return res.status(500).json({ status: 'error', message: 'Failed to process security data' });
    }
};

app.post('/api/v1/alerts/ingest', handleSecurityAlert);



app.get('/api/v1/alerts/:id/chat', async(req, res) => {
    try {
        const chats = await prisma.incidentChat.findMany({
            where: { alertId: req.params.id },
            orderBy: { createdAt: 'asc' }
        });
        res.json({ status: 'success', data: chats });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.post('/api/v1/alerts/:id/chat', async(req, res) => {
    const { sender, message } = req.body;
    const alertId = req.params.id;

    if (!sender || !message) {
        return res.status(400).json({ error: 'Sender and message are required' });
    }

    try {
        const newChat = await prisma.incidentChat.create({
            data: { alertId, sender, message }
        });
        console.log(`[💬] New message in War Room ${alertId} from ${sender}: ${message}`);

        if (message.includes('@Bayezid-Action') || message.includes('@bayezid')) {

            const alertData = await prisma.alert.findUnique({ where: { id: alertId } });

            const aiService = require('./aiService'); // استدعاء لحظي (Dynamic Require) لتجنب اللغبطة
            const aiDecision = await aiService.runActionAgent(alertData, message);

            if (aiDecision) {
                await prisma.incidentChat.create({
                    data: {
                        alertId,
                        sender: "Bayezid-Action 🤖",
                        message: `${aiDecision.agent_reply}\n\n[⚙️ Action Executed: ${aiDecision.recommended_playbook} on ${aiDecision.target_ip}]`
                    }
                });

                const mockAiResponseForPlaybook = {
                    severity: alertData.severity,
                    threat_type: alertData.threatType,
                    extracted_ip: aiDecision.target_ip || alertData.sourceIp,
                    recommended_action: aiDecision.understood_intent
                };

                await executePlaybook(alertId, mockAiResponseForPlaybook, { source_ip: mockAiResponseForPlaybook.extracted_ip });

                await prisma.alert.update({
                    where: { id: alertId },
                    data: { status: 'RESOLVED_BY_WAR_ROOM' }
                });
            }
        }

        res.status(200).json({ status: 'success', data: newChat });
    } catch (error) {
        console.error('[-] Chat API Error:', error.message);
        res.status(500).json({ status: 'error', message: error.message });
    }
});

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

app.post('/api/v1/redswarm/engage', async(req, res) => {
    const { targetInfo, currentState } = req.body;

    if (!targetInfo) {
        return res.status(400).json({ error: 'Missing targetInfo in request body' });
    }

    console.log(`\n[🔥] RedSwarm Engagement Requested! Target: ${targetInfo}`);

    try {
        const state = currentState || "Starting new engagement. Need initial reconnaissance.";
        const decision = await runOverlordAgent(targetInfo);

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


app.post('/api/v1/redswarm/overlord', async(req, res) => {
    const { targetInfo, allAgentsData } = req.body;
    if (!targetInfo || !allAgentsData) return res.status(400).json({ error: 'Missing data' });

    console.log(`\n[👑] Overlord requested for: ${targetInfo}`);
    try {
        const result = await runOverlordAgent(targetInfo, allAgentsData);
        res.status(200).json({ status: 'success', data: result });
    } catch (error) {
        console.error('[-] Overlord API Crash:', error);
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
        console.error('[-] Overlord API Crash:', error);
        res.status(500).json({ status: 'error', message: error.message });
    }
});


app.post('/api/v1/redswarm/auto-pilot', async(req, res) => {
    const { targetInfo } = req.body;
    if (!targetInfo) return res.status(400).json({ error: 'Target IP is required' });

    console.log(`\n[🚀] INITIATING FULL AUTO-PILOT CAMPAIGN AGAINST: ${targetInfo}`);
    res.status(200).json({ status: 'success', message: 'Campaign started. Overlord is now in control.' });

    //
    (async() => {
        let campaignActive = true;
        let lastScanResults = "";

        let iterations = 0;
        const MAX_ITERATIONS = 12;

        while (campaignActive && iterations < MAX_ITERATIONS) {
            iterations++;
            console.log(`\n--- ⏳ Autonomous Loop Iteration: ${iterations}/${MAX_ITERATIONS} ---`);

            const decision = await runOverlordAgent(targetInfo);

            if (!decision || decision.is_operation_complete) {
                console.log(`[👑] Overlord: Operation Finished (or AI halted). Scribe is writing the report.`);
                await runScribeAgent(targetInfo);
                campaignActive = false;
                break;
            }

            console.log(`[👑] Overlord Order: Activate [${decision.next_agent}]`);

            if (decision.next_agent === 'Scout') {
                const scoutData = await runScoutAgent(targetInfo, decision.detailed_instructions);
                if (scoutData) lastScanResults = scoutData.scan_results;

            } else if (decision.next_agent === 'Breacher') {
                await runBreacherAgent(targetInfo, lastScanResults, decision.detailed_instructions);

            } else if (decision.next_agent === 'Phantom') {
                await runPhantomAgent(targetInfo, "Previous session logs in DB", decision.detailed_instructions);

            } else if (decision.next_agent === 'Chameleon') {
                await runChameleonAgent(targetInfo, "Failed payloads in DB", "WAF Bypass needed", decision.detailed_instructions);
            }

            await new Promise(r => setTimeout(r, 5000));
        }

        if (iterations >= MAX_ITERATIONS) {
            console.log(`\n[⚠️] OVERLORD REACHED MAX ITERATIONS (${MAX_ITERATIONS}). Forcing operation halt and reporting.`);
            await runScribeAgent(targetInfo);
        }
    })();
});

app.post('/api/v1/bridge/report-vuln', async(req, res) => {
    const { vulnName, severity, detectedBy, targetIp, evidence } = req.body;
    const vuln = await prisma.vulnerabilityBridge.create({
        data: { vulnName, severity, detectedBy, targetIp, evidence }
    });
    res.json({ status: "success", message: "Vulnerability recorded.", vulnId: vuln.id });
});

app.post('/api/v1/bridge/analyze', async(req, res) => {
    const { vulnId } = req.body;
    const fixSuggestion = await bridgeRedToBlue(vulnId);
    res.json({ status: "success", data: fixSuggestion });
});

app.post('/api/v1/bridge/approve-fix', async(req, res) => {
    const { vulnId, userInstructions } = req.body;
    const result = await applyFixAndVerify(vulnId, userInstructions);
    res.json({ status: "success", message: "Fix applied and regression testing complete.", data: result });
});

const startEscalationWatcher = () => {
    setInterval(async() => {
        try {
            const timeLimit = new Date(Date.now() - (liveConfig.SLA_TIMEOUT_MINUTES * 60 * 1000));

            const expiredAlerts = await prisma.alert.findMany({
                where: {
                    status: 'WAITING_FOR_APPROVAL',
                    createdAt: { lt: timeLimit }
                }
            });

            for (const alert of expiredAlerts) {
                console.log(`\n[⏰] SLA TIMEOUT: Alert ${alert.id} exceeded ${liveConfig.SLA_TIMEOUT_MINUTES} mins!`);
                console.log(`[🤖] Bayezid taking over. Auto-Escalating threat: ${alert.threatType}`);

                await prisma.alert.update({
                    where: { id: alert.id },
                    data: { status: 'AUTO_ESCALATED' }
                });

                const mockAiResponse = {
                    severity: alert.severity,
                    threat_type: alert.threatType,
                    extracted_ip: alert.sourceIp,
                    recommended_action: alert.recommendedAction || "Auto-Isolated due to timeout SLA."
                };

                await executePlaybook(alert.id, mockAiResponse, { source_ip: alert.sourceIp });

                console.log(`[✔] Auto-Escalation Complete for IP: ${alert.sourceIp}`);
            }
        } catch (error) {
            console.error('[-] Escalation Watcher Error:', error.message);
        }
    }, 60 * 1000);
};


app.post('/api/v1/system/tune', async(req, res) => {
    const { command, role } = req.body;

    const result = await processTuningCommand(command, role);

    if (result.action === "UNAUTHORIZED") {
        return res.status(403).json(result);
    }

    res.json({
        status: "success",
        current_config: liveConfig,
        message: result.reply
    });
});

const PORT = process.env.PORT || 3000;

const loadConfigsFromDB = async() => {
    try {
        const configs = await prisma.systemConfig.findMany();
        configs.forEach(cfg => {
            if (cfg.key === 'SLA_TIMEOUT_MINUTES') {
                liveConfig.SLA_TIMEOUT_MINUTES = Number(cfg.value);
            }
        });
        console.log(`[📥] Persistent configurations loaded from Database.`);
    } catch (err) {
        console.log(`[⚠️] Startup: Using default configurations.`);
    }
};

io.on('connection', (socket) => {
    console.log(`[🔌] New Connection: ${socket.id}`);

    socket.on('join_war_room', () => {
        socket.join('war_room_shield');
        console.log(`[🛡️] Socket ${socket.id} joined the War Room.`);
    });

    socket.on('chat_message', async(data) => {
        console.log(`[💬] Message from Dashboard: ${data.text}`);
        if (data.text.includes('@Bayezid')) {
            io.emit('chat_message', {
                sender: 'Bayezid-AI',
                text: 'System command received. Analyzing threat patterns...',
                type: 'system'
            });
        }
    });

    socket.on('disconnect', () => {
        console.log(`[❌] Socket Disconnected: ${socket.id}`);
    });
});

const startBayezidServer = () => {
    const server = httpServer.listen(PORT, async() => {
        await loadConfigsFromDB();

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
        startEscalationWatcher();
        console.log(`[⏱️] SLA Escalation Watcher Active (${liveConfig.SLA_TIMEOUT_MINUTES} min timeout)`);
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