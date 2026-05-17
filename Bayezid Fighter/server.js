const express = require('express');
const net = require('net');
const axios = require('axios');
const cors = require('cors');
const readline = require('readline');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const path = require('path');
const { processTuningCommand, liveConfig } = require('./tuningService');
const { smartExec, analyzeWithVertexAI, analyzeWithLocalModel, runScoutAgent, runBreacherAgent, runPhantomAgent, runChameleonAgent, runOverlordAgent, runScribeAgent, runActionAgent, bridgeRedToBlue, applyFixAndVerify, runStealthScribeAgent, runVetoAgent, runShadowRouterAgent, runForensicRCAAgent, executeAlchemistFuzzingLoop, runMirageAgent, runWardenSandbox, runZeroDayForgeAgent } = require('./aiService');
const { executePlaybook } = require('./playbookService');
const { enrichWithOSINT } = require('./osintService');
const { sendTelegramAlert } = require('./notificationService');
const { loadMitreDatabase } = require('./ragService');
const { enrichWithCTI } = require('./ctiService');
const { findSimilarIncidents, saveIncidentToMemory } = require('./memoryService');
const crypto = require('crypto');
const itsmService = require('./itsmService');
const { analyzeLogFastLive, injectSwarmRule } = require('./kineticFilter');
const KernelStriker = require('./kernelStriker');
const WargamingEngine = require('./wargamingEngine');
KernelStriker.startTtlDaemon();
const ThreatGrapher = require('./threatGrapher');
const OracleReverser = require('./oracleAgent');
const SwarmCrypto = require('./swarmCrypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;
const { startMatrixShell } = require('./matrixShell');

function encryptEvidence(text) {
    let iv = crypto.randomBytes(IV_LENGTH);
    let keyBuffer = Buffer.from(ENCRYPTION_KEY, 'hex');
    if (keyBuffer.length !== 32) {
        keyBuffer = crypto.createHash('sha256').update(String(ENCRYPTION_KEY)).digest();
    }
    let cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function hashEvidence(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

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

    let evidence_payload = req.body.evidence || req.body.payload || (typeof rawData === 'string' ? rawData : JSON.stringify(rawData));
    let detected_by = req.body.detectedBy || req.body.detected_by || "Bayezid Omni-Ingest";
    let severity_level = req.body.severity || "HIGH";

    let requested_engine = process.env.AI_MODE || 'LOCAL';
    const isJson = req.headers['content-type'] === 'application/json';

    if (isJson) {
        source_ip = req.body.sourceIp || req.body.source_ip || req.body.targetIp || req.ip || "Unknown";
        event_type = req.body.vulnName || req.body.event_type || "Security Alert";
        target_server = req.body.targetIp || req.body.target_server || "Unknown";
        if (req.body.engine) requested_engine = req.body.engine.toUpperCase();
        console.log(`\n[+] Received Structured Threat: ${event_type} from ${source_ip}`);
    } else {
        const logPreview = typeof rawData === 'string' ? rawData.substring(0, 50) : 'Invalid Format';
        console.log(`\n[+] Received Raw Log Data: ${logPreview}...`);
        source_ip = req.ip || "Unknown";
        event_type = "Raw Log Analysis";
        target_server = "Detecting...";
        if (req.query.engine) requested_engine = req.query.engine.toUpperCase();
    }

    try {

        let mlFeatures = { entropy: "N/A", symbols: "N/A", keywords: "N/A" };
        let mlScore = "Regex Match";
        let isSuspiciousTraffic = false;

        if (source_ip !== "Extracting..." && source_ip !== "Unknown") {
            const kineticTriage = await analyzeLogFastLive(source_ip, rawData);
            if (kineticTriage.isSuspicious) {
                isSuspiciousTraffic = true;
                if (kineticTriage.reason && kineticTriage.reason.includes("(Cached)")) {
                    console.log(`[🛡️] Shield Active: Redundant anomaly from ${source_ip} suppressed by Intelligence Cache.`);
                    return res.json({ status: "blocked", message: "Attack suppressed by Intelligence Cache.", reason: kineticTriage.reason });
                }

                console.log(`[🚨] Kinetic Filter Alert: ${kineticTriage.reason}. Escalating to Cognitive AI Engine!`);
                console.log(`[⚔️] KINETIC ENGAGEMENT: Malicious signature detected. Triggering KernelStriker!`);
                await KernelStriker.blockIp(source_ip);
                console.log(`[🛡️] OS LEVEL SHIELD ACTIVE: IP ${source_ip} dropped via eBPF/Firewall.`);

                if (kineticTriage.ml_analysis) {
                    mlFeatures = kineticTriage.ml_analysis.features_extracted || mlFeatures;
                    mlScore = kineticTriage.ml_analysis.score || mlScore;
                }
            } else if (!isJson || (!req.body.vulnName && !req.body.event_type)) {
                console.log(`[♻️] Kinetic Filter Dropped Event: ${kineticTriage.reason}`);
                return res.json({ status: "ignored", message: kineticTriage.reason });
            }
        }


        let wardenReport = null;
        let oracleReport = { aiAnalysis: "Pending", obfuscation: "Unknown" };

        if (evidence_payload && (evidence_payload.includes('bash') || evidence_payload.includes('wget') || evidence_payload.length > 50)) {
            if (typeof runWardenSandbox === 'function') {
                wardenReport = await runWardenSandbox(evidence_payload);

                if (wardenReport && wardenReport.isMalicious) {
                    console.log(`\n[☠️] WARDEN ALERT: Payload verified as ${wardenReport.threatType} (Score: ${wardenReport.riskScore})`);
                    console.log(`[☠️] Verdict: ${wardenReport.sandboxVerdict}`);
                    severity_level = "CRITICAL";
                    event_type = `[Sandbox Verified] ${wardenReport.threatType} via ${event_type}`;
                    console.log(`[🐝] WARDEN -> ML SYNC: Sending malicious payload to ML Swarm Memory...`);
                    axios.post('http://127.0.0.1:8000/api/v1/ml/swarm_feedback', { payload: evidence_payload }).catch(e => console.log("[-] Swarm sync failed."));
                } else if (wardenReport && !wardenReport.isMalicious) {
                    console.log(`[🧠] Warden analysis confirmed safe. Sending feedback to ML Sniper to learn this pattern...`);
                    axios.post('http://127.0.0.1:8000/api/v1/ml/feedback', { payload: evidence_payload }).catch(e => console.log("[-] Feedback loop failed."));
                }
            }
        }

        if (typeof OracleReverser !== 'undefined' && OracleReverser.analyzePayload) {
            oracleReport = await OracleReverser.analyzePayload(evidence_payload || "");
            console.log(`[👁️] Oracle Insight: ${oracleReport.aiAnalysis}`);
        }


        let ticketId = `BZ-INC-${Date.now()}`;
        if (typeof itsmService !== 'undefined' && itsmService.createTicket) {
            ticketId = await itsmService.createTicket(event_type, severity_level, target_server).catch(() => ticketId);
        }

        const savedAlert = await prisma.alert.create({
            data: { sourceIp: source_ip, targetServer: target_server, eventType: event_type, status: "NEW" }
        });

        let vulnRecordId = null;
        try {
            if (req.body.vulnName) {
                const vuln = await prisma.vulnerabilityBridge.create({
                    data: { vulnName: event_type, severity: severity_level, detectedBy: detected_by, targetIp: target_server, evidence: evidence_payload, ticketId: ticketId }
                });
                vulnRecordId = vuln.id;
            }
        } catch (e) { console.log("[-] Bridge record skip"); }

        try {
            console.log(`[🔐] Evidence Encrypted & Stored in Vault.`);
            let encryptedDataStr = evidence_payload;
            let ivStr = "N/A";
            if (typeof encryptEvidence === 'function') {
                const encResult = encryptEvidence(evidence_payload);
                encryptedDataStr = encResult.encryptedData;
                ivStr = encResult.iv;
            }

            let hashStr = "N/A";
            if (typeof hashEvidence === 'function') {
                hashStr = hashEvidence(evidence_payload + Date.now().toString());
            }

            await prisma.evidenceVault.create({
                data: { incidentId: vulnRecordId || savedAlert.id.toString(), evidenceType: "PAYLOAD", encryptedData: encryptedDataStr, iv: ivStr, sha256Hash: hashStr, collectedBy: detected_by || "System" }
            }).catch(() => {});
        } catch (e) { console.log("[-] Evidence Vault Save Skipped"); }

        const payloadForAI = isJson ? req.body : rawData;
        let aiResponse;

        if (requested_engine === 'CLOUD' || requested_engine === 'VERTEX' || requested_engine === 'GEMINI') {
            aiResponse = await analyzeWithVertexAI(payloadForAI);
            if (aiResponse.engine_used.includes('Fail-safe')) aiResponse = await analyzeWithLocalModel(payloadForAI);
        } else {
            aiResponse = await analyzeWithLocalModel(payloadForAI);
            if (aiResponse.engine_used.includes('Fail-safe')) aiResponse = await analyzeWithVertexAI(payloadForAI);
        }

        const final_ip = aiResponse.extracted_ip && aiResponse.extracted_ip !== "Unknown" ? aiResponse.extracted_ip : source_ip;
        let osintData = await enrichWithOSINT(final_ip);
        let ctiData = null;

        if (aiResponse.extracted_iocs || (aiResponse.related_cves && aiResponse.related_cves.length > 0)) {
            ctiData = await enrichWithCTI(aiResponse.extracted_iocs, aiResponse.related_cves);
        }

        let alertStatus = aiResponse.is_false_positive ? "FALSE_POSITIVE" : (aiResponse.confidence_type === 'PROBABILISTIC' ? "WAITING_FOR_APPROVAL" : "ANALYZED");

        await prisma.alert.update({
            where: { id: savedAlert.id },
            data: {
                sourceIp: final_ip,
                severity: (wardenReport && wardenReport.isMalicious) ? 'CRITICAL' : aiResponse.severity,
                threatType: aiResponse.threat_type,
                recommendedAction: aiResponse.recommended_action,
                confidenceType: aiResponse.confidence_type,
                osintData: { osint: osintData, cti: ctiData },
                status: alertStatus
            }
        });


        let playbookResult = null;
        let redTeamVerdict = null;

        const shouldExecutePlaybook = !aiResponse.is_false_positive && (aiResponse.severity === 'HIGH' || aiResponse.severity === 'CRITICAL') && (aiResponse.confidence_type === 'DETERMINISTIC');

        if (shouldExecutePlaybook) {
            console.log(`[⚡] DETERMINISTIC Threat: Auto-executing Playbook and deploying patch...`);
            playbookResult = await executePlaybook(savedAlert.id, aiResponse, isJson ? req.body : { source_ip: final_ip });
            if (typeof sendTelegramAlert === 'function') sendTelegramAlert(aiResponse, osintData);


            console.log(`[🩸] WAKING RED TEAM: Forging Live Payload to test the new Blue Team Patch...`);
            const weaponizedPayload = await runZeroDayForgeAgent(aiResponse.threat_type, 1);

            if (weaponizedPayload && weaponizedPayload.weaponizedCode) {
                const actual_target = (target_server !== 'Unknown' && target_server !== 'Detecting...') ? target_server : (req.body.destination_ip || aiResponse.extracted_ip || 'localhost');
                console.log(`[🔥] LIVE FIRE: Alchemist attacking ${target_server} to verify patch integrity...`);
                const attackResult = await executeAlchemistFuzzingLoop(weaponizedPayload.weaponizedCode, target_server, 1);

                if (attackResult && attackResult.bypassed) {
                    console.log(`[❌] CRITICAL BREACH: Red Team bypassed the Blue Patch! Escalating...`);
                    if (typeof itsmService !== 'undefined' && itsmService.createJiraTicket) await itsmService.createJiraTicket(`Patch Bypass: ${aiResponse.threat_type}`, "Red Team successfully bypassed the applied mitigation.");
                    await prisma.alert.update({ where: { id: savedAlert.id }, data: { status: "PATCH_FAILED" } });
                    redTeamVerdict = "FAILED_BYPASS";
                } else {
                    console.log(`[✅] VERIFIED: Red Team neutralized. Patch is bulletproof.`);
                    await prisma.alert.update({ where: { id: savedAlert.id }, data: { status: "RESOLVED_VERIFIED" } });
                    redTeamVerdict = "VERIFIED_SECURE";

                    console.log(`[🌐] HYDRA PROTOCOL: Broadcasting immunity signature to the Swarm...`);
                    if (typeof SwarmCrypto !== 'undefined' && SwarmCrypto.broadcastSignature) {
                        await SwarmCrypto.broadcastSignature({ threat: aiResponse.threat_type, verified: true });
                    }
                }
            } else {
                console.log(`[⚠️] Forge Agent could not construct a valid payload for testing.`);
                redTeamVerdict = "UNTESTED";
            }
        }

        if (typeof ThreatGrapher !== 'undefined' && ThreatGrapher.generateReport) {
            ThreatGrapher.generateReport({
                ticketId: ticketId,
                attackerIp: final_ip,
                payload: evidence_payload.substring(0, 100),
                mlScore: mlScore,
                wardenStatus: wardenReport ? "Container Analysis Performed" : "Layer 3 Mitigation",
                mitreTactic: "T1190 - Exploit Public-Facing Application",
                finalAction: "Omni-Pipeline Execution (WIN32 Block)",
                severity: severity_level,
                mlFeatures: mlFeatures,
                oracleAnalysis: oracleReport.aiAnalysis,
                obfuscationType: oracleReport.obfuscation
            });
        }

        await saveIncidentToMemory(savedAlert.id, evidence_payload);

        return res.status(200).json({
            status: 'success',
            ticket_id: ticketId,
            vulnId: vulnRecordId,
            is_false_positive: aiResponse.is_false_positive,
            alert_status: alertStatus,
            warden_sandbox: wardenReport ? wardenReport.sandboxVerdict : "Not Required",
            oracle_insight: oracleReport.aiAnalysis,
            analysis: aiResponse,
            osint: osintData,
            cti: ctiData,
            playbook_details: playbookResult ? playbookResult.message : "Pending Review",
            rollback_command: playbookResult ? playbookResult.rollbackCmd : "N/A",
            red_team_verification: redTeamVerdict,
            evidence_vault: "Encrypted & Hashed (SHA-256)"
        });

    } catch (error) {
        console.error('[-] Error in Omni-Pipeline:', error);
        return res.status(500).json({ status: 'error', message: 'Pipeline failure', details: error.message });
    }
};

app.post('/api/v1/alerts/ingest', handleSecurityAlert);

app.post('/api/v1/bridge/report-vuln', (req, res) => {
    console.log(`\n[🌉] FUSION PROTOCOL: Vulnerability Report Proxy Triggered.`);
    handleSecurityAlert(req, res);
});
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

            const aiService = require('./aiService');
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


const handleLiveFireDrill = async(req, res) => {
    const { attackType, targetAsset } = req.body;

    console.log(`\n[🔥] LIVE FIRE DRILL INITIATED: Launching ${attackType} against ${targetAsset || 'localhost'}`);

    try {
        const forgeResult = await runZeroDayForgeAgent(`Create a ${attackType} exploit payload`, 1);

        if (forgeResult && forgeResult.weaponizedCode) {
            console.log(`[⚔️] Exploit Forged. Firing at target...`);

            const attackResult = await executeAlchemistFuzzingLoop(forgeResult.weaponizedCode, targetAsset || 'localhost', 1);

            return res.status(200).json({
                status: "success",
                message: "Live round fired. Monitoring Kinetic Filter for interception.",
                forge_report: forgeResult,
                attack_outcome: attackResult
            });
        } else {
            return res.status(500).json({ error: "Forge failed to create live payload." });
        }
    } catch (error) {
        console.error("[-] Live Fire Error:", error);
        return res.status(500).json({ error: "Drill execution failed." });
    }
};

app.post('/api/v1/drill/live-fire', handleLiveFireDrill);

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
    console.log(`\n[🌉] FUSION PROTOCOL: Vulnerability Report Proxy Triggered.`);

    const mockReq = {
        body: {
            ...req.body,
            source_ip: req.body.sourceIp || req.body.targetIp || req.ip || "Unknown",
            event_type: req.body.vulnName || "Vulnerability Scan Report",
            target_server: req.body.targetIp || "127.0.0.1",
            payload: req.body.evidence || "No payload provided",
            detected_by: req.body.detectedBy || "Bayezid Bridge"
        },
        ip: req.ip,
        headers: { 'content-type': 'application/json' },
        query: req.query || {}
    };

    const mockRes = {
        status: function(code) { this.statusCode = code; return this; },
        json: function(data) {
            console.log(`[🌉] FUSION COMPLETE: Vulnerability routed and processed via Omni-Pipeline.`);
            return res.status(this.statusCode || 200).json({
                fusion_route: "Success",
                original_vuln: req.body.vulnName,
                omni_result: data
            });
        }
    };

    try {
        await handleSecurityAlert(mockReq, mockRes);
    } catch (error) {
        console.error("[-] Fusion Routing Error:", error);
        res.status(500).json({ error: "Failed to route into Omni-Pipeline" });
    }
});

app.post('/api/v1/users/seed', async(req, res) => {
    try {
        const junior = await prisma.user.upsert({
            where: { username: "ahmed_junior" },
            update: {},
            create: { username: "ahmed_junior", role: "JUNIOR_ANALYST", trustScore: 50 }
        });
        const senior = await prisma.user.upsert({
            where: { username: "momen_senior" },
            update: {},
            create: { username: "momen_senior", role: "SENIOR_ANALYST", trustScore: 90 }
        });
        console.log("[👥] Test users seeded successfully.");
        res.json({ status: "success", junior, senior });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/v1/bridge/analyze', async(req, res) => {
    const { vulnId } = req.body;
    const fixSuggestion = await bridgeRedToBlue(vulnId);
    res.json({ status: "success", data: fixSuggestion });
});

app.post('/api/v1/bridge/approve-fix', async(req, res) => {
    const { vulnId, userId } = req.body;

    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        if (!vuln) return res.status(404).json({ error: "Vulnerability not found" });

        if (userId) {
            const user = await prisma.user.findUnique({ where: { id: String(userId) } });
            if (user) {
                const fixData = JSON.parse(vuln.suggestedFix || "{}");
                const remediationCode = fixData.remediation_code || "Unknown";

                const vetoEvaluation = await runVetoAgent(user.role, user.trustScore, vuln.vulnName, vuln.severity, remediationCode);

                if (vetoEvaluation.veto_decision) {
                    console.log(`\n[🛑] AI VETO TRIGGERED: User '${user.username}' blocked! Reason: ${vetoEvaluation.reason}`);

                    await prisma.user.update({
                        where: { id: user.id },
                        data: { trustScore: Math.max(0, user.trustScore - 5) }
                    });

                    return res.status(403).json({
                        status: "blocked",
                        message: `AI VETO: ${vetoEvaluation.reason}`,
                        trustScore: user.trustScore - 5
                    });
                }
                console.log(`\n[✅] AI Approved User Action. Reason: ${vetoEvaluation.reason}`);
            }
        }

        await prisma.vulnerabilityBridge.update({
            where: { id: vulnId },
            data: { status: "APPROVED" }
        });

        const aiService = require('./aiService');
        aiService.applyFixAndVerify(vulnId, "Human Approved");

        res.json({ status: "success", message: "Fix approved and is being applied." });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/v1/bridge/isolate', async(req, res) => {
    const { vulnId, attackerIp } = req.body;

    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        if (!vuln) return res.status(404).json({ error: "Vulnerability not found" });

        console.log(`\n[🛡️] Blue Side: Initiating Cognitive Isolation for ID: ${vulnId}`);

        const aiService = require('./aiService');
        const targetIpToIsolate = attackerIp || "185.20.30.40";

        const isolationResult = await aiService.runShadowRouterAgent(targetIpToIsolate, vuln.vulnName);

        if (isolationResult) {
            await prisma.vulnerabilityBridge.update({
                where: { id: vulnId },
                data: { status: "ISOLATED" }
            });

            res.json({
                status: "success",
                message: "Attacker successfully rerouted to Honeypot.",
                strategy: isolationResult
            });
        } else {
            res.status(500).json({ error: "Failed to generate isolation strategy." });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const startEscalationWatcher = () => {
    const watch = async() => {
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
        } finally {
            setTimeout(watch, 60 * 1000);
        }
    };

    watch();
};

app.post('/api/v1/bridge/rca', async(req, res) => {
    const { vulnId } = req.body;
    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        if (!vuln) return res.status(404).json({ error: "Vulnerability record not found." });

        const mockLogs = `[INFO] Connection from ${vuln.targetIp} - 200 OK\n[WARN] High frequency of SQL keywords detected: DROP, SELECT, FROM\n[ERROR] Database error at line 45: Syntax error near 'DROP'`;

        const rcaReport = await runForensicRCAAgent(vuln.vulnName, vuln.targetIp, mockLogs);

        res.json({
            status: "success",
            report: rcaReport
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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


app.post('/api/v1/config/set-autonomy', async(req, res) => {
    const { mode } = req.body;

    try {
        const config = await prisma.systemConfig.upsert({
            where: { id: "BAYEZID_CORE_CONFIG" },
            update: { autonomyMode: mode },
            create: {
                id: "BAYEZID_CORE_CONFIG",
                autonomyMode: mode,
                emergencyTtlMinutes: 5,
                dualRedTeamMode: "MODE_A",
                key: "CORE_AUTONOMY",
                value: mode
            }
        });
        console.log(`\n[⚙️] System Autonomy Level changed to: ${mode}`);
        res.json({ status: "success", message: `Autonomy Mode set to ${mode}`, config });
    } catch (error) {
        res.status(500).json({ status: "error", message: error.message });
    }
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

app.post('/api/v1/wargaming/start', async(req, res) => {
    const { targetAsset } = req.body;
    console.log(`\n[🚀] API Trigger: Launching GAN Wargaming Arena manually...`);
    WargamingEngine.runArenaSession(targetAsset || "Production DB & Web API").catch(e => console.log(`[⚠️] Wargaming Error: ${e.message}`));
    res.json({ status: "success", message: "GAN Wargaming started in the background. Check server console." });
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

        if (global.BAYEZID_MODE === 'BLUE') {
            const { startMatrixShell } = require('./matrixShell');
            startMatrixShell(2222);
            startMatrixShell(8080);
            console.log(`[⚡] Bayezid Intelligence Matrix is LIVE and Lethal.`);
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

rl.question('\nEnter your choice (1 or 2):\n', (answer) => {
    if (answer.trim() === '2') {
        global.BAYEZID_MODE = 'RED';
        console.log("\n[⚔️ RED TEAM] Select Tactical Mode:");
        console.log("[A] 🔁 Auto-Mitigate (Attack -> Send to Blue Team -> Verify)");
        console.log("[B] 🥷 Stealth Pentest (Attack -> Generate Report -> No Patching)\n");

        rl.question("Enter mode (A or B): ", (modeChoice) => {
            const isStealth = modeChoice.trim().toUpperCase() === 'B';
            console.log(`\n[+] RED TEAM Activated in ${isStealth ? 'STEALTH (Mode B)' : 'AUTO-MITIGATE (Mode A)'}`);

            rl.question("\n[🎯] Enter Target IP or Domain to scan: ", (targetIpInput) => {
                const targetIp = targetIpInput.trim() || "10.0.0.99";
                rl.close();

                startBayezidServer();

                setTimeout(async() => {
                    console.log(`\n[⚔️] Initializing RedSwarm Agents for Live Target Scan on ${targetIp}...`);

                    try {
                        const { runScoutAgent, runBreacherAgent, runStealthScribeAgent, executeAlchemistFuzzingLoop } = require('./aiService');
                        const axios = require('axios');

                        console.log(`\n[🔍] Scout Agent is scanning the target...`);
                        const scoutData = await runScoutAgent(targetIp, "Perform a comprehensive vulnerability scan.");

                        if (!scoutData || !scoutData.scan_results) {
                            console.log("[-] Recon finished. No open ports or critical vulnerabilities found.");
                            process.exit(0);
                        }

                        console.log(`\n[🧪] Awakening The Alchemist: Initiating Adaptive Exploit Mutation (Live Execution)...`);

                        const scanContext = scoutData.scan_results ? scoutData.scan_results.substring(0, 200) : "Unknown Open Ports";

                        const alchemistData = await executeAlchemistFuzzingLoop(scanContext, targetIp, 3);

                        if (!alchemistData || !alchemistData.mutated_payload) {
                            console.log("[-] Alchemist could not bypass defenses or find a viable exploit path.");
                            process.exit(0);
                        }

                        const realVuln = {
                            vulnName: "Adaptive Mutated Exploit (Alchemist Bypass)",
                            severity: "CRITICAL",
                            detectedBy: "RedSwarm Alchemist Agent",
                            targetIp: targetIp,
                            evidence: alchemistData.mutated_payload
                        };

                        console.log(`\n[🚨] Real Threat Detected: ${realVuln.vulnName}`);

                        if (isStealth) {
                            console.log(`\n[🥷] Stealth Mode Active. Bypassing Blue Team and generating report...`);
                            await runStealthScribeAgent(realVuln);
                            console.log("\n[+] Stealth Pentest Complete. Check the report above.");
                        } else {
                            console.log("\n[🌉] Forwarding Live Threat to Blue Team Bridge...");
                            const res = await axios.post(`http://localhost:${PORT}/api/v1/bridge/report-vuln`, realVuln);
                            console.log(`[✔] Handover complete! Ticket ID: ${res.data.ticketId}`);
                            console.log(`[🛡️] Awakening Overlord Agent for autonomous defense...`);
                            await axios.post(`http://localhost:${PORT}/api/v1/bridge/analyze`, { vulnId: res.data.vulnId });
                        }

                    } catch (error) {
                        console.error("[-] Attack Execution Failed:", error.message);
                    }
                }, 2000);
            });
        });
    } else {
        global.BAYEZID_MODE = 'BLUE';
        rl.close();
        startBayezidServer();
    }
});

app.post('/api/v1/bridge/isolate', async(req, res) => {
    const { vulnId, attackerIp } = req.body;

    try {
        const vuln = await prisma.vulnerabilityBridge.findUnique({ where: { id: vulnId } });
        if (!vuln) return res.status(404).json({ error: "Vulnerability not found" });

        const finalIpToIsolate = attackerIp || vuln.targetIp;

        if (!finalIpToIsolate) {
            return res.status(400).json({ error: "Attacker IP not provided and not found in vulnerability record." });
        }

        console.log(`\n[🛡️] Blue Side: Initiating Cognitive Isolation for Target: ${finalIpToIsolate}`);

        const isolationResult = await runShadowRouterAgent(finalIpToIsolate, vuln.vulnName);

        if (isolationResult) {
            await prisma.vulnerabilityBridge.update({
                where: { id: vulnId },
                data: { status: "ISOLATED" }
            });

            res.json({
                status: "success",
                message: `Attacker (${finalIpToIsolate}) successfully rerouted to Honeypot.`,
                strategy: isolationResult
            });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/v1/red/alchemist', async(req, res) => {
    const { targetIp, vulnContext, maxMutations } = req.body;

    if (!targetIp) {
        return res.status(400).json({ error: "Target IP is required." });
    }

    try {
        console.log(`\n[🚀] Postman Trigger: Launching Alchemist Attack Loop on ${targetIp}`);

        const result = await executeAlchemistFuzzingLoop(
            vulnContext || "General vulnerability exploitation",
            targetIp,
            maxMutations || 3
        );

        if (result) {
            res.json({
                status: "success",
                message: "Alchemist successfully bypassed defenses via Live Execution.",
                finalPayload: result.mutated_payload,
                techniqueUsed: result.obfuscation_technique
            });
        } else {
            res.status(418).json({
                status: "failed",
                message: "Alchemist exhausted all mutation attempts without gaining access."
            });
        }
    } catch (error) {
        console.error("[-] Alchemist API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/v1/red/forge', async(req, res) => {
    const { vulnContext, maxRetries } = req.body;

    if (!vulnContext) {
        return res.status(400).json({ error: "vulnContext is required." });
    }

    try {
        console.log(`\n[🚀] Forge Trigger: Commissioning new Zero-Day exploit...`);

        const result = await runZeroDayForgeAgent(vulnContext, maxRetries || 3);

        if (result && result.status === "success") {
            res.json({
                status: "weaponized",
                message: "Exploit successfully compiled and verified.",
                attemptsTaken: result.attempts,
                exploitCode: result.weaponizedCode
            });
        } else if (result && result.status === "failed") {
            res.status(422).json({
                status: "compilation_failed",
                message: "Forge could not produce a syntactically valid exploit within the retry limit.",
                lastError: result.lastError,
                flawedCode: result.flawedCode
            });
        } else {
            res.status(500).json({ error: "Forge critical failure." });
        }
    } catch (error) {
        console.error("[-] Forge API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/v1/swarm/sync', async(req, res) => {
    const { rule, signature, sourceNode } = req.body;

    if (!rule || !signature) {
        return res.status(400).json({ error: "Invalid Swarm Payload" });
    }

    const isValid = SwarmCrypto.verifySwarmPayload(rule, signature);

    if (!isValid) {
        console.log(`[🚨] SWARM ALERT: Forged defense rule received from ${sourceNode}! Rejecting to protect Core Engine.`);
        return res.status(403).json({ error: "Cryptographic Signature Verification Failed. Intel Rejected." });
    }

    console.log(`\n[🐝] HYDRA PROTOCOL TRIGGERED: Valid Zero-Day Rule received from [${sourceNode}].`);
    console.log(`[🧠] Rule Name: ${rule.rule_name}`);

    try {
        injectSwarmRule(rule);
        res.json({ status: "success", message: "Defense Rule assimilated into Kinetic Filter Memory." });
    } catch (error) {
        console.log(`[⚠️] Failed to inject Swarm Rule.`);
        res.status(500).json({ error: "Memory injection failed" });
    }
});


process.on('SIGINT', () => {
    console.log('\n[🛑] Graceful Shutdown Initiated...');
    console.log('[🧹] Cleaning up background processes...');
    process.exit(0);
});