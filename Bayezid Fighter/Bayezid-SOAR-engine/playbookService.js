const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const executePlaybook = async(alertId, analysisResult, alertData) => {
    console.log(`\n[▶] Initiating Playbook for Threat: ${analysisResult.threat_type}`);

    let actionSteps = [];

    const uniquePlaybookName = `PB-${alertData.event_type}-${Date.now()}`;

    if (analysisResult.severity === 'CRITICAL' || analysisResult.severity === 'HIGH') {
        actionSteps = [
            { step: 1, action: "Create High Priority Incident Ticket", status: "SUCCESS" },
            { step: 2, action: `Block Source IP: ${alertData.source_ip} on Firewall`, status: "SIMULATED_SUCCESS" },
            { step: 3, action: "Send Slack Notification to SOC Team", status: "SUCCESS" }
        ];
    } else {
        actionSteps = [
            { step: 1, action: "Log event for future monitoring", status: "SUCCESS" },
            { step: 2, action: `Increase logging level for target: ${alertData.target_server}`, status: "SUCCESS" }
        ];
    }

    try {
        const savedPlaybook = await prisma.playbook.create({
            data: {
                name: uniquePlaybookName,
                description: `Automated mitigation response for ${analysisResult.threat_type} triggered by Alert ID: ${alertId}`,
                actions: actionSteps
            }
        });

        console.log(`[✔] Playbook Executed & Saved to Cloud (ID: ${savedPlaybook.id})`);
        return savedPlaybook;

    } catch (error) {
        console.error('[-] Error saving playbook to database:', error.message);
        return null;
    }
};

module.exports = {
    executePlaybook
};