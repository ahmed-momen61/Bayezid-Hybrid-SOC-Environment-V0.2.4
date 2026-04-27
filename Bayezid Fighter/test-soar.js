require('dotenv').config();
const { analyzeIP } = require('./otxService');

const runBayezidTest = async() => {
    const targetIP = '185.220.101.44';

    console.log(`\n🔍 [Bayezid SOAR] Starting threat analysis for IP: ${targetIP}...\n`);

    const report = await analyzeIP(targetIP);

    if (report.success) {
        console.log('✅ Analysis Complete!');
        console.log('-----------------------------------');
        console.log(`📍 IP Address : ${report.ip}`);
        console.log(`🌍 Country    : ${report.country}`);
        console.log(`🚨 Threat Hits: ${report.malicious_reports} (Pulses)`);
        console.log('-----------------------------------');

        if (report.malicious_reports > 0) {
            console.log('🛑 [DECISION] Malicious IP detected! SOAR Action: BLOCK and add to Firewall rules.');
        } else {
            console.log('🛡️ [DECISION] IP seems clean. SOAR Action: ALLOW.');
        }
    } else {
        console.log('❌ Error:', report.error);
    }
};

runBayezidTest();