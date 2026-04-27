const { analyzeIP } = require('./otxService');

const processIncomingAlert = async(ipAddress) => {
    console.log(`\n🛡️ [Bayezid Engine] Processing alert for IP: ${ipAddress}`);

    const report = await analyzeIP(ipAddress);

    if (!report.success) return { action: 'RETRY', status: 'error' };

    if (report.malicious_reports > 10) {
        console.log(`🛑 [BLOCK] IP ${ipAddress} is confirmed malicious (${report.malicious_reports} hits).`);

        saveToBlocklist(ipAddress, report.malicious_reports, "AlienVault High Threat Score");

        return {
            ip: ipAddress,
            action: 'BLOCK',
            details: 'Added to firewall and local database'
        };
    }

    console.log(`✅ [ALLOW] IP ${ipAddress} passed the security check.`);
    return { ip: ipAddress, action: 'ALLOW', details: 'No significant threats found' };
};

module.exports = { processIncomingAlert };