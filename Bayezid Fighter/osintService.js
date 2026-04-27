const axios = require('axios');

const OTX_API_KEY = process.env.OTX_API_KEY;
const OTX_BASE_URL = 'https://otx.alienvault.com/api/v1/indicators';

const enrichWithOSINT = async(ipAddress) => {
    console.log(`\n[🔍] Gathering AlienVault OTX Intelligence for IP: ${ipAddress}...`);

    try {
        const response = await axios.get(`${OTX_BASE_URL}/IPv4/${ipAddress}/general`, {
            headers: {
                'X-OTX-API-KEY': OTX_API_KEY
            }
        });

        const data = response.data;
        const pulseCount = data.pulse_info ? data.pulse_info.count : 0;
        const country = data.base_indicator.country_name || "Unknown";

        const osintData = {
            ip: ipAddress,
            country: country,
            city: data.base_indicator.city || "Unknown",
            threat_actor_suspicion: pulseCount > 0 ? "Confirmed Malicious Activity" : "Clean",
            reputation_score: pulseCount > 10 ? "CRITICAL RISK" : (pulseCount > 0 ? "HIGH RISK" : "LOW RISK"),
            known_malicious_activity: `Reported in ${pulseCount} OTX Pulses`,
            otx_pulses: pulseCount
        };

        console.log(`[+] OSINT Data Retrieved: Origin ${country} | Pulses: ${pulseCount}`);
        return osintData;

    } catch (error) {
        console.error('[-] OSINT Retrieval Failed:', error.message);
        return {
            ip: ipAddress,
            note: "OSINT check failed (Network Timeout or Error)",
            error: error.message
        };
    }
};

const analyzeHash = async(fileHash) => {
    try {
        const response = await axios.get(`${OTX_BASE_URL}/file/${fileHash}/general`, {
            headers: {
                'X-OTX-API-KEY': OTX_API_KEY
            }
        });

        return {
            success: true,
            hash: fileHash,
            malicious_reports: response.data.pulse_info ? response.data.pulse_info.count : 0,
            malware_family: response.data.base_indicator.malware_family || 'Unknown'
        };

    } catch (error) {
        return { success: false, error: error.message };
    }
};

module.exports = {
    enrichWithOSINT,
    analyzeHash
};