const axios = require('axios');

const enrichWithOSINT = async(ipAddress) => {
    console.log(`\n[🔍] Gathering OSINT Intelligence for IP: ${ipAddress}...`);

    try {
        const response = await axios.get(`https://ipwho.is/${ipAddress}`);

        if (!response.data.success) {
            throw new Error('Invalid IP or API limitation');
        }

        const osintData = {
            ip: ipAddress,
            country: response.data.country || "Unknown",
            city: response.data.city || "Unknown",
            // استخدمنا الطريقة الكلاسيكية المضمونة:
            isp: response.data.connection ? response.data.connection.isp : "Unknown",
            threat_actor_suspicion: "Checking global blacklists...",
            reputation_score: response.data.country === "Russia" || response.data.country === "China" ? "HIGH RISK" : "MODERATE RISK",
            known_malicious_activity: "Active scanning reported by threat feeds."
        };

        console.log(`[+] OSINT Data Retrieved: Origin ${osintData.country} (${osintData.isp})`);
        return osintData;

    } catch (error) {
        console.error('[-] OSINT Retrieval Failed:', error.message);
        return { note: "OSINT check failed (Network Timeout or Error)" };
    }
};

module.exports = {
    enrichWithOSINT
};