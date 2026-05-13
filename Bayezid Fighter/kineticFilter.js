const crypto = require('crypto');

const requestTracker = new Map();

const THREAT_SIGNATURES = [
    { name: "SQL Injection", regex: /(?:'|"|`|\\b)(?:select|drop|union|insert|update|delete|truncate)\\b/i },
    { name: "Cross-Site Scripting (XSS)", regex: /(?:<script>|<img.*?onload=|javascript:)/i },
    { name: "Path Traversal", regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f)/i },
    { name: "OS Command Injection", regex: /(?:;|\||&&|`|\$\().*(?:bash|sh|cmd|powershell|curl|wget|nc)/i }
];

const analyzeLogFastLive = (ip, payload) => {
    const now = Date.now();
    const payloadString = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);

    if (!requestTracker.has(ip)) {
        requestTracker.set(ip, { count: 1, firstSeen: now });
    } else {
        let tracker = requestTracker.get(ip);
        tracker.count += 1;

        if (now - tracker.firstSeen < 10000 && tracker.count > 5) {
            return { isSuspicious: true, reason: `Live Rate Limit Exceeded (DDoS/Scanner): ${tracker.count} requests from ${ip} in <10s.` };
        }

        if (now - tracker.firstSeen >= 10000) {
            requestTracker.set(ip, { count: 1, firstSeen: now });
        }
    }

    for (let sig of THREAT_SIGNATURES) {
        if (sig.regex.test(payloadString)) {
            return { isSuspicious: true, reason: `Live Signature Match [${sig.name}]` };
        }
    }

    if (payloadString.length > 5000) {
        return { isSuspicious: true, reason: `Live Anomaly: Payload size (${payloadString.length} bytes) exceeds safe limits.` };
    }

    return { isSuspicious: false, reason: "Traffic deemed safe by Live Kinetic Engine." };
};

module.exports = { analyzeLogFastLive };