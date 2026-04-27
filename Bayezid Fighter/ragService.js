const axios = require('axios');

let localMitreDB = {};

async function loadMitreDatabase() {
    console.log("\n[📥] Boot-Time Downloader: Activating...");
    console.log("[📥] Fetching MITRE ATT&CK Enterprise DB into RAM...");

    try {

        localMitreDB = {
            "T1486": { name: "Data Encrypted for Impact", description: "Ransomware encryption phase.", mitigation: "Offline backups, EDR blocking." },
            "T1059": { name: "Command and Scripting Interpreter", description: "Malicious use of PowerShell/CMD.", mitigation: "Restrict script execution." },
            "T1078": { name: "Valid Accounts", description: "Use of compromised credentials (e.g., VPN Impossible Travel).", mitigation: "MFA, Session Revocation." },
            "T1055": { name: "Process Injection", description: "Injecting code into processes (e.g., Meterpreter).", mitigation: "Behavioral Endpoint Protection." },
            "T1003": { name: "OS Credential Dumping", description: "Stealing passwords from memory (e.g., Mimikatz).", mitigation: "Credential Guard, LSA Protection." }
        };

        console.log(`[✔] MITRE DB Loaded successfully. (${Object.keys(localMitreDB).length} core techniques cached in RAM ⚡)`);
    } catch (error) {
        console.error("[-] Failed to load MITRE DB:", error.message);
    }
}


async function searchLiveThreat(query) {
    console.log(`[🌐] Web Agent: Searching the internet live for '${query}'...`);
    try {
        const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
        const response = await axios.get(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });

        const snippetMatch = response.data.match(/<a class="result__snippet[^>]*>(.*?)<\/a>/i);

        if (snippetMatch && snippetMatch[1]) {
            const cleanText = snippetMatch[1].replace(/(<([^>]+)>)/gi, "").trim();
            console.log(`[✔] Web Agent Found: ${cleanText.substring(0, 50)}...`);
            return `[Live Web Intel for ${query}]: ${cleanText}`;
        }
        return `[Live Web Intel]: No quick summary found for ${query}.`;
    } catch (error) {
        console.error("[-] Web Agent Search failed:", error.message);
        return `[Live Web Intel]: Could not fetch data for ${query} (Internet/Firewall block).`;
    }
}


async function enrichContext(alertDataString) {
    let contextList = [];

    for (const [techId, details] of Object.entries(localMitreDB)) {
        if (alertDataString.includes(techId) || alertDataString.toLowerCase().includes(details.name.toLowerCase())) {
            contextList.push(`[Local MITRE DB] Technique ${techId} (${details.name}): ${details.description}. Mitigation: ${details.mitigation}`);
        }
    }

    const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
    const foundCVEs = alertDataString.match(cveRegex);

    if (foundCVEs) {
        const uniqueCVE = [...new Set(foundCVEs)][0];
        const webIntel = await searchLiveThreat(uniqueCVE);
        contextList.push(webIntel);
    }

    if (alertDataString.toLowerCase().includes('meterpreter') && contextList.length === 0) {
        const webIntel = await searchLiveThreat("What is Meterpreter malware?");
        contextList.push(webIntel);
    }

    return contextList.length > 0 ? contextList.join('\n\n') : "No specific Threat Intel context found. Proceed with raw analysis.";
}

module.exports = { loadMitreDatabase, enrichContext };