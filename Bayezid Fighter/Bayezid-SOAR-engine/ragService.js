const axios = require('axios');

// 1. الذاكرة العشوائية (RAM) اللي هنخزن فيها منهج مايتر
let localMitreDB = {};

// ============================================================================
// 🚀 1. Boot-Time Downloader (تحميل قاعدة البيانات في الرامات وقت التشغيل)
// ============================================================================
async function loadMitreDatabase() {
    console.log("\n[📥] Boot-Time Downloader: Activating...");
    console.log("[📥] Fetching MITRE ATT&CK Enterprise DB into RAM...");

    try {
        // في البيئة الحقيقية بنسحب ملف الـ JSON الرسمي من سيرفرات مايتر
        // لكن عشان سرعة المشروع وعدم التعامل مع ملفات STIX المعقدة (30 ميجا)، 
        // هنبني الـ Core Database لأخطر التكتيكات اللي بتهم الـ SOC:
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

// ============================================================================
// 🌐 2. Live Web Search Agent (وكيل البحث الحي على الإنترنت)
// ============================================================================
async function searchLiveThreat(query) {
    console.log(`[🌐] Web Agent: Searching the internet live for '${query}'...`);
    try {
        // بنستخدم DuckDuckGo HTML Search عشان سريع ومجاني ومبيحتاجش API Key
        const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
        const response = await axios.get(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });

        // استخراج أول نتيجة (Snippet) من صفحة البحث
        const snippetMatch = response.data.match(/<a class="result__snippet[^>]*>(.*?)<\/a>/i);

        if (snippetMatch && snippetMatch[1]) {
            // تنظيف النتيجة من أكواد الـ HTML
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

// ============================================================================
// 🧠 3. The Master Router (العقل المدبر اللي بيقرر يبحث فين)
// ============================================================================
async function enrichContext(alertDataString) {
    let contextList = [];

    // 1. فحص قاعدة البيانات المحلية (MITRE) بسرعة الضوء
    for (const [techId, details] of Object.entries(localMitreDB)) {
        if (alertDataString.includes(techId) || alertDataString.toLowerCase().includes(details.name.toLowerCase())) {
            contextList.push(`[Local MITRE DB] Technique ${techId} (${details.name}): ${details.description}. Mitigation: ${details.mitigation}`);
        }
    }

    // 2. البحث عن الثغرات الجديدة (CVEs) على الإنترنت
    // بنستخدم Regex عشان نطلع أي ثغرة مكتوبة في اللوج (مثال: CVE-2026-1234)
    const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
    const foundCVEs = alertDataString.match(cveRegex);

    if (foundCVEs) {
        // لو لقينا ثغرات، نبعت الـ Web Agent يفتح النت ويدور عليها
        // بناخد أول ثغرة بس عشان منضيعش وقت كتير
        const uniqueCVE = [...new Set(foundCVEs)][0];
        const webIntel = await searchLiveThreat(uniqueCVE);
        contextList.push(webIntel);
    }

    // 3. بحث عن كلمات مفتاحية خطيرة (زي أدوات الهاكرز) على النت لو مش في الداتا بيز
    if (alertDataString.toLowerCase().includes('meterpreter') && contextList.length === 0) {
        const webIntel = await searchLiveThreat("What is Meterpreter malware?");
        contextList.push(webIntel);
    }

    return contextList.length > 0 ? contextList.join('\n\n') : "No specific Threat Intel context found. Proceed with raw analysis.";
}

module.exports = { loadMitreDatabase, enrichContext };