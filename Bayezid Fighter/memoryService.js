const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

const generateEmbedding = async(text) => {
    try {
        const model = genAI.getGenerativeModel({ model: "text-embedding-004" });
        const result = await model.embedContent(text);
        return result.embedding.values;
    } catch (error) {
        console.error("[-] Embedding Error:", error.message);
        return null;
    }
};

const findSimilarIncidents = async(logData) => {
    console.log(`[🧠] Searching Institutional Memory for similar attack patterns...`);
    const vector = await generateEmbedding(logData);
    if (!vector) return [];

    const vectorString = `[${vector.join(',')}]`;

    try {
        const similarAlerts = await prisma.$queryRaw `
            SELECT id, "threatType", "status", 
            1 - (embedding <=> ${vectorString}::vector) as similarity
            FROM "Alert"
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> ${vectorString}::vector
            LIMIT 1;
        `;

        if (similarAlerts.length > 0 && similarAlerts[0].similarity > 0.90) {
            return similarAlerts[0];
        }
        return null;
    } catch (error) {
        console.error("[-] Vector Search Error:", error.message);
        return null;
    }
};

const saveIncidentToMemory = async(alertId, logData) => {
    const vector = await generateEmbedding(logData);
    if (!vector) return;

    const vectorString = `[${vector.join(',')}]`;

    try {
        await prisma.$executeRaw `
            UPDATE "Alert" 
            SET embedding = ${vectorString}::vector 
            WHERE id = ${alertId};
        `;
        console.log(`[💾] Alert ${alertId} etched into Bayezid's Vector Memory.`);
    } catch (error) {
        console.error("[-] Vector Save Error:", error.message);
    }
};

module.exports = { findSimilarIncidents, saveIncidentToMemory };