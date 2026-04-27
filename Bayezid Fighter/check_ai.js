const axios = require('axios');
require('dotenv').config();

async function checkGoogleModels() {
    const apiKey = process.env.GOOGLE_API_KEY;

    if (!apiKey || apiKey === "FUCK U, I won't give u my API") {
        console.log("\n[❌] ERROR: API Key is missing or invalid in .env file.");
        return;
    }

    console.log(`\n[🔍] Connecting to Google AI servers using your API Key...`);

    try {
        const response = await axios.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);

        const models = response.data.models;
        console.log(`\n[✅] SUCCESS! Here are the models your API Key is allowed to use for generation:\n`);

        models.forEach(model => {
            if (model.supportedGenerationMethods.includes("generateContent")) {
                console.log(`🟢 ${model.name.replace('models/', '')}`);
            }
        });

        console.log(`\n[*] Copy one of the green names above and put it in your aiService.js!`);

    } catch (error) {
        if (error.response && error.response.status === 403) {
            console.log('\n[❌] Error 403: API Key is not valid or does not have access to Gemini API.');
        } else if (error.response && error.response.status === 400) {
            console.log('\n[❌] Error 400: API Key might be restricted or typed incorrectly.');
        } else {
            console.error('\n[❌] Error fetching models:', error.message);
        }
    }
}

checkGoogleModels();