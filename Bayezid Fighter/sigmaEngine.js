const { spawn } = require('child_process');
const path = require('path');
const { applyGradientUpdate } = require('./matrixShell');

const runCommand = (command, args, cwd) => {
    return new Promise((resolve, reject) => {
        // Use shell: true for windows compatibility with docker-compose/python
        const proc = spawn(command, args, { cwd, shell: true });
        
        proc.stdout.on('data', (data) => {
            const output = data.toString();
            
            const lines = output.split('\n');
            for (const line of lines) {
                if (line.trim()) {
                    // Check for gradient updates from RL agent
                    if (line.includes('__SIGMA_UPDATE__:')) {
                        try {
                            const jsonStr = line.split('__SIGMA_UPDATE__:')[1].trim();
                            const update = JSON.parse(jsonStr);
                            console.log(`\n[🧠] SIGMA-LIVE: Intercepted Gradient Update from RL Agent!`);
                            console.log(`[🔧] Hardening Matrix Logic against: ${update.vector}`);
                            // Apply feedback to dynamically rewrite deception logic
                            if (typeof applyGradientUpdate === 'function') {
                                applyGradientUpdate(update);
                            } else {
                                console.log(`[!] applyGradientUpdate not implemented in matrixShell yet.`);
                            }
                        } catch (e) {
                            console.log(`[!] Failed to parse gradient update: ${e.message}`);
                        }
                    } else {
                        console.log(line.trim());
                    }
                }
            }
        });

        proc.stderr.on('data', (data) => {
            // Keep docker-compose pull logs from cluttering as errors
            const output = data.toString().trim();
            if (output && !output.includes('Pulling') && !output.includes('Created') && !output.includes('Started')) {
                // Docker compose often outputs to stderr even for success info
                 console.log(`[PPO/SYS Log]: ${output}`);
            }
        });

        proc.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`Process ${command} exited with code ${code}`));
        });
        
        proc.on('error', (err) => {
             reject(err);
        });
    });
};

const startSigmaSymbioticLoop = async () => {
    console.log(`\n======================================================`);
    console.log(`[🚀] INITIATING PROJECT SIGMA-LIVE`);
    console.log(`[🧬] Symbiotic Sandbox-to-Matrix Reinforcement Learning`);
    console.log(`======================================================\n`);

    const sandboxDir = path.join(__dirname, 'sandbox');
    const pythonScript = path.join(__dirname, 'ml_engine', 'sigma_ppo.py');

    try {
        console.log(`[📦] 1. Starting Lightweight Docker Sandbox...`);
        try {
             await runCommand('docker-compose', ['up', '-d'], sandboxDir);
        } catch(e) {
             console.log(`[!] Sandbox creation warning (Docker might not be running): ${e.message}`);
             console.log(`[+] Proceeding with agent training simulation anyway...`);
        }

        console.log(`\n[🧠] 2. Initiating PPO Agent Training (Sandbox Mode)...`);
        await runCommand('python', [pythonScript, 'sandbox'], __dirname);

        console.log(`\n[🌐] 3. Injecting PPO Agent into Live Matrix Shell...`);
        // Note: Assumes matrixShell is already running (usually started via server.js)
        await runCommand('python', [pythonScript, 'live'], __dirname);

        console.log(`\n[🧹] 4. Tearing down Sandbox...`);
        try {
             await runCommand('docker-compose', ['down'], sandboxDir);
        } catch(e) {}

        console.log(`\n[✅] SIGMA-LIVE Symbiotic Loop Completed.`);
        
    } catch (error) {
        console.error(`\n[❌] SIGMA-LIVE encountered a critical error: ${error.message}`);
    }
};

module.exports = { startSigmaSymbioticLoop };
