const loadHistory = async() => {
    const tableBody = document.getElementById('historyTableBody');
    tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Loading data...</td></tr>';

    try {
        const response = await fetch('/api/v1/alerts');
        const result = await response.json();

        if (response.ok && result.data) {
            tableBody.innerHTML = '';

            result.data.forEach(alert => {
                const row = document.createElement('tr');
                const dateObj = new Date(alert.createdAt);

                row.innerHTML = `
                    <td>${dateObj.toLocaleString()}</td>
                    <td>${alert.eventType}</td>
                    <td>${alert.sourceIp}</td>
                    <td><span style="color: ${alert.severity === 'HIGH' || alert.severity === 'CRITICAL' ? '#ff7b72' : '#79c0ff'}">${alert.severity || 'INFO'}</span></td>
                    <td>${alert.status}</td>
                `;
                tableBody.appendChild(row);
            });
        } else {
            tableBody.innerHTML = '<tr><td colspan="5" style="color:#ff7b72; text-align:center;">Failed to load history</td></tr>';
        }
    } catch (error) {
        console.error("Error fetching history:", error);
        tableBody.innerHTML = '<tr><td colspan="5" style="color:#ff7b72; text-align:center;">Server connection error</td></tr>';
    }
};

const handleSimulationSubmit = async(event) => {
    event.preventDefault();

    const resultDiv = document.getElementById('simResult');
    resultDiv.textContent = "⏳ Processing Simulation...";
    resultDiv.style.color = "#d2a8ff";

    const payload = {
        attackType: document.getElementById('attackType').value,
        logFormat: document.getElementById('logFormat').value,
        parameters: document.getElementById('parameters').value,
        logData: document.getElementById('logData').value
    };

    try {
        const response = await fetch('/api/v1/simulation/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (response.ok) {
            resultDiv.textContent = "✅ Simulation Executed & Logged Successfully!";
            resultDiv.style.color = "#56d364";

            document.getElementById('simulationForm').reset();
            loadHistory();
        } else {
            resultDiv.textContent = `❌ Failed: ${result.error || 'Unknown error'}`;
            resultDiv.style.color = "#ff7b72";
        }
    } catch (error) {
        console.error("Simulation API Error:", error);
        resultDiv.textContent = "❌ Failed to connect to the server.";
        resultDiv.style.color = "#ff7b72";
    }
};

const initApp = () => {
    const simForm = document.getElementById('simulationForm');
    if (simForm) {
        simForm.addEventListener('submit', handleSimulationSubmit);
    }

    const refreshBtn = document.getElementById('refreshHistoryBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadHistory);
    }

    loadHistory();
};

document.addEventListener('DOMContentLoaded', initApp);