const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./bayezid_soar.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        threat_hits INTEGER,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const saveToBlocklist = (ip, hits, reason) => {
    const stmt = db.prepare("INSERT OR IGNORE INTO blocklist (ip, threat_hits, reason) VALUES (?, ?, ?)");
    stmt.run(ip, hits, reason);
    stmt.finalize();
};