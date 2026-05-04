const createTicket = async(vulnName, severity, targetIp) => {
    const ticketId = "JIRA-" + Math.floor(Math.random() * 9000 + 1000);
    console.log(`\n[🎫] ITSM: Auto-created Ticket [${ticketId}] for [${severity}] ${vulnName} on ${targetIp}`);
    return ticketId;
};

const closeTicket = async(ticketId, remediationCode) => {
    console.log(`\n[🎫] ITSM: Auto-closing Ticket [${ticketId}]...`);
    console.log(`[🎫] ITSM Resolution Note: "Resolved by Bayezid-AI. Applied Patch: ${remediationCode.substring(0, 50)}..."`);
};

module.exports = { createTicket, closeTicket };