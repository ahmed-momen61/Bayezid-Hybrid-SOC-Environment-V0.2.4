const axios = require('axios');
require('dotenv').config();

const queryMISP = async(indicator) => {
    const mispUrl = process.env.MISP_URL;
    const mispKey = process.env.MISP_API_KEY;

    if (!mispUrl || !mispKey) return null;

    try {
        const response = await axios.post(`${mispUrl}/attributes/restSearch`, {
            returnFormat: 'json',
            value: indicator
        }, {
            headers: {
                'Authorization': mispKey,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        const attributes = (response.data && response.data.response) ? response.data.response.Attribute : null;

        if (attributes && attributes.length > 0) {
            return {
                found: true,
                event_id: attributes[0].event_id,
                category: attributes[0].category,
                comment: attributes[0].comment
            };
        }
        return { found: false };
    } catch (error) {
        console.error(`[-] MISP Connection Error for ${indicator}:`, error.message);
        return null;
    }
};

const queryOpenCTI = async(indicator) => {
    const openCtiUrl = process.env.OPENCTI_URL;
    const openCtiToken = process.env.OPENCTI_TOKEN;

    if (!openCtiUrl || !openCtiToken) return null;

    const query = `
        query SearchIndicators($search: String!) {
            stixCyberObservables(search: $search) {
                edges {
                    node {
                        entity_type
                        observable_value
                        standard_id
                    }
                }
            }
        }
    `;

    try {
        const response = await axios.post(`${openCtiUrl}/graphql`, {
            query: query,
            variables: { search: indicator }
        }, {
            headers: {
                'Authorization': `Bearer ${openCtiToken}`,
                'Content-Type': 'application/json'
            }
        });

        const edges = (response.data && response.data.data && response.data.data.stixCyberObservables) ?
            response.data.data.stixCyberObservables.edges :
            null;

        if (edges && edges.length > 0) {
            return {
                found: true,
                type: edges[0].node.entity_type,
                id: edges[0].node.standard_id
            };
        }
        return { found: false };
    } catch (error) {
        console.error(`[-] OpenCTI Connection Error for ${indicator}:`, error.message);
        return null;
    }
};

const enrichWithCTI = async(extractedIocs, relatedCves) => {
    console.log('\n[🌍] Querying Global Threat Intel (MISP & OpenCTI)...');
    let ctiReport = {
        misp_results: [],
        opencti_results: []
    };

    let indicatorsToSearch = [];
    if (extractedIocs) {
        if (extractedIocs.ips) indicatorsToSearch.push(...extractedIocs.ips);
        if (extractedIocs.hashes) indicatorsToSearch.push(...extractedIocs.hashes);
        if (extractedIocs.domains) indicatorsToSearch.push(...extractedIocs.domains);
    }
    if (relatedCves) {
        indicatorsToSearch.push(...relatedCves);
    }

    indicatorsToSearch = [...new Set(indicatorsToSearch.filter(i => i && i.trim() !== ''))];

    if (indicatorsToSearch.length === 0) {
        console.log('[!] No IoCs or CVEs found to query.');
        return ctiReport;
    }

    for (const indicator of indicatorsToSearch) {
        const mispData = await queryMISP(indicator);
        if (mispData && mispData.found) {
            ctiReport.misp_results.push({ indicator, details: mispData });
        }

        const openCtiData = await queryOpenCTI(indicator);
        if (openCtiData && openCtiData.found) {
            ctiReport.opencti_results.push({ indicator, details: openCtiData });
        }
    }

    console.log(`[✔] CTI Enrichment Complete. MISP Hits: ${ctiReport.misp_results.length} | OpenCTI Hits: ${ctiReport.opencti_results.length}`);
    return ctiReport;
};

module.exports = {
    enrichWithCTI
};