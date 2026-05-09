const fs = require('fs').promises;

/* --------------------------------------------------------------------
   Logger helpers: load, flush, add
--------------------------------------------------------------------- */
const LOG_FILE = 'resolved.log';          // file used to persist mappings
const FLUSH_INTERVAL_MS = 60_000;         // 1 minute
const IGNORE_LIST = [
    '10.10.34.35',
    '10.10.34.34',
    '10.10.34.36',
    '0.0.0.0',
]

// In‑memory set of "<domain>|<ip>" strings
const seenMap = new Map();

/**
 * Load previously logged domain|ip pairs from disk into the `seen` set.
 */
async function loadSeen() {
    try {
        const data = await fs.readFile(LOG_FILE, 'utf8');
        for (const line of data.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const [domain, ...ips] = trimmed.split(/\s+/);
            seenMap.set(domain, new Set(ips));
        }
        console.log(`Loaded ${seenMap.size} domains from ${LOG_FILE}`);
    } catch (err) {
        if (err.code !== 'ENOENT') console.error(err);
    }
}

/**
 * Flush the current `seen` set to disk.  The file contains one line per
 * mapping: "domain ip".
 */
async function flushSeen() {
    const lines = [];
    for (const [domain, ipSet] of seenMap.entries()) {
        lines.push(`${domain} ${Array.from(ipSet).join(' ')}`);
    }
    try {
        await fs.writeFile(LOG_FILE, lines.join('\n') + '\n', 'utf8');
        console.log(`Flushed ${lines.length} domain entries to ${LOG_FILE}`);
    } catch (err) {
        console.error('Error writing resolved log:', err);
    }
}

/** Add or replace a mapping for a domain. */
function upsertDomain(domain, ipsArray) {
    let filteredIPs = [];
    for (const ip of ipsArray) {
        if (IGNORE_LIST.includes(ip)) {
            continue;
        }

        filteredIPs.push(ip)
    }
    if (filteredIPs.length > 0) {
        seenMap.set(domain, new Set(filteredIPs));
    }
}

/* --------------------------------------------------------------------
     Bootstrap: load persisted data and start periodic flush
--------------------------------------------------------------------- */
async function init() {
    await loadSeen();                     // step 1
    setInterval(flushSeen, FLUSH_INTERVAL_MS); // step 2
}

module.exports = {
    init,
    upsertDomain,
};