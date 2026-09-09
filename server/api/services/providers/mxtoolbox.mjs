/**
 * MXToolbox public API client.
 * Mirrors frontend dns-admin-ui/src/api/mxtoolbox.ts shapes.
 */

const BASE = 'https://api.mxtoolbox.com';

/**
 * @typedef {{ DnsRequests: number, DnsMax: number, NetworkRequests?: number, NetworkMax?: number }} MxUsage
 * @typedef {{ Type?: string, 'Domain Name'?: string, 'Canonical Name'?: string, 'IP Address'?: string, TTL?: string, [k: string]: unknown }} MxInformationRow
 * @typedef {{ Command?: string, CommandArgument?: string, IsError?: boolean, Failed?: unknown[], Information?: MxInformationRow[], Errors?: unknown[], [k: string]: unknown }} MxLookupResponse
 */

/**
 * @param {string} path
 * @param {string} apiKey
 * @returns {Promise<any>}
 */
async function mxFetch(path, apiKey) {
    const res = await fetch(`${BASE}${path}`, {
        method: 'GET',
        headers: {
            Authorization: apiKey,
            Accept: 'application/json'
        }
    });

    if (!res.ok) {
        let detail = res.statusText || `HTTP ${res.status}`;
        try {
            const body = await res.json();
            if (body && typeof body === 'object' && body.Error) {
                detail = String(body.Error);
            }
        } catch {
            /* ignore */
        }
        const err = new Error(detail);
        err.status = res.status;
        throw err;
    }

    return res.json();
}

/**
 * @param {string} apiKey
 * @returns {Promise<MxUsage>}
 */
export async function fetchMxUsage(apiKey) {
    return mxFetch('/api/v1/Usage', apiKey);
}

/**
 * @param {string} apiKey
 * @param {'a'|'aaaa'} command
 * @param {string} domain
 * @returns {Promise<MxLookupResponse>}
 */
export async function mxLookup(apiKey, command, domain) {
    const arg = encodeURIComponent(String(domain).replace(/\.$/, ''));
    return mxFetch(`/api/v1/Lookup/${command}/?argument=${arg}`, apiKey);
}

/**
 * @param {MxInformationRow[]|undefined} info
 * @returns {{ a: string[], aaaa: string[], cnames: string[] }}
 */
export function parseMxInformation(info) {
    const a = [];
    const aaaa = [];
    const cnames = [];
    for (const row of info ?? []) {
        const type = String(row.Type ?? '').toUpperCase();
        if (type === 'A') {
            const ip = String(row['IP Address'] ?? '').trim();
            if (ip && !a.includes(ip)) a.push(ip);
        } else if (type === 'AAAA') {
            const ip = String(row['IP Address'] ?? '').trim();
            if (ip && !aaaa.includes(ip)) aaaa.push(ip);
        } else if (type === 'CNAME') {
            const cn = String(row['Canonical Name'] ?? '')
                .trim()
                .replace(/\.$/, '');
            if (cn && !cnames.includes(cn)) cnames.push(cn);
        }
    }
    return { a, aaaa, cnames };
}

/**
 * Remaining DNS lookups for this key (provider-reported).
 * @param {MxUsage|null|undefined} usage
 * @returns {number}
 */
export function mxRemaining(usage) {
    if (!usage) return 0;
    const max = Number(usage.DnsMax) || 0;
    const used = Number(usage.DnsRequests) || 0;
    return Math.max(0, max - used);
}
