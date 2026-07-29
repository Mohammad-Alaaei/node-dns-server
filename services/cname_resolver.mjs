import { findRecord } from '../memory/resolver.mjs';

const MAX_DEPTH = 10;

/**
 * Resolves a local record while following CNAME chains.
 *
 * Returns:
 * {
 *   record,
 *   cnameChain
 * }
 */
export function resolveLocalRecord(domain, type) {

    const visited = new Set();
    const cnameChain = [];

    let current = domain;

    for (let depth = 0; depth < MAX_DEPTH; depth++) {

        if (visited.has(current)) {
            break;
        }

        visited.add(current);

        const record = findRecord(current, type);

        if (!record) {
            return null;
        }

        if (record[type].length) {
            return {
                record,
                cnameChain
            };
        }

        if (!record.CNAME.length) {
            return null;
        }

        const target = record.CNAME[0];

        cnameChain.push({
            from: current,
            to: target
        });

        current = target;
    }

    return null;
}