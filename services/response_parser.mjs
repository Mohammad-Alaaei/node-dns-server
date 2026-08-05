import { Packet } from 'dns2';
import * as logger from '../utils/logger.mjs';
import { cacheRecord } from './cache_service.mjs';
import { config } from '../config/config.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';
import { shouldProcessUpstreamAnswer } from './cache_policy.mjs';

function getRecord(records, domain) {
    const key = normalizeDomain(domain);
    let record = records.get(key);

    if (!record) {
        record = {
            domain: key,
            A: [],
            AAAA: [],
            CNAME: []
        };
        records.set(key, record);
    }

    return record;
}

function packetHasFilterIp(packet) {
    // Build from live config — do NOT freeze at module load
    const filterIps = new Set(config.cache.filterIps);
    if (filterIps.size === 0) {
        return false;
    }

    for (const answer of packet.answers) {
        if (
            (answer.type === Packet.TYPE.A || answer.type === Packet.TYPE.AAAA) &&
            answer.address &&
            filterIps.has(answer.address)
        ) {
            return true;
        }
    }

    return false;
}

function packetHasIgnoreIp(packet) {
    const ignoreIps = new Set(config.ignoreIps);
    if (ignoreIps.size === 0) {
        return false;
    }

    for (const answer of packet.answers) {
        if (
            (answer.type === Packet.TYPE.A || answer.type === Packet.TYPE.AAAA) &&
            answer.address &&
            ignoreIps.has(answer.address)
        ) {
            return true;
        }
    }

    return false;
}

/**
 * Pure decision helper (tests + handleUpstreamResponse).
 */
export function evaluateUpstreamHandling(packet, isCustom = false) {
    const isFiltered = packetHasFilterIp(packet);
    const process = shouldProcessUpstreamAnswer({ isCustom, isFiltered });
    const doLog = process && !packetHasIgnoreIp(packet);
    return { isFiltered, process, doLog };
}

function handleUpstreamResponse(packet, isCustom = false, dnsServerId = null) {
    if (!packet?.answers?.length) {
        return;
    }

    const { process, doLog } = evaluateUpstreamHandling(packet, isCustom);
    const records = new Map();
    const expireMs = config.cache.expireTime * 1000;
    const now = Date.now();

    for (const answer of packet.answers) {
        switch (answer.type) {
            case Packet.TYPE.CNAME: {
                if (doLog) {
                    logger.info(`Resolved CNAME: ${answer.name} → ${answer.domain}`);
                }
                if (process) {
                    const record = getRecord(records, answer.name);
                    record.CNAME.push({
                        name: record.domain,
                        domain: normalizeDomain(answer.domain),
                        ttl: answer.ttl,
                        expiresAt: now + expireMs
                    });
                }
                break;
            }
            case Packet.TYPE.A: {
                if (doLog) {
                    logger.info(`Resolved A: ${answer.name} → ${answer.address}`);
                }
                if (process) {
                    const record = getRecord(records, answer.name);
                    record.A.push({
                        name: record.domain,
                        address: answer.address,
                        ttl: answer.ttl,
                        expiresAt: now + expireMs
                    });
                }
                break;
            }
            case Packet.TYPE.AAAA: {
                if (doLog) {
                    logger.info(`Resolved AAAA: ${answer.name} → ${answer.address}`);
                }
                if (process) {
                    const record = getRecord(records, answer.name);
                    record.AAAA.push({
                        name: record.domain,
                        address: answer.address,
                        ttl: answer.ttl,
                        expiresAt: now + expireMs
                    });
                }
                break;
            }
            case Packet.TYPE.PTR:
                if (doLog) {
                    logger.info(`Resolved PTR: ${answer.name} → ${answer.domain}`);
                }
                break;
            case Packet.TYPE.MX:
                if (doLog) {
                    logger.info(`Resolved MX: ${answer.name} → ${answer.exchange}`);
                }
                break;
        }
    }

    if (process) {
        for (const record of records.values()) {
            cacheRecord(record, dnsServerId);
        }
    }

    if (doLog) {
        console.log('=============');
    }
}

export { handleUpstreamResponse };