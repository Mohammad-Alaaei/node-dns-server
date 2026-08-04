import { Packet } from 'dns2';
import * as logger from '../utils/logger.mjs';
import { cacheRecord } from './cache_service.mjs';
import { config } from '../config/config.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';

const CACHE_EXPIRE_TIME = config.cache.expireTime;

function getRecord(records, domain) {
    const key = normalizeDomain(domain);
    let record = records.get(key);
    if (!record) {
        record = { domain: key, A: [], AAAA: [], CNAME: [] };
        records.set(key, record);
    }
    return record;
}

/**
 * Logs resolved resource records from an external DNS response.
 *
 */
function handleUpstreamResponse(
    packet,
    cacheResult = false,
    dnsServerId = null
) {

    if (!packet.answers.length) {
        return;
    }

    const records = new Map();

    for (const answer of packet.answers) {

        switch (answer.type) {
            case Packet.TYPE.CNAME: {
                logger.info(`Resolved CNAME: ${answer.name} → ${answer.domain}`);

                const record = getRecord(records, answer.name);

                record.CNAME.push({
                    name: answer.name,
                    domain: answer.domain,
                    ttl: answer.ttl,
                    expiresAt: Date.now() + CACHE_EXPIRE_TIME * 1000
                });


                break;
            }

            case Packet.TYPE.A: {
                logger.info(`Resolved A: ${answer.name} → ${answer.address}`);

                const record = getRecord(records, answer.name);

                record.A.push({
                    name: answer.name,
                    address: answer.address,
                    ttl: answer.ttl,
                    expiresAt: Date.now() + CACHE_EXPIRE_TIME * 1000
                });

                break;
            }

            case Packet.TYPE.AAAA: {
                logger.info(`Resolved AAAA: ${answer.name} → ${answer.address}`);

                const record = getRecord(records, answer.name);

                record.AAAA.push({
                    name: answer.name,
                    address: answer.address,
                    ttl: answer.ttl,
                    expiresAt: Date.now() + CACHE_EXPIRE_TIME * 1000
                });

                break;
            }

            case Packet.TYPE.PTR:
                logger.info(`Resolved PTR: ${answer.name} → ${answer.domain}`);
                break;

            case Packet.TYPE.MX:
                logger.info(`Resolved MX: ${answer.name} → ${answer.exchange}`);
                break;
        }
    }

    if (cacheResult) {
        for (const record of records.values()) {
            cacheRecord(record, dnsServerId);
        }
    }

    console.log('=============');
}

export {
    handleUpstreamResponse
}