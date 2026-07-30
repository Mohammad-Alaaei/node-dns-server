import { Packet } from 'dns2';
import * as logger from '../utils/logger.mjs';
import { cacheRecord } from './cache_service.mjs';


function getRecord(records, domain) {

    let record = records.get(domain);

    if (!record) {

        record = {
            domain,
            A: [],
            AAAA: [],
            CNAME: [],
            ttl: 300
        };

        records.set(domain, record);
    }

    return record;
}

/**
 * Logs resolved resource records from an external DNS response.
 *
 */
function handleUpstreamResponse(packet, cacheResult = false) {

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
                    domain: answer.domain
                });

                if (answer.ttl) {
                    record.ttl = Math.min(record.ttl, answer.ttl);
                }

                break;
            }

            case Packet.TYPE.A: {
                logger.info(`Resolved A: ${answer.name} → ${answer.address}`);

                const record = getRecord(records, answer.name);

                record.A.push({
                    name: answer.name,
                    address: answer.address
                });

                if (answer.ttl) {
                    record.ttl = Math.min(record.ttl, answer.ttl);
                }

                break;
            }

            case Packet.TYPE.AAAA: {
                logger.info(`Resolved AAAA: ${answer.name} → ${answer.address}`);

                const record = getRecord(records, answer.name);

                record.AAAA.push({
                    name: answer.name,
                    address: answer.address
                });

                if (answer.ttl) {
                    record.ttl = Math.min(record.ttl, answer.ttl);
                }

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
            cacheRecord(
                record.domain,
                record.A,
                record.AAAA,
                record.CNAME,
                record.ttl
            );
        }
    }

    console.log('=============');
}

export {
    handleUpstreamResponse
}