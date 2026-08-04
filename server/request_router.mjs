import { Packet } from 'dns2';
import { config } from '../config/config.mjs';

import * as logger from '../utils/logger.mjs';
import { sendResponse } from './dns_server.mjs';

import { handleARequest } from '../records/a_record.mjs';
import { handleAAAARequest } from '../records/aaaa_record.mjs';
import { handlePtrRequest } from '../records/ptr_record.mjs';
import { handleOtherRequest } from '../records/other_records.mjs';
import { DNS_TYPES } from '../config/constants.mjs';
import { handleCNAMERequest } from '../records/cname_record.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';

const DEBUG_PREFIX = config.server.debugPrefix;


/**
 * Handles a DNS request.
 *
 * @param {Buffer} message
 * @param {import('node:dgram').RemoteInfo} remote
 * @returns {Promise<void>}
 */
export async function handleRequest(message, remote) {
    try {
        const request = Packet.parse(message);

        if (request.questions.length !== 1) {
            return;
        }

        const question = request.questions[0];

        let debug = false;
        let domain = question.name;

        if (domain.startsWith(DEBUG_PREFIX)) {
            debug = true;
            domain = domain.substring(2);
        }

        domain = normalizeDomain(domain);

        logger.info(`Requested for: ${domain} (${DNS_TYPES[question.type] ?? question.type})`);

        let response;

        switch (question.type) {
            case Packet.TYPE.A:
                response = await handleARequest(request, message, domain, debug);
                break;

            case Packet.TYPE.AAAA:
                response = await handleAAAARequest(request, message, domain, debug);
                break;

            case Packet.TYPE.CNAME:
                response = await handleCNAMERequest(request, message, domain, debug);
                break;

            case Packet.TYPE.PTR:
                response = await handlePtrRequest(request, message, domain, debug);
                break;

            default:
                response = await handleOtherRequest(request, message, domain, DNS_TYPES[question.type] ?? String(question.type));
                break;
        }

        sendResponse(remote, response);

    } catch (err) {
        logger.error(err);
    }
}