import { Packet } from 'dns2';
import { config } from '../config/config.mjs';
import { findRecord } from '../memory/resolver.mjs';

const DNS_TTL = config.dns.ttl;
const DEBUG_PREFIX = config.server.debugPrefix;


/**
 * Appends TXT debug records to a DNS packet.
 *
 * @param {object} packet dns2 Packet.
 * @param {object} request Parsed request.
 * @param {{
 *   resolver: string,
 *   server: string,
 *   type: string,
 *   answers: string[]
 * }} info
 */
function appendDebugRecords(packet, request, info) {
    if (!packet.additionals) {
        packet.additionals = [];
    }

    const answers = info.answers.map(answer => {

        if (typeof answer === 'string') {
            return answer;
        }

        return (
            answer.address ??
            answer.domain ??
            answer.exchange ??
            answer.data ??
            String(answer)
        );
    });

    const records = [
        `Resolver=${info.resolver}`,
        `Server=${info.server}`,
        `Type=${info.type}`,
        `Count=${answers.length}`,
        ...answers.map(value => `Answer=${value}`)
    ];

    for (const record of records) {
        packet.additionals.push({
            name: request.questions[0].name,
            type: Packet.TYPE.TXT,
            class: Packet.CLASS.IN,
            ttl: DNS_TTL,
            data: record
        });
    }
}

function createRecordResponse(request, record,server, requestedType) {

    const response = Packet.createResponseFromRequest(request);

    let current = record;
    const visited = new Set();

    while (current && !visited.has(current.domain)) {
        visited.add(current.domain);

        if (!server) {
            break;
        }

        for (const cname of server.CNAME) {
            response.answers.push({
                name: current.domain,
                type: Packet.TYPE.CNAME,
                class: Packet.CLASS.IN,
                ttl: cname.ttl ?? 60,
                domain: cname.domain
            });
        }

        if (server[requestedType].length) {
            for (const value of server[requestedType]) {
                response.answers.push({
                    name: value.name,
                    type: Packet.TYPE[requestedType],
                    class: Packet.CLASS.IN,
                    ttl: value.ttl ?? 60,
                    address: value.address
                });
            }
            break;
        }

        if (!server.CNAME.length) {
            break;
        }

        current = findRecord(
            server.CNAME[0].domain,
            requestedType
        );
    }

    return response;
}

function appendAddressRecords(response, record, type) {

    for (const value of record[type]) {

        response.answers.push({
            name: value.name,
            type: Packet.TYPE[type],
            class: Packet.CLASS.IN,
            ttl: record.ttl,
            address: value.address
        });
    }
}

/**
 * Creates a DNS PTR response.
 *
 * @param {object} request Parsed dns2 request.
 * @param {string} hostname Host name returned for the PTR lookup.
 * @returns {object} dns2 Packet.
 */
function createPtrResponse(request, hostname) {
    const response = Packet.createResponseFromRequest(request);

    response.answers.push({
        name: request.questions[0].name,
        type: Packet.TYPE.PTR,
        class: Packet.CLASS.IN,
        ttl: DNS_TTL,
        domain: hostname
    });

    return response;
}

/**
 * Creates a successful DNS response with no answers.
 *
 * Used when a locally matched domain receives an unsupported query
 * type (currently AAAA).
 *
 * @param {object} request Parsed dns2 request.
 * @returns {object} dns2 Packet.
 */
function createEmptyResponse(request) {
    const response = Packet.createResponseFromRequest(request);

    response.answers = [];

    return response;
}

function decorateDebugResponse(
    packet,
    request,
    domain,
    type,
    dnsServer,
    resolver
) {
    const answers = [];
    const debugName = `${DEBUG_PREFIX}${domain}`;

    packet.questions[0].name = debugName;

    for (const answer of packet.answers) {
        answer.name = debugName;

        switch (answer.type) {
            case Packet.TYPE.A:
            case Packet.TYPE.AAAA:
                answers.push(answer.address);
                break;

            case Packet.TYPE.CNAME:
            case Packet.TYPE.PTR:
                answers.push(answer.domain);
                break;

            case Packet.TYPE.MX:
                answers.push(answer.exchange);
                break;

            case Packet.TYPE.TXT:
                answers.push(answer.data);
                break;
        }
    }

    for (const authority of packet.authorities ?? []) {
        authority.name = debugName;
    }

    for (const additional of packet.additionals ?? []) {
        if (additional.type !== Packet.TYPE.OPT) {
            additional.name = debugName;
        }
    }

    appendDebugRecords(packet, request, {
        resolver,
        server: dnsServer,
        type: type ?? 'UNKNOWN',
        answers
    });

    return packet;
}

function createCnameResponse(
    request,
    names,
    ttl = DNS_TTL
) {
    const response = Packet.createResponseFromRequest(request);

    for (const domain of names) {
        response.answers.push({
            name: request.questions[0].name,
            type: Packet.TYPE.CNAME,
            class: Packet.CLASS.IN,
            ttl,
            domain
        });
    }

    return response;
}

export {
    appendDebugRecords,
    createRecordResponse,
    createPtrResponse,
    createEmptyResponse,
    decorateDebugResponse,
    createCnameResponse
};