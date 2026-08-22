import * as logger from '../utils/logger.mjs';
import { config } from '../config/config.mjs';
import {
    findRecord,
    findStoredRecord,
    getPreferredServer,
    hasLocalRecord
} from '../memory/resolver.mjs';
import { appendDebugRecords, createRecordResponse } from '../server/response_builder.mjs';
import { handleExternalRequests } from '../services/upstream_service.mjs';
import {
    resolveRewrite,
    injectCnameAnswer,
    MAX_REWRITE_DEPTH
} from '../services/rewrite_service.mjs';
import { Packet } from 'dns2';
import { RECORD_SOURCE, REWRITE_ACTIONS } from '../config/constants.mjs';

const SERVER_IP = config.server.ip;

export function selectServer(record, type) {

    // LOCAL records are authoritative.
    if (record.source === RECORD_SOURCE.LOCAL) {
        return record.servers[0] ?? null;
    }

    const now = Date.now();

    let server = record.servers.find(s =>
        s.selected &&
        !s.isStale &&
        (
            s[type].some(r => r.expiresAt > now) ||
            s.CNAME.some(r => r.expiresAt > now)
        )
    );

    if (server) {
        return server;
    }

    server = record.servers.find(s =>
        !s.isStale &&
        (
            s[type].some(r => r.expiresAt > now) ||
            s.CNAME.some(r => r.expiresAt > now)
        )
    );

    if (server) {
        return server;
    }

    return record.servers
        .filter(s =>
            s.isStale &&
            (
                s[type].length ||
                s.CNAME.length
            )
        )
        .sort((a, b) => (b.lastSuccessAt ?? 0) - (a.lastSuccessAt ?? 0))[0] ?? null;
}

/**
 * Handles record types stored in DB / memory.
 * Optionally applies rewrite rules (e.g. cname_rewrite) before normal lookup.
 */
export async function handleLocalRecord({
    request,
    message,
    domain,
    type,
    debug = false,
    _rewriteDepth = 0
}) {

    // Rewrite rules run early for A/AAAA/CNAME so the original name is never
    // sent upstream when a cname_rewrite matches.
    if (
        _rewriteDepth < MAX_REWRITE_DEPTH &&
        (type === 'A' || type === 'AAAA' || type === 'CNAME')
    ) {
        const rewrite = resolveRewrite(domain);
        if (rewrite && rewrite.action === REWRITE_ACTIONS.CNAME_REWRITE) {
            logger.info(
                `REWRITE cname: ${domain} → ${rewrite.target}` +
                    (debug ? ' [debug]' : '')
            );

            const targetResult = await handleLocalRecord({
                request,
                message,
                domain: rewrite.target,
                type,
                debug,
                _rewriteDepth: _rewriteDepth + 1
            });

            return injectCnameAnswer(
                request,
                domain,
                rewrite.target,
                targetResult,
                debug
            );
        }
    }

    const record = findRecord(domain, type);

    if (record) {

        const { packet, server, answers } = createRecordResponse(
            request,
            record,
            type
        );

        if (server && (
            server[type].length ||
            server.CNAME.length
        )) {

            const inlineAnswers = answers.join(', ');
            logger.info(`FOUND: ${inlineAnswers ? inlineAnswers : '[N/A]'}`);
            console.log('=============');

            if (debug) {
                const debugAnswers = packet.answers.map(answer => {
                    switch (answer.type) {
                        case Packet.TYPE.A:
                        case Packet.TYPE.AAAA:
                            return answer.address;

                        case Packet.TYPE.CNAME:
                        case Packet.TYPE.PTR:
                            return answer.domain;

                        case Packet.TYPE.MX:
                            return answer.exchange;

                        default:
                            return null;
                    }
                }).filter(Boolean);

                appendDebugRecords(packet, request, {
                    resolver: 'Local',
                    server: SERVER_IP,
                    type,
                    answers: debugAnswers
                });
            }

            return { packet, buffer: null };
        }

        // LOCAL exists but this type is missing — only then allow upstream.
        // Do not re-resolve LOCAL when type is present but empty answer path failed.
        if (record.source === RECORD_SOURCE.LOCAL) {
            logger.info(`LOCAL ${domain} has no ${type}; forwarding upstream`);
        }
    } else if (hasLocalRecord(domain)) {
        // LOCAL row exists but isRecordValid failed for this type → upstream for missing type only
        logger.info(`LOCAL ${domain} missing type ${type}; forwarding upstream`);
    }

    const stored = findStoredRecord(domain);
    const preferred = stored
        ? getPreferredServer(stored, type)
        : null;

    return handleExternalRequests(
        request,
        message,
        domain,
        type,
        debug,
        preferred
    );
}
