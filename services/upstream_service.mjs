import * as logger from '../utils/logger.mjs';
import { decorateDebugResponse, createRecordResponse } from '../server/response_builder.mjs';
import { handleUpstreamResponse, evaluateUpstreamHandling } from './response_parser.mjs';
import { forwardToExternalDns } from './upstream_resolver.mjs';
import { selectUpstream } from './upstream_selector.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';
import { findStoredRecord } from '../memory/resolver.mjs';
import { RECORD_STATUS } from '../config/constants.mjs';

export async function handleExternalRequests(
    request,
    message,
    domain,
    type = null,
    debug = false,
    preferredServer = null
) {
    const upstream = selectUpstream(domain, preferredServer);

    logger.info(
        `Forwarding ${type ?? 'query'} for ${domain} to ${upstream.server.ip}`
    );

    console.log('=============');

    // Always query upstream for the domain we are resolving (may differ from
    // the client question when a rewrite rule redirected us to a CNAME target).
    let upstreamMessage = message;
    const originalQuestion = request.questions[0].name;
    const needsRewrite =
        normalizeDomain(originalQuestion) !== normalizeDomain(domain);

    if (debug || needsRewrite) {
        request.questions[0].name = domain;
        upstreamMessage = request.toBuffer();
        request.questions[0].name = originalQuestion;
    }

    const response = await forwardToExternalDns(
        upstreamMessage,
        upstream.server
    );

    // isCustom drives CUSTOM_ONLY; FILTERED_ONLY decided inside after seeing answers
    await handleUpstreamResponse(
        response.packet,
        upstream.custom,
        upstream.server.id
    );

    // Filtered upstream must not replace a previous SUCCESS.
    // Serve the last good data (CNAME or A) instead of the sinkhole answer.
    const { isFiltered } = evaluateUpstreamHandling(response.packet, upstream.custom);
    if (isFiltered && type) {
        const stored = findStoredRecord(domain);
        if (stored) {
            const built = createRecordResponse(request, stored, type);
            const srv = built.server;
            const isFilteredServer =
                srv?.status === RECORD_STATUS.FILTERED || srv?.status === 'FILTERED';
            if (
                srv &&
                !isFilteredServer &&
                ((srv[type]?.length || 0) > 0 || (srv.CNAME?.length || 0) > 0)
            ) {
                logger.info(
                    `FILTERED refresh ignored for ${domain}; serving last SUCCESS`
                );
                return {
                    packet: built.packet,
                    buffer: null
                };
            }
        }
    }

    if (!debug) {
        return {
            packet: null,
            buffer: response.buffer
        };
    }

    return {
        packet: decorateDebugResponse(
            response.packet,
            request,
            domain,
            type,
            upstream.server.ip,
            upstream.custom ? 'Custom' : 'Default'
        ),
        buffer: null
    };
}
