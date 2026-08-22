import * as logger from '../utils/logger.mjs';
import { decorateDebugResponse } from '../server/response_builder.mjs';
import { handleUpstreamResponse } from './response_parser.mjs';
import { forwardToExternalDns } from './upstream_resolver.mjs';
import { selectUpstream } from './upstream_selector.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';

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
