import * as logger from '../utils/logger.mjs';
import { decorateDebugResponse } from '../server/response_builder.mjs';
import { handleUpstreamResponse } from './response_parser.mjs';
import { forwardToExternalDns } from './upstream_resolver.mjs';
import { selectUpstream } from './upstream_selector.mjs';

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

    let upstreamMessage = message;

    if (debug) {
        const original = request.questions[0].name;

        request.questions[0].name = domain;
        upstreamMessage = request.toBuffer();
        request.questions[0].name = original;
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
