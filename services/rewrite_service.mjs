import { store } from '../memory/store.mjs';
import { normalizeDomain } from '../utils/domain_utils.mjs';
import { REWRITE_ACTIONS } from '../config/constants.mjs';
import { Packet } from 'dns2';
import * as logger from '../utils/logger.mjs';

const MAX_REWRITE_DEPTH = 5;
const DEFAULT_CNAME_TTL = 60;

/**
 * Find the first matching rewrite rule for a domain.
 * Rules are already sorted by pattern length (longer first).
 *
 * @param {string} domain
 * @returns {object|null} memory rewrite rule or null
 */
export function matchRewrite(domain) {
    domain = normalizeDomain(domain);
    if (!domain || !store.rewriteRules.length) {
        return null;
    }

    for (const rule of store.rewriteRules) {
        if (!rule.enabled || !rule.regex) {
            continue;
        }
        if (rule.regex.test(domain)) {
            return rule;
        }
    }

    return null;
}

/**
 * Expand a cname_rewrite rule against a domain.
 * Uses standard JS replace with the template (supports $1, $2, …).
 *
 * @param {string} domain
 * @param {object} rule
 * @returns {string|null} rewritten target or null on failure
 */
export function expandCnameRewrite(domain, rule) {
    domain = normalizeDomain(domain);
    const template = rule?.params?.template;
    if (typeof template !== 'string' || !template.trim()) {
        return null;
    }

    if (!rule.regex) {
        return null;
    }

    try {
        const expanded = domain.replace(rule.regex, template.trim());
        const target = normalizeDomain(expanded);
        if (!target || target === domain) {
            return null;
        }
        // Basic sanity: must look like a hostname
        if (!/^[a-z0-9._-]+$/i.test(target) || target.length > 253) {
            return null;
        }
        return target;
    } catch {
        return null;
    }
}

/**
 * Apply rewrite for a domain. Currently only cname_rewrite is implemented.
 *
 * @param {string} domain
 * @returns {{ action: string, target: string, rule: object }|null}
 */
export function resolveRewrite(domain) {
    const rule = matchRewrite(domain);
    if (!rule) {
        return null;
    }

    if (rule.action === REWRITE_ACTIONS.CNAME_REWRITE) {
        const target = expandCnameRewrite(domain, rule);
        if (!target) {
            return null;
        }
        return {
            action: REWRITE_ACTIONS.CNAME_REWRITE,
            target,
            rule
        };
    }

    // Unknown / not-yet-implemented action — ignore
    return null;
}

/**
 * Inject a synthetic CNAME (original → target) into a resolution result.
 * Always returns a packet so the CNAME can be prepended.
 *
 * @param {object} request original dns2 request (question = original name)
 * @param {string} originalDomain
 * @param {string} targetDomain
 * @param {{ packet: object|null, buffer: Buffer|null }} result
 * @param {boolean} debug
 * @returns {{ packet: object, buffer: null }}
 */
export function injectCnameAnswer(
    request,
    originalDomain,
    targetDomain,
    result,
    debug = false
) {
    let packet = result?.packet ?? null;

    if (!packet && result?.buffer) {
        try {
            packet = Packet.parse(result.buffer);
        } catch (err) {
            logger.error('Failed to parse upstream buffer for rewrite inject', err);
            packet = Packet.createResponseFromRequest(request);
        }
    }

    if (!packet) {
        packet = Packet.createResponseFromRequest(request);
    }

    // Ensure question reflects the original name the client asked for
    if (packet.questions?.[0]) {
        packet.questions[0].name = request.questions[0].name;
    }

    const ttl = DEFAULT_CNAME_TTL;
    const cnameRr = {
        name: originalDomain,
        type: Packet.TYPE.CNAME,
        class: Packet.CLASS.IN,
        ttl,
        domain: targetDomain
    };

    if (!Array.isArray(packet.answers)) {
        packet.answers = [];
    }

    // Avoid duplicate CNAME if somehow already present
    const already = packet.answers.some(
        a =>
            a.type === Packet.TYPE.CNAME &&
            normalizeDomain(a.domain) === targetDomain &&
            normalizeDomain(a.name) === originalDomain
    );

    if (!already) {
        packet.answers.unshift(cnameRr);
    }

    if (debug) {
        logger.info(
            `REWRITE inject CNAME ${originalDomain} → ${targetDomain} (answers=${packet.answers.length})`
        );
    }

    return {
        packet,
        buffer: null
    };
}

export { MAX_REWRITE_DEPTH };
