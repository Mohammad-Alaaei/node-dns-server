/**
 * Unit tests for rewrite rules (cname_rewrite).
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { resetStore, store } from './helpers.mjs';
import {
    matchRewrite,
    expandCnameRewrite,
    resolveRewrite,
    injectCnameAnswer
} from '../services/rewrite_service.mjs';
import { REWRITE_ACTIONS } from '../config/constants.mjs';
import { Packet } from 'dns2';

function putRewrite({
    id = 1,
    name = null,
    pattern,
    action = REWRITE_ACTIONS.CNAME_REWRITE,
    params = { template: '$1.$2' },
    enabled = true
} = {}) {
    const rule = {
        id,
        name,
        pattern,
        regex: new RegExp(`^(?:${pattern})$`, 'i'),
        action,
        params,
        enabled,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };
    store.rewriteRules.push(rule);
    store.rewriteRules.sort((a, b) => b.pattern.length - a.pattern.length);
    return rule;
}

describe('rewrite match + expand (googlevideo schema)', () => {
    beforeEach(resetStore);

    const pattern = String.raw`(.+)---(.+\.googlevideo\.com)`;

    it('matches triple-dash googlevideo domains', () => {
        putRewrite({ pattern });
        const domain = 'r3---sn-g5njvh-n8vl.googlevideo.com';
        const rule = matchRewrite(domain);
        assert.ok(rule);
        assert.equal(rule.pattern, pattern);
    });

    it('expands --- to . via template', () => {
        const rule = putRewrite({ pattern, params: { template: '$1.$2' } });
        const domain = 'r3---sn-g5njvh-n8vl.googlevideo.com';
        const target = expandCnameRewrite(domain, rule);
        assert.equal(target, 'r3.sn-g5njvh-n8vl.googlevideo.com');
    });

    it('expands rr3 and r1 variants', () => {
        const rule = putRewrite({ pattern, params: { template: '$1.$2' } });
        assert.equal(
            expandCnameRewrite('rr3---sn-qxau5-btqk.googlevideo.com', rule),
            'rr3.sn-qxau5-btqk.googlevideo.com'
        );
        assert.equal(
            expandCnameRewrite('r1---sn-vh5ouxa-hjuk.googlevideo.com', rule),
            'r1.sn-vh5ouxa-hjuk.googlevideo.com'
        );
    });

    it('resolveRewrite returns action + target', () => {
        putRewrite({ pattern, params: { template: '$1.$2' } });
        const result = resolveRewrite('r3---sn-g5njvh-n8vl.googlevideo.com');
        assert.ok(result);
        assert.equal(result.action, REWRITE_ACTIONS.CNAME_REWRITE);
        assert.equal(result.target, 'r3.sn-g5njvh-n8vl.googlevideo.com');
    });

    it('does not match unrelated domains', () => {
        putRewrite({ pattern });
        assert.equal(matchRewrite('www.example.com'), null);
        assert.equal(resolveRewrite('www.example.com'), null);
    });

    it('prefers longer pattern', () => {
        putRewrite({
            id: 1,
            pattern: String.raw`.+\.googlevideo\.com`,
            params: { template: 'short.example' }
        });
        putRewrite({
            id: 2,
            pattern: String.raw`(.+)---(.+\.googlevideo\.com)`,
            params: { template: '$1.$2' }
        });

        const result = resolveRewrite('r3---sn-g5njvh-n8vl.googlevideo.com');
        assert.ok(result);
        assert.equal(result.target, 'r3.sn-g5njvh-n8vl.googlevideo.com');
        assert.equal(result.rule.id, 2);
    });

    it('skips disabled rules', () => {
        putRewrite({ pattern, enabled: false });
        assert.equal(matchRewrite('r3---sn-g5njvh-n8vl.googlevideo.com'), null);
    });

    it('returns null when template missing', () => {
        putRewrite({ pattern, params: {} });
        assert.equal(
            resolveRewrite('r3---sn-g5njvh-n8vl.googlevideo.com'),
            null
        );
    });
});

describe('injectCnameAnswer', () => {
    it('prepends CNAME and keeps original question', () => {
        const req = {
            questions: [
                {
                    name: 'r3---sn-g5njvh-n8vl.googlevideo.com',
                    type: Packet.TYPE.A,
                    class: Packet.CLASS.IN
                }
            ],
            header: { id: 1 }
        };

        const targetPacket = {
            questions: [
                {
                    name: 'r3.sn-g5njvh-n8vl.googlevideo.com',
                    type: Packet.TYPE.A,
                    class: Packet.CLASS.IN
                }
            ],
            answers: [
                {
                    name: 'r3.sn-g5njvh-n8vl.googlevideo.com',
                    type: Packet.TYPE.A,
                    class: Packet.CLASS.IN,
                    ttl: 60,
                    address: '203.0.113.50'
                }
            ]
        };

        const result = injectCnameAnswer(
            req,
            'r3---sn-g5njvh-n8vl.googlevideo.com',
            'r3.sn-g5njvh-n8vl.googlevideo.com',
            { packet: targetPacket, buffer: null }
        );

        assert.ok(result.packet);
        assert.equal(result.buffer, null);
        assert.equal(
            result.packet.questions[0].name,
            'r3---sn-g5njvh-n8vl.googlevideo.com'
        );
        assert.equal(result.packet.answers[0].type, Packet.TYPE.CNAME);
        assert.equal(
            result.packet.answers[0].domain,
            'r3.sn-g5njvh-n8vl.googlevideo.com'
        );
        assert.equal(result.packet.answers[1].type, Packet.TYPE.A);
        assert.equal(result.packet.answers[1].address, '203.0.113.50');
    });
});
