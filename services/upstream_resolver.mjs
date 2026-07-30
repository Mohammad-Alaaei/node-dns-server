import dgram from 'node:dgram';

import * as dnsMonitor from './dns_monitor.mjs';
import { saveLookupStatus } from '../database/repository.mjs';
import { DNS_TYPES, RECORD_STATUS } from '../config/constants.mjs';

import { config } from '../config/config.mjs';
import { Packet } from 'dns2';

const DNS_TIMEOUT = config.dns.timeout;
const DNS_PORT = config.dns.port;

export function forwardToExternalDns(message, server) {
    const request = Packet.parse(message);
    const started = Date.now();

    return new Promise((resolve, reject) => {

        const client = dgram.createSocket('udp4');
        const timeout = setTimeout(async () => {
            client.close();
            await dnsMonitor.timeout(server.ip);
            await saveLookupStatus(
                request.questions[0].name,
                server.id,
                DNS_TYPES[request.questions[0].type],
                RECORD_STATUS.TIMEOUT
            );
            reject(new Error(`DNS query timed out (${server.ip})`));
        }, DNS_TIMEOUT);

        client.once('error', async err => {
            clearTimeout(timeout);
            client.close();
            await dnsMonitor.failure(server.ip);
            reject(err);
        });

        client.once('message', async responseBuffer => {
            clearTimeout(timeout);
            client.close();

            try {
                const latency = Date.now() - started;

                await dnsMonitor.success(
                    server.ip,
                    latency
                );

                const packet = Packet.parse(responseBuffer);

                let status = RECORD_STATUS.SUCCESS;

                switch (packet.header.rcode) {

                    case Packet.RCODE.NXDOMAIN:
                        status = RECORD_STATUS.NXDOMAIN;
                        break;

                    case Packet.RCODE.SERVFAIL:
                        status = RECORD_STATUS.SERVFAIL;
                        break;

                    case Packet.RCODE.REFUSED:
                        status = RECORD_STATUS.REFUSED;
                        break;
                }

                if (status !== RECORD_STATUS.SUCCESS) {
                    await saveLookupStatus(
                        request.questions[0].name,
                        server.id,
                        DNS_TYPES[request.questions[0].type],
                        status
                    );
                }

                resolve({
                    packet,
                    buffer: responseBuffer,
                    server: server.ip
                });

            } catch (err) {
                await dnsMonitor.failure(server.ip);
                reject(err);
            }

        });

        client.send(message, DNS_PORT, server.ip, async err => {

            if (!err) {
                return;
            }

            clearTimeout(timeout);
            client.close();

            await dnsMonitor.failure(server.ip);
            reject(err);

        });

    });

}