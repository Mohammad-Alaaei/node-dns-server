import dgram from 'node:dgram';

import * as dnsMonitor from './dns_monitor.mjs';

import { config } from '../config/config.mjs';
import { Packet } from 'dns2';

const DNS_TIMEOUT = config.dns.timeout;
const DNS_PORT = config.dns.port;

export function forwardToExternalDns(message, dnsServer) {

    const started = Date.now();

    return new Promise((resolve, reject) => {

        const client = dgram.createSocket('udp4');
        const timeout = setTimeout(async () => {
            client.close();
            await dnsMonitor.timeout(dnsServer);
            reject(new Error(`DNS query timed out (${dnsServer})`));
        }, DNS_TIMEOUT);

        client.once('error', async err => {
            clearTimeout(timeout);
            client.close();
            await dnsMonitor.failure(dnsServer);
            reject(err);
        });

        client.once('message', async responseBuffer => {
            clearTimeout(timeout);
            client.close();

            try {
                const latency = Date.now() - started;
                
                await dnsMonitor.success(
                    dnsServer,
                    latency
                );

                const packet = Packet.parse(responseBuffer);

                resolve({
                    packet,
                    buffer: responseBuffer,
                    server: dnsServer
                });

            } catch (err) {
                await dnsMonitor.failure(dnsServer);
                reject(err);
            }

        });

        client.send(message, DNS_PORT, dnsServer, async err => {

            if (!err) {
                return;
            }

            clearTimeout(timeout);
            client.close();

            await dnsMonitor.failure(dnsServer);
            reject(err);

        });

    });

}