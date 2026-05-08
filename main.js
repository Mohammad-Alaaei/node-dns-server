const dns = require('dns');
const dgram = require('dgram');
const fs = require('fs').promises;
const readline = require('readline');
const path = require('path');

const DEFAULT_DNS = '178.22.122.101';
const DOMAIN_FILE = 'domains.txt';
const TXT_FILES_DIR = './';

// Async function to read all domain mappings
const readDomainsFile = async (filename) => {
    const domainMap = new Map();
    try {
        const data = await fs.readFile(filename, 'utf8');
        const lines = data.split('\n');

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue; // Skip empty lines and comments

            const parts = trimmed.split(/\s+/);
            if (parts.length < 2) continue;

            domainMap.set(parts[0], parts.slice(1)); // First is regex, rest are IPs
        }
    } catch (err) {
        console.error(`Error reading ${filename}: ${err.message}`);
    }
    return domainMap;
};


// Read all custom DNS files (e.g., "178.22.122.100.txt")
const readCustomDNSFiles = async (directory = TXT_FILES_DIR) => {
    const customDNSMap = new Map();

    try {
        const files = await fs.readdir(directory);
        const readPromises = files
            .filter(file => file.endsWith('.txt') && file !== DOMAIN_FILE)
            .map(async (file) => {
                const dnsIP = file.replace('.txt', '');
                const data = await fs.readFile(path.join(directory, file), 'utf8');
                const domains = new Set(
                    data.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'))
                );
                customDNSMap.set(dnsIP, domains);
            });

        await Promise.all(readPromises);
    } catch (err) {
        console.error(`Error reading custom DNS files: ${err.message}`);
    }

    return customDNSMap;
};


const parseDomainName = (message) => {
    let domainName = '';
    let offset = 12; // Skip the header

    while (message[offset] !== 0) {
        const length = message[offset];
        domainName += message.slice(offset + 1, offset + 1 + length).toString('ascii') + '.';
        offset += length + 1;
    }

    return domainName.slice(0, -1); // Remove trailing dot
};

const buildResponse = (query, domainName, domainMap) => {
    if (!domainMap) {
        console.error('Error: domainMap is undefined in buildResponse()');
        return Buffer.alloc(0);
    }

    if (domainName === '1.0.0.127.in-addr.arpa') {
        console.log('Handling reverse lookup for 127.0.0.1');
        return buildPTRResponse(query, 'localhost');
    }

    let ipAddresses = [];

    for (const [domainRegex, ips] of domainMap.entries()) {
        const regex = new RegExp(domainRegex, 'i'); // Case insensitive regex match
        if (regex.test(domainName)) {
            ipAddresses = ips;
            console.log(`FOUND!: ${ipAddresses}`);
            break;
        }
    }

    if (ipAddresses.length === 0) {
        console.error(`Domain ${domainName} not found in ${DOMAIN_FILE}`);
        return Buffer.alloc(0); // Empty response for not found domains
    }

    return buildARecordResponse(query, domainName, ipAddresses);
};

const buildARecordResponse = (query, domainName, ipAddresses) => {
    const response = Buffer.alloc(512);
    query.copy(response, 0, 0, 12); // Copy query header
    response.writeUInt16BE(0x8180, 2); // Standard query response, no error
    response.writeUInt16BE(1, 4); // Questions count
    response.writeUInt16BE(ipAddresses.length, 6); // Answer count
    response.writeUInt16BE(0, 8); // Authority RR count
    response.writeUInt16BE(0, 10); // Additional RR count

    let offset = 12;
    const splitDomain = domainName.split('.');
    splitDomain.forEach((part) => {
        response.writeUInt8(part.length, offset++);
        response.write(part, offset, part.length, 'ascii');
        offset += part.length;
    });
    response.writeUInt8(0, offset++); // Null byte to end the domain name
    response.writeUInt16BE(1, offset); // Type A record
    response.writeUInt16BE(1, offset + 2); // Class IN
    offset += 4;

    ipAddresses.forEach((ip) => {
        response.writeUInt16BE(0xC00C, offset); // Name offset
        offset += 2;
        response.writeUInt16BE(1, offset); // Type A record
        response.writeUInt16BE(1, offset + 2); // Class IN
        response.writeUInt32BE(60, offset + 4); // TTL
        response.writeUInt16BE(4, offset + 8); // RDLength
        offset += 10;
        ip.split('.').forEach((octet) => {
            response.writeUInt8(parseInt(octet, 10), offset++);
        });
    });

    return response.subarray(0, offset);
};

const buildPTRResponse = (query, hostname) => {
    const response = Buffer.alloc(512);
    query.copy(response, 0, 0, 12); // Copy query header
    response.writeUInt16BE(0x8180, 2); // Standard query response, no error
    response.writeUInt16BE(1, 4); // Questions count
    response.writeUInt16BE(1, 6); // Answer count
    response.writeUInt16BE(0, 8); // Authority RR count
    response.writeUInt16BE(0, 10); // Additional RR count

    let offset = 12;
    response.writeUInt16BE(0xC00C, offset); // Name offset
    offset += 2;
    response.writeUInt16BE(12, offset); // Type PTR
    response.writeUInt16BE(1, offset + 2); // Class IN
    response.writeUInt32BE(60, offset + 4); // TTL
    offset += 8;

    const parts = hostname.split('.');
    response.writeUInt16BE(hostname.length + 2, offset); // RDLength
    offset += 2;

    parts.forEach((part) => {
        response.writeUInt8(part.length, offset++);
        response.write(part, offset, part.length, 'ascii');
        offset += part.length;
    });
    response.writeUInt8(0, offset++); // Null byte

    return response.subarray(0, offset);
};

const forwardToExternalDNS = (message, remote, server, externalDNSServer) => {
    const client = dgram.createSocket('udp4');
    client.send(message, 0, message.length, 53, externalDNSServer, (err) => {
        if (err) {
            console.error(`Error forwarding request to ${externalDNSServer}: ${err.message}`);
            client.close();
            return;
        }
        client.on('message', (responseMessage) => {
            server.send(responseMessage, 0, responseMessage.length, remote.port, remote.address, (err) => {
                if (err) {
                    console.error(`Error sending response to ${remote.address}:${remote.port}: ${err.message}`);
                }
            });
            client.close();
        });
    });
};

const handleRequest = async (message, remote, server, domainMap, customDNSMap, defaultDNSServer) => {
    const domainName = parseDomainName(message);
    console.log('=============')
    console.log(`domainName: ${domainName}`);

    // Ignore reverse DNS lookups
    if (domainName.endsWith('.in-addr.arpa')) {
        console.log(`Ignoring reverse lookup for ${domainName}`);
        return;
    }

    // 1. Check in `DOMAIN_FILE`
    const response = buildResponse(message, domainName, domainMap);
    if (response.length > 0) {
        server.send(response, 0, response.length, remote.port, remote.address);
        return;
    }

    // 2. Check in custom DNS files
    for (const [dnsServer, domains] of customDNSMap.entries()) {
        for (const domainRegex of domains) {
            const regex = new RegExp(domainRegex, 'i');
            if (regex.test(domainName)) {
                console.log(`Resolving ${domainName} using custom DNS server ${dnsServer}`);
                forwardToExternalDNS(message, remote, server, dnsServer);
                return;
            }
        }
    }

    // 3. Fallback to default DNS
    console.log(`Forwarding ${domainName} to default DNS server ${defaultDNSServer}`);
    forwardToExternalDNS(message, remote, server, defaultDNSServer);
};


const startServer = async () => {
    const domainMap = await readDomainsFile(DOMAIN_FILE);
    const customDNSMap = await readCustomDNSFiles(); // Read all custom DNS mappings

    const server = dgram.createSocket('udp4');
    server.on('message', (message, remote) => {
        handleRequest(message, remote, server, domainMap, customDNSMap, DEFAULT_DNS); // Default DNS
    });

    server.on('error', (err) => {
        console.error(`Server error:\n${err.stack}`);
        server.close();
    });

    server.on('listening', () => {
        const address = server.address();
        console.log(`DNS server listening on ${address.address}:${address.port}`);
    });

    server.bind(53, '127.0.0.1');
};

startServer().catch(err => console.error(`Failed to start server: ${err.message}`));
