const dns = require('dns');
const dgram = require('dgram');
const fs = require('fs').promises;
const readline = require('readline');
const path = require('path');

const DEFAULT_DNS = '178.22.122.100';
const DOMAIN_FILE = 'domains.txt';
const TXT_FILES_DIR = './';

// Async function to read all domain mappings
const readDomainsFile = async (filename) => {
    const domainMap = new Map();

    try {
        const fileStream = await fs.open(filename);
        const lineReader = readline.createInterface({
            input: fileStream.createReadStream(),
            crlfDelay: Infinity
        });

        for await (const line of lineReader) {
            if (line.trim() === '' || line.startsWith('#')) continue; // Skip empty lines and comments

            const parts = line.split(/\s+/);
            if (parts.length < 2) continue; // Malformed line, skip

            const domainRegex = parts[0];
            const ips = parts.slice(1);

            domainMap.set(domainRegex, ips);
        }

        await fileStream.close();
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
        for (const file of files) {
            if (file.endsWith('.txt') && file !== DOMAIN_FILE) {
                const dnsIP = file.replace('.txt', '');
                const domains = new Set();

                const fileStream = await fs.open(path.join(directory, file));
                const lineReader = readline.createInterface({
                    input: fileStream.createReadStream(),
                    crlfDelay: Infinity
                });

                for await (const line of lineReader) {
                    const domain = line.trim();
                    if (domain && !domain.startsWith('#')) {
                        domains.add(domain);
                    }
                }

                await fileStream.close();
                customDNSMap.set(dnsIP, domains);
            }
        }
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

    return response.slice(0, offset);
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
    console.log(`domainName: ${domainName}`);

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
        console.log(`DNS server listening on 0.0.0.0:53`);
    });

    server.bind(53);
};

startServer().catch(err => console.error(`Failed to start server: ${err.message}`));
