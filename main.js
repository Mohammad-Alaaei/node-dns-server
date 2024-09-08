const dns = require('dns');
const dgram = require('dgram');
const fs = require('fs').promises;
const readline = require('readline');

// Async function to read the domains.txt file and parse entries
const readDomainsFile = async (filename) => {
    const domainMap = new Map();

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
    return domainMap;
};

const parseDomainName = (message) => {
    let domainName = '';
    let offset = 12; // Skip the header

    while (message[offset] !== 0) {
        const length = message[offset];
        domainName += message.slice(offset + 1, offset + 1 + length).toString('ascii') + '.';
        offset += length + 1;
    }

    return domainName.slice(0, -1); // Remove the trailing dot
};

const buildResponse = (query, domainName, domainMap) => {
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
        console.error(`Domain ${domainName} not found in domains.txt`);
        return Buffer.alloc(0); // Empty response for not found domains
    }

    const response = Buffer.alloc(512); // Allocate buffer for response
    query.copy(response, 0, 0, 12); // Copy the query header into the response header
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
        response.writeUInt16BE(0xC00C, offset); // Name (offset to the domain name in the query)
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
                } else {
                    console.log(`Forwarded response sent to ${remote.address}:${remote.port}`);
                }
            });
            client.close();
        });
    });
};

const handleRequest = async (message, remote, server, domainMap, externalDNSServer) => {
    const domainName = parseDomainName(message); // Extract domain name from DNS query message
    const response = buildResponse(message, domainName, domainMap); // Pass the domainMap to buildResponse

    console.log(`domainName: ${domainName}`);

    if (response.length > 0) {
        server.send(response, 0, response.length, remote.port, remote.address, (err) => {
            if (err) {
                console.error(`Error sending response to ${remote.address}:${remote.port}: ${err.message}`);
            } else {
                console.log(`Response sent to ${remote.address}:${remote.port}`);
            }
        });
    } else {
        console.log(`Forwarding request for ${domainName} to external DNS server ${externalDNSServer}`);
        forwardToExternalDNS(message, remote, server, externalDNSServer);
    }
};

const startServer = async () => {
    const domainMap = await readDomainsFile('domains.txt');

    // Create DNS server
    const server = dgram.createSocket('udp4');

    server.on('message', (message, remote) => {
        handleRequest(message, remote, server, domainMap, '8.8.8.8');
    });

    server.on('error', (err) => {
        console.error(`Server error:\n${err.stack}`);
        server.close();
    });

    server.on('listening', () => {
        const address = server.address();
        console.log(`DNS server listening on ${address.address}:${address.port}`);
    });

    server.bind(53);
};

startServer().catch(err => console.error(`Failed to start server: ${err.message}`));
