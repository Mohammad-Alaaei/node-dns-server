export const store = {

    // Exact domains
    exactRecords: new Map(),

    // Regex domains (sorted by priority)
    regexRecords: [],

    // Default upstream DNS servers
    defaultDnsServers: [],

    // Custom upstream DNS servers
    // [
    //   {
    //      domain: '.*\\.spotify\\.com',
    //      regex: /.../,
    //      servers: [
    //          { ip, priority, averageLatency, successes, failures, timeouts }
    //      ]
    //   }
    // ]
    customDnsServers: []

};