export const store = {

    // Exact domains
    exactRecords: new Map(),

    // Regex domains (sorted by pattern length desc)
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
    customDnsServers: [],

    // Rewrite rules (sorted by pattern length desc, same as regexRecords)
    // [
    //   {
    //      id, name, pattern, regex, action, params, enabled,
    //      createdAt, updatedAt
    //   }
    // ]
    rewriteRules: []

};
