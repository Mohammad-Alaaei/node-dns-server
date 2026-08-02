import { Packet } from "dns2";

export const CACHE_LEVELS = {
    ALL: 'ALL',
    CUSTOM_ONLY: 'CUSTOM_ONLY',
    FILTERED_ONLY: 'FILTERED_ONLY',
    NONE: 'NONE'
};

export const DNS_TYPES = {
    ...Object.fromEntries(
        Object.entries(Packet.TYPE).map(([name, value]) => [value, name])
    ),
    65: 'HTTPS'
};

export const RECORD_STATUS = {
    SUCCESS: 'SUCCESS',
    FILTERED: 'FILTERED',
    TIMEOUT: 'TIMEOUT',
    NXDOMAIN: 'NXDOMAIN',
    SERVFAIL: 'SERVFAIL',
    REFUSED: 'REFUSED'
};

export const RECORD_SOURCE = {
    LOCAL: 'LOCAL',
    CACHE: 'CACHE',
    FILTERED: 'FILTERED'
}