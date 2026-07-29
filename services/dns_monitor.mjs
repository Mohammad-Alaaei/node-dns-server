import {
    recordDnsSuccess,
    recordDnsFailure,
    recordDnsTimeout
} from '../database/repository.mjs';

export async function success(ip, latency) {

    try {
        await recordDnsSuccess(ip, latency);
    } catch {}
}

export async function failure(ip) {

    try {
        await recordDnsFailure(ip);
    } catch {}
}

export async function timeout(ip) {

    try {
        await recordDnsTimeout(ip);
    } catch {}
}