import { handleLocalRecord } from './record_utils.mjs';

export async function handleAAAARequest(
    request,
    message,
    domain,
    debug = false
) {

    return handleLocalRecord({
        request,
        message,
        domain,
        type: 'AAAA',
        debug
    });
}