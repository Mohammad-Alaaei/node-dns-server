import { handleLocalRecord } from './record_utils.mjs';

export async function handleCNAMERequest(
    request,
    message,
    domain,
    debug = false
) {

    return handleLocalRecord({
        request,
        message,
        domain,
        type: 'CNAME',
        debug
    });
}