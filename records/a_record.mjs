import { handleLocalRecord } from "./record_utils.mjs";

export async function handleARequest(
    request,
    message,
    domain,
    debug = false
) {

    return handleLocalRecord({
        request,
        message,
        domain,
        type: 'A',
        debug
    });
}