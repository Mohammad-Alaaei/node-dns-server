import { store } from './store.mjs';

export function putRecord(record) {

    if (!record.isRegex) {
        store.exactRecords.set(record.domain, record);
    }

    return record;
}