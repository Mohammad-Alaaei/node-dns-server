export function mergeRecords(target, source, key) {

    const values = new Set(
        target.map(record => record[key])
    );

    for (const record of source) {

        if (values.has(record[key])) {
            continue;
        }

        values.add(record[key]);
        target.push(record);
    }
}