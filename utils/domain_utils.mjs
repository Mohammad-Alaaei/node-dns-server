/**
 * DNS names are case-insensitive; trailing dots are equivalent.
 * Always normalize before cache keys / exact map lookups.
 */
export function normalizeDomain(domain) {
    if (!domain) {
        return domain;
    }

    return String(domain)
        .trim()
        .toLowerCase()
        .replace(/\.+$/, '');
}