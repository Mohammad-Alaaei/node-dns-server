/**
 * DNS names are case-insensitive; trailing dots are equivalent.
 * Always normalize before cache keys / exact map lookups.
 */
export function normalizeDomain(domain) {
    if (!domain) {
        return domain;
    }

    let d = String(domain).trim().toLowerCase();

    while (d.endsWith('.')) {
        d = d.slice(0, -1);
    }

    return d;
}

/**
 * Same heuristic as import_domains / import_custom_dns:
 * treat pattern as regex when it contains regex metacharacters.
 */
export function isRegexPattern(pattern) {
    return /[()[\]{}*+?|^$]/.test(String(pattern ?? ''));
}

/**
 * Prepare a domain/pattern for storage as a dns_rule (or LOCAL record).
 * - If regex: keep pattern as-is (trimmed)
 * - If exact: unescape `\.` → `.` then normalizeDomain
 */
export function prepareRuleDomain(raw) {
    const trimmed = String(raw ?? '').trim();
    if (!trimmed) {
        return { error: 'domain is required' };
    }

    const regex = isRegexPattern(trimmed);
    const domain = regex
        ? trimmed
        : normalizeDomain(trimmed.replace(/\\\./g, '.'));

    return { domain, is_regex: regex };
}
