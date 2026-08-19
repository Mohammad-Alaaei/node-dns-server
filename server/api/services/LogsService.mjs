import { promises as fs } from 'node:fs';
import path from 'node:path';
import {
    flush as flushLogger,
    getLogDir,
    getSessionLogFile,
    rotate as rotateLogger
} from '../../../utils/logger.mjs';
import { paginateArray, parsePagination } from '../utils/pagination.mjs';
import { httpError } from '../utils/http_errors.mjs';

const DEFAULT_TAIL_LINES = 200;
const MAX_READ_LINES = 2000;

function isSafeLogName(name) {
    if (typeof name !== 'string' || !name) {
        return false;
    }
    if (name !== path.basename(name)) {
        return false;
    }
    if (name.includes('..') || name.includes('/') || name.includes('\\')) {
        return false;
    }
    return name.toLowerCase().endsWith('.log');
}

class LogsService {
    async list(query) {
        const logDir = path.resolve(getLogDir());
        await fs.mkdir(logDir, { recursive: true });

        const sessionFile = getSessionLogFile();
        const sessionBase = sessionFile ? path.basename(sessionFile) : null;

        const names = await fs.readdir(logDir);
        const entries = [];

        for (const name of names) {
            if (!isSafeLogName(name)) {
                continue;
            }

            const full = path.join(logDir, name);
            let st;
            try {
                st = await fs.stat(full);
            } catch {
                continue;
            }

            if (!st.isFile()) {
                continue;
            }

            entries.push({
                name,
                size: st.size,
                mtime: st.mtimeMs,
                current: sessionBase != null && name === sessionBase
            });
        }

        entries.sort((a, b) => b.mtime - a.mtime);
        return paginateArray(entries, query);
    }

    async rotate(who) {
        const result = await rotateLogger(`manual by ${who}`);
        if (!result.ok) {
            throw httpError(result.error, 409);
        }
        return result;
    }

    async read(filename, query) {
        if (!isSafeLogName(filename)) {
            throw httpError('Invalid log filename', 400);
        }

        const logDir = path.resolve(getLogDir());
        const full = path.join(logDir, filename);
        const resolved = path.resolve(full);

        if (!resolved.startsWith(logDir + path.sep) && resolved !== logDir) {
            throw httpError('Invalid log filename', 400);
        }

        const sessionFile = getSessionLogFile();
        const isCurrent =
            sessionFile &&
            path.resolve(sessionFile) === resolved;

        if (isCurrent) {
            await flushLogger();
        }

        let text;
        try {
            text = await fs.readFile(resolved, 'utf8');
        } catch (err) {
            if (err && err.code === 'ENOENT') {
                throw httpError('Log file not found', 404);
            }
            throw err;
        }

        const allLines = text.length === 0
            ? []
            : text.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n');

        const total = allLines.length;
        const linesParam = query.lines;

        let slice;
        let meta;

        if (linesParam !== undefined && linesParam !== '') {
            let n = Number.parseInt(String(linesParam), 10);
            if (!Number.isFinite(n) || n < 1) {
                n = DEFAULT_TAIL_LINES;
            }
            if (n > MAX_READ_LINES) {
                n = MAX_READ_LINES;
            }

            const start = Math.max(0, total - n);
            slice = allLines.slice(start);
            meta = {
                mode: 'tail',
                lines: n,
                from: start,
                to: total,
                total
            };
        } else {
            let start = 0;
            if (query.offset !== undefined && query.offset !== '') {
                start = Number.parseInt(String(query.offset), 10);
                if (!Number.isFinite(start) || start < 0) {
                    start = 0;
                }
            } else {
                const parsed = parsePagination(query, {
                    defaultLimit: DEFAULT_TAIL_LINES,
                    maxLimit: MAX_READ_LINES
                });
                start = parsed.offset;
            }

            let take = DEFAULT_TAIL_LINES;
            if (query.limit !== undefined && query.limit !== '') {
                take = Number.parseInt(String(query.limit), 10);
            } else if (query.offset === undefined) {
                take = parsePagination(query, {
                    defaultLimit: DEFAULT_TAIL_LINES,
                    maxLimit: MAX_READ_LINES
                }).limit;
            }
            if (!Number.isFinite(take) || take < 1) {
                take = DEFAULT_TAIL_LINES;
            }
            if (take > MAX_READ_LINES) {
                take = MAX_READ_LINES;
            }

            slice = allLines.slice(start, start + take);
            meta = {
                mode: 'range',
                offset: start,
                limit: take,
                from: start,
                to: Math.min(total, start + take),
                total
            };
        }

        return {
            name: filename,
            current: !!isCurrent,
            lines: slice,
            meta
        };
    }
}

export default new LogsService();
