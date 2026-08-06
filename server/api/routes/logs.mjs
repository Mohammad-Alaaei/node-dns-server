import { Router } from 'express';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import {
    flush as flushLogger,
    getLogDir,
    getSessionLogFile
} from '../../../utils/logger.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { paginateArray, parsePagination } from '../utils/pagination.mjs';

const router = Router();

const DEFAULT_TAIL_LINES = 200;
const MAX_READ_LINES = 2000;

router.use(authenticate, requireRole('superadmin'));

/**
 * GET /api/logs?page=1&limit=20
 * List .log files in LOG_DIR (newest mtime first).
 */
router.get('/', async (req, res, next) => {
    try {
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

        return res.json(paginateArray(entries, req.query));
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/logs/:filename
 *
 * Query (option C):
 *   lines  — if set, return the last N lines (tail). Cap MAX_READ_LINES.
 *   offset — 0-based line index from start (used when lines is not set)
 *   limit  — number of lines from offset (default page size, cap MAX_READ_LINES)
 *
 * Current session file: flushes in-memory buffer before read.
 */
router.get('/:filename', async (req, res, next) => {
    try {
        const filename = req.params.filename;

        if (!isSafeLogName(filename)) {
            return res.status(400).json({ error: 'Invalid log filename' });
        }

        const logDir = path.resolve(getLogDir());
        const full = path.join(logDir, filename);

        // Resolve + ensure still under log dir (no symlink escape)
        const resolved = path.resolve(full);
        if (!resolved.startsWith(logDir + path.sep) && resolved !== logDir) {
            return res.status(400).json({ error: 'Invalid log filename' });
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
                return res.status(404).json({ error: 'Log file not found' });
            }
            throw err;
        }

        // Keep trailing empty line out of the array when file ends with \n
        const allLines = text.length === 0
            ? []
            : text.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n');

        const total = allLines.length;
        const linesParam = req.query.lines;

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
            // Range from start: offset + limit (or page + limit via shared parser)
            let start = 0;
            if (req.query.offset !== undefined && req.query.offset !== '') {
                start = Number.parseInt(String(req.query.offset), 10);
                if (!Number.isFinite(start) || start < 0) {
                    start = 0;
                }
            } else {
                const parsed = parsePagination(req.query, {
                    defaultLimit: DEFAULT_TAIL_LINES,
                    maxLimit: MAX_READ_LINES
                });
                start = parsed.offset;
            }

            let take = DEFAULT_TAIL_LINES;
            if (req.query.limit !== undefined && req.query.limit !== '') {
                take = Number.parseInt(String(req.query.limit), 10);
            } else if (req.query.offset === undefined) {
                take = parsePagination(req.query, {
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

        return res.json({
            name: filename,
            current: !!isCurrent,
            lines: slice,
            meta
        });
    } catch (err) {
        return next(err);
    }
});

/** Basename only, must end with .log, no path separators. */
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

export default router;
