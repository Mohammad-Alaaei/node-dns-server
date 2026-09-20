import fs from 'node:fs';
import LogsService from '../services/LogsService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class LogsController {
    list = asyncHandler(async (req, res) => {
        res.json(await LogsService.list(req.query));
    });

    rotate = asyncHandler(async (req, res) => {
        const who = req.user?.username ?? req.user?.id ?? 'unknown';
        res.json(await LogsService.rotate(who));
    });

    read = asyncHandler(async (req, res) => {
        res.json(await LogsService.read(req.params.filename, req.query));
    });

    download = asyncHandler(async (req, res) => {
        const info = await LogsService.getDownloadPath(req.params.filename);

        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader(
            'Content-Disposition',
            `attachment; filename="${info.name}"`
        );
        res.setHeader('Content-Length', String(info.size));
        res.setHeader('Cache-Control', 'no-store');

        const stream = fs.createReadStream(info.path);
        stream.on('error', (err) => {
            if (!res.headersSent) {
                res.status(500).json({ error: 'Failed to read log file' });
            } else {
                res.destroy(err);
            }
        });
        stream.pipe(res);
    });

    remove = asyncHandler(async (req, res) => {
        res.json(await LogsService.delete(req.params.filename));
    });
}

export default new LogsController();
