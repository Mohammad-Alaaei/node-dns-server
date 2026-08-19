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
}

export default new LogsController();
