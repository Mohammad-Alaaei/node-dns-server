import SystemService from '../services/SystemService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class SystemController {
    flush = asyncHandler(async (_req, res) => {
        res.json(await SystemService.flush());
    });

    reload = asyncHandler(async (req, res) => {
        const scope = req.body?.scope ?? 'all';
        res.json(await SystemService.reload(scope));
    });
}

export default new SystemController();
