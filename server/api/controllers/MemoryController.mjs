import MemoryService from '../services/MemoryService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class MemoryController {
    getStore = asyncHandler(async (req, res) => {
        res.json(MemoryService.getStore(req.query));
    });

    getPendingCache = asyncHandler(async (req, res) => {
        res.json(MemoryService.getPendingCache(req.query));
    });
}

export default new MemoryController();
