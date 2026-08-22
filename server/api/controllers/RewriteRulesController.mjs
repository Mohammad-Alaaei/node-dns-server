import RewriteRulesService from '../services/RewriteRulesService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class RewriteRulesController {
    list = asyncHandler(async (req, res) => {
        res.json(await RewriteRulesService.list(req.query));
    });

    getById = asyncHandler(async (req, res) => {
        res.json(await RewriteRulesService.getById(req.params.id));
    });

    create = asyncHandler(async (req, res) => {
        const data = await RewriteRulesService.create(req.body);
        const status = data.status ?? 201;
        delete data.status;
        res.status(status).json(data);
    });

    update = asyncHandler(async (req, res) => {
        res.json(await RewriteRulesService.update(req.params.id, req.body));
    });

    remove = asyncHandler(async (req, res) => {
        res.json(await RewriteRulesService.remove(req.params.id));
    });

    setEnabled = asyncHandler(async (req, res) => {
        const { ids, enabled } = req.body ?? {};
        res.json(await RewriteRulesService.setEnabled(ids, enabled));
    });
}

export default new RewriteRulesController();
