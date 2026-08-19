import DnsServersService from '../services/DnsServersService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class DnsServersController {
    list = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.list(req.query));
    });

    create = asyncHandler(async (req, res) => {
        const data = await DnsServersService.create(req.body);
        res.status(data.status ?? 201).json({ server: data.server });
    });

    getById = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.getById(req.params.id));
    });

    update = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.update(req.params.id, req.body));
    });

    listRules = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.listRules(req.params.id, req.query));
    });

    createRule = asyncHandler(async (req, res) => {
        const data = await DnsServersService.createRule(req.params.id, req.body);
        res.status(data.status ?? 201).json({ rule: data.rule });
    });

    updateRule = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.updateRule(req.params.ruleId, req.body));
    });

    deleteRule = asyncHandler(async (req, res) => {
        res.json(await DnsServersService.deleteRule(req.params.ruleId));
    });
}

export default new DnsServersController();
