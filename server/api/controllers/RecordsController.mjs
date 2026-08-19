import RecordsService from '../services/RecordsService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class RecordsController {
    list = asyncHandler(async (req, res) => {
        res.json(await RecordsService.list(req.query));
    });

    setEnabled = asyncHandler(async (req, res) => {
        const { ids, enabled } = req.body ?? {};
        res.json(await RecordsService.setEnabled(ids, enabled));
    });

    promote = asyncHandler(async (req, res) => {
        res.json(await RecordsService.promote(req.body?.ids));
    });

    demote = asyncHandler(async (req, res) => {
        res.json(await RecordsService.demote(req.body?.ids));
    });

    create = asyncHandler(async (req, res) => {
        const data = await RecordsService.create(req.body);
        const status = data.status ?? 201;
        delete data.status;
        res.status(status).json(data);
    });

    update = asyncHandler(async (req, res) => {
        res.json(await RecordsService.update(req.params.id, req.body));
    });

    remove = asyncHandler(async (req, res) => {
        res.json(await RecordsService.remove(req.params.id));
    });

    addValue = asyncHandler(async (req, res) => {
        const data = await RecordsService.addValue(req.params.id, req.body);
        const status = data.status ?? 201;
        delete data.status;
        res.status(status).json(data);
    });

    updateValue = asyncHandler(async (req, res) => {
        res.json(
            await RecordsService.updateValue(
                req.params.id,
                req.params.valueId,
                req.body
            )
        );
    });

    deleteValue = asyncHandler(async (req, res) => {
        res.json(
            await RecordsService.deleteValue(req.params.id, req.params.valueId)
        );
    });

    getById = asyncHandler(async (req, res) => {
        res.json(await RecordsService.getById(req.params.id));
    });
}

export default new RecordsController();
