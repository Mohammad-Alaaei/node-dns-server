import ExternalResolversService from '../services/ExternalResolversService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class ExternalResolversController {
    list = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.list(req.query));
    });

    getById = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.getById(req.params.id));
    });

    create = asyncHandler(async (req, res) => {
        const data = await ExternalResolversService.create(req.body);
        const status = data.status ?? 201;
        delete data.status;
        res.status(status).json(data);
    });

    update = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.update(req.params.id, req.body));
    });

    remove = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.remove(req.params.id));
    });

    listKeys = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.listKeys(req.params.id));
    });

    createKey = asyncHandler(async (req, res) => {
        const data = await ExternalResolversService.createKey(
            req.params.id,
            req.body
        );
        const status = data.status ?? 201;
        delete data.status;
        res.status(status).json(data);
    });

    updateKey = asyncHandler(async (req, res) => {
        res.json(
            await ExternalResolversService.updateKey(
                req.params.id,
                req.params.keyId,
                req.body
            )
        );
    });

    removeKey = asyncHandler(async (req, res) => {
        res.json(
            await ExternalResolversService.removeKey(
                req.params.id,
                req.params.keyId
            )
        );
    });

    resetKeyUsage = asyncHandler(async (req, res) => {
        res.json(
            await ExternalResolversService.resetKeyUsage(
                req.params.id,
                req.params.keyId
            )
        );
    });

    lookup = asyncHandler(async (req, res) => {
        res.json(
            await ExternalResolversService.lookup(req.params.id, req.body)
        );
    });

    syncUsage = asyncHandler(async (req, res) => {
        res.json(await ExternalResolversService.syncUsage(req.params.id));
    });
}

export default new ExternalResolversController();
