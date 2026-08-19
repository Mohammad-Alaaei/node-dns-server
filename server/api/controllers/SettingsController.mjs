import SettingsService from '../services/SettingsService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class SettingsController {
    getSystem = asyncHandler(async (_req, res) => {
        res.json(SettingsService.getSystem());
    });

    patchSystem = asyncHandler(async (req, res) => {
        res.json(await SettingsService.patchSystem(req.body));
    });

    getMe = asyncHandler(async (req, res) => {
        res.json(await SettingsService.getMe(req.user.id));
    });

    patchMe = asyncHandler(async (req, res) => {
        res.json(await SettingsService.patchMe(req.user.id, req.body));
    });
}

export default new SettingsController();
