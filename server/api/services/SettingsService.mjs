import { config } from '../../../config/config.mjs';
import {
    patchSystemSettings,
    getUserSettings,
    patchUserSettings
} from '../../../database/repository.mjs';
import { httpError } from '../utils/http_errors.mjs';

class SettingsService {
    getSystem() {
        return { settings: structuredClone(config.system) };
    }

    async patchSystem(body) {
        const result = await patchSystemSettings(body ?? {});
        if (result.error) {
            throw httpError(result.error, 400);
        }
        return { settings: result.data };
    }

    async getMe(userId) {
        const settings = await getUserSettings(userId);
        return { settings };
    }

    async patchMe(userId, body) {
        const result = await patchUserSettings(userId, body ?? {});
        if (result.error) {
            throw httpError(result.error, result.status ?? 400);
        }
        return { settings: result.data };
    }
}

export default new SettingsService();
