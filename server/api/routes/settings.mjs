import { Router } from 'express';
import { config } from '../../../config/config.mjs';
import {
    patchSystemSettings,
    getUserSettings,
    patchUserSettings
} from '../../../database/repository.mjs';
import { authenticate, requireRole } from '../middleware/auth.mjs';

const router = Router();

router.use(authenticate);

/**
 * GET /api/settings/system
 * Reads live config.system (single source of truth).
 */
router.get('/system',
    requireRole('superadmin', 'admin', 'viewer'),
    (_req, res) => {
        res.json({ settings: structuredClone(config.system) });
    }
);

/**
 * PATCH /api/settings/system
 * superadmin only — merges into config.system and persists DB blob.
 */
router.patch('/system', requireRole('superadmin'), async (req, res, next) => {
    try {
        const result = await patchSystemSettings(req.body ?? {});

        if (result.error) {
            return res.status(400).json({ error: result.error });
        }

        return res.json({ settings: result.data });
    } catch (err) {
        return next(err);
    }
});

/**
 * GET /api/settings/me
 */
router.get('/me', async (req, res, next) => {
    try {
        const settings = await getUserSettings(req.user.id);
        return res.json({ settings });
    } catch (err) {
        return next(err);
    }
});

/**
 * PATCH /api/settings/me
 */
router.patch('/me', async (req, res, next) => {
    try {
        const result = await patchUserSettings(req.user.id, req.body ?? {});

        if (result.error) {
            return res.status(result.status ?? 400).json({ error: result.error });
        }

        return res.json({ settings: result.data });
    } catch (err) {
        return next(err);
    }
});

export default router;
