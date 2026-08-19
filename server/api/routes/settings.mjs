import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import settingsController from '../controllers/SettingsController.mjs';

const router = Router();

router.use(authenticate);

/** GET /api/settings/system */
router.get(
    '/system',
    requireRole('superadmin', 'admin', 'viewer'),
    settingsController.getSystem,
    nextRouter
);

/** PATCH /api/settings/system — superadmin */
router.patch(
    '/system',
    requireRole('superadmin'),
    settingsController.patchSystem,
    nextRouter
);

/** GET /api/settings/me */
router.get('/me', settingsController.getMe, nextRouter);

/** PATCH /api/settings/me */
router.patch('/me', settingsController.patchMe, nextRouter);

export default router;
