import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import systemController from '../controllers/SystemController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin'));

/** POST /api/system/flush */
router.post('/flush', systemController.flush, nextRouter);

/** POST /api/system/reload — body: { scope?: 'all'|'records'|'dns-servers' } */
router.post('/reload', systemController.reload, nextRouter);

export default router;
