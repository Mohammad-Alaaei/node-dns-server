import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import logsController from '../controllers/LogsController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin'));

/** GET /api/logs?page=1&limit=20 */
router.get('/', logsController.list, nextRouter);

/** POST /api/logs/rotate */
router.post('/rotate', requireRole('superadmin'), logsController.rotate, nextRouter);

/** GET /api/logs/:filename?lines=200 | ?offset=0&limit=500 */
router.get('/:filename', logsController.read, nextRouter);

export default router;
