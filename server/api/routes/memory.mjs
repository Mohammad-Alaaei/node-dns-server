import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import memoryController from '../controllers/MemoryController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/memory/store?page=1&limit=20 */
router.get('/store', memoryController.getStore, nextRouter);

/** GET /api/memory/pending-cache?page=1&limit=20 */
router.get('/pending-cache', memoryController.getPendingCache, nextRouter);

export default router;
