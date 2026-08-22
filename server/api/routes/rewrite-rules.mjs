import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import rewriteRulesController from '../controllers/RewriteRulesController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/rewrite-rules */
router.get('/', rewriteRulesController.list, nextRouter);

/** PATCH /api/rewrite-rules/enabled — superadmin|admin */
router.patch(
    '/enabled',
    requireRole('superadmin', 'admin'),
    rewriteRulesController.setEnabled,
    nextRouter
);

/** POST /api/rewrite-rules — superadmin|admin */
router.post(
    '/',
    requireRole('superadmin', 'admin'),
    rewriteRulesController.create,
    nextRouter
);

/** GET /api/rewrite-rules/:id */
router.get('/:id', rewriteRulesController.getById, nextRouter);

/** PATCH /api/rewrite-rules/:id — superadmin|admin */
router.patch(
    '/:id',
    requireRole('superadmin', 'admin'),
    rewriteRulesController.update,
    nextRouter
);

/** DELETE /api/rewrite-rules/:id — superadmin|admin */
router.delete(
    '/:id',
    requireRole('superadmin', 'admin'),
    rewriteRulesController.remove,
    nextRouter
);

export default router;
