import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import recordsController from '../controllers/RecordsController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/records */
router.get('/', recordsController.list, nextRouter);

/** PATCH /api/records/enabled — superadmin|admin */
router.patch(
    '/enabled',
    requireRole('superadmin', 'admin'),
    recordsController.setEnabled,
    nextRouter
);

/** POST /api/records/promote — superadmin|admin */
router.post(
    '/promote',
    requireRole('superadmin', 'admin'),
    recordsController.promote,
    nextRouter
);

/** POST /api/records/demote — superadmin|admin */
router.post(
    '/demote',
    requireRole('superadmin', 'admin'),
    recordsController.demote,
    nextRouter
);

/** POST /api/records — superadmin|admin */
router.post(
    '/',
    requireRole('superadmin', 'admin'),
    recordsController.create,
    nextRouter
);

/** POST /api/records/:id/values — superadmin|admin */
router.post(
    '/:id/values',
    requireRole('superadmin', 'admin'),
    recordsController.addValue,
    nextRouter
);

/** PATCH /api/records/:id/values/:valueId — superadmin|admin */
router.patch(
    '/:id/values/:valueId',
    requireRole('superadmin', 'admin'),
    recordsController.updateValue,
    nextRouter
);

/** DELETE /api/records/:id/values/:valueId — superadmin|admin */
router.delete(
    '/:id/values/:valueId',
    requireRole('superadmin', 'admin'),
    recordsController.deleteValue,
    nextRouter
);

/** GET /api/records/:id */
router.get('/:id', recordsController.getById, nextRouter);

/** PATCH /api/records/:id — superadmin|admin */
router.patch(
    '/:id',
    requireRole('superadmin', 'admin'),
    recordsController.update,
    nextRouter
);

/** DELETE /api/records/:id — superadmin|admin */
router.delete(
    '/:id',
    requireRole('superadmin', 'admin'),
    recordsController.remove,
    nextRouter
);

export default router;
