import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import externalResolversController from '../controllers/ExternalResolversController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/external-resolvers */
router.get('/', externalResolversController.list, nextRouter);

/** POST /api/external-resolvers — superadmin|admin */
router.post(
    '/',
    requireRole('superadmin', 'admin'),
    externalResolversController.create,
    nextRouter
);

/** GET /api/external-resolvers/:id */
router.get('/:id', externalResolversController.getById, nextRouter);

/** PATCH /api/external-resolvers/:id — superadmin|admin */
router.patch(
    '/:id',
    requireRole('superadmin', 'admin'),
    externalResolversController.update,
    nextRouter
);

/** DELETE /api/external-resolvers/:id — superadmin|admin */
router.delete(
    '/:id',
    requireRole('superadmin', 'admin'),
    externalResolversController.remove,
    nextRouter
);

/** GET /api/external-resolvers/:id/keys */
router.get('/:id/keys', externalResolversController.listKeys, nextRouter);

/** POST /api/external-resolvers/:id/keys — superadmin|admin */
router.post(
    '/:id/keys',
    requireRole('superadmin', 'admin'),
    externalResolversController.createKey,
    nextRouter
);

/** PATCH /api/external-resolvers/:id/keys/:keyId — superadmin|admin */
router.patch(
    '/:id/keys/:keyId',
    requireRole('superadmin', 'admin'),
    externalResolversController.updateKey,
    nextRouter
);

/** DELETE /api/external-resolvers/:id/keys/:keyId — superadmin|admin */
router.delete(
    '/:id/keys/:keyId',
    requireRole('superadmin', 'admin'),
    externalResolversController.removeKey,
    nextRouter
);

/** POST /api/external-resolvers/:id/keys/:keyId/reset-usage — superadmin|admin */
router.post(
    '/:id/keys/:keyId/reset-usage',
    requireRole('superadmin', 'admin'),
    externalResolversController.resetKeyUsage,
    nextRouter
);

/** POST /api/external-resolvers/:id/lookup — manual lookup (queue) */
router.post(
    '/:id/lookup',
    requireRole('superadmin', 'admin', 'viewer'),
    externalResolversController.lookup,
    nextRouter
);

/** POST /api/external-resolvers/:id/sync-usage — pull Usage from provider */
router.post(
    '/:id/sync-usage',
    requireRole('superadmin', 'admin'),
    externalResolversController.syncUsage,
    nextRouter
);

export default router;
