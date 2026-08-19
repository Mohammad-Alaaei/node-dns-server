import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import dnsServersController from '../controllers/DnsServersController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/dns-servers */
router.get('/', dnsServersController.list, nextRouter);

/** POST /api/dns-servers — superadmin */
router.post('/', requireRole('superadmin'), dnsServersController.create, nextRouter);

/** PATCH /api/dns-servers/rules/:ruleId — before /:id */
router.patch(
    '/rules/:ruleId',
    requireRole('superadmin'),
    dnsServersController.updateRule,
    nextRouter
);

/** DELETE /api/dns-servers/rules/:ruleId */
router.delete(
    '/rules/:ruleId',
    requireRole('superadmin'),
    dnsServersController.deleteRule,
    nextRouter
);

/** GET /api/dns-servers/:id/rules */
router.get('/:id/rules', dnsServersController.listRules, nextRouter);

/** POST /api/dns-servers/:id/rules — superadmin */
router.post(
    '/:id/rules',
    requireRole('superadmin'),
    dnsServersController.createRule,
    nextRouter
);

/** GET /api/dns-servers/:id */
router.get('/:id', dnsServersController.getById, nextRouter);

/** PATCH /api/dns-servers/:id — superadmin */
router.patch(
    '/:id',
    requireRole('superadmin'),
    dnsServersController.update,
    nextRouter
);

export default router;
