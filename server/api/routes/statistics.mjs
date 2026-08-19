import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.mjs';
import { nextRouter } from '../middleware/nextRouter.mjs';
import statisticsController from '../controllers/StatisticsController.mjs';

const router = Router();

router.use(authenticate, requireRole('superadmin', 'admin', 'viewer'));

/** GET /api/statistics/summary */
router.get('/summary', statisticsController.summary, nextRouter);

/** GET /api/statistics/dns-servers */
router.get('/dns-servers', statisticsController.dnsServers, nextRouter);

/** GET /api/statistics/top-records */
router.get('/top-records', statisticsController.topRecords, nextRouter);

/** POST /api/statistics/reset/servers — superadmin */
router.post(
    '/reset/servers',
    requireRole('superadmin'),
    statisticsController.resetServers,
    nextRouter
);

/** POST /api/statistics/reset/records — superadmin */
router.post(
    '/reset/records',
    requireRole('superadmin'),
    statisticsController.resetRecords,
    nextRouter
);

/** POST /api/statistics/reset/all — superadmin */
router.post(
    '/reset/all',
    requireRole('superadmin'),
    statisticsController.resetAll,
    nextRouter
);

export default router;
