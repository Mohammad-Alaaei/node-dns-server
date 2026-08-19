import StatisticsService from '../services/StatisticsService.mjs';
import { asyncHandler } from '../utils/http_errors.mjs';

class StatisticsController {
    summary = asyncHandler(async (_req, res) => {
        res.json(await StatisticsService.summary());
    });

    dnsServers = asyncHandler(async (req, res) => {
        res.json(await StatisticsService.dnsServers(req.query));
    });

    topRecords = asyncHandler(async (req, res) => {
        res.json(await StatisticsService.topRecords(req.query));
    });

    resetServers = asyncHandler(async (req, res) => {
        const who = req.user?.username ?? req.user?.id ?? 'unknown';
        res.json(await StatisticsService.resetServers(req.body?.ids, who));
    });

    resetRecords = asyncHandler(async (req, res) => {
        const who = req.user?.username ?? req.user?.id ?? 'unknown';
        res.json(await StatisticsService.resetRecords(req.body?.ids, who));
    });

    resetAll = asyncHandler(async (req, res) => {
        const who = req.user?.username ?? req.user?.id ?? 'unknown';
        res.json(await StatisticsService.resetAll(who));
    });
}

export default new StatisticsController();
