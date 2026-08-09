import express from 'express';
import { config } from '../../config/config.mjs';
import { ensureBootstrapAdmin } from './auth/bootstrap.mjs';
import { initLoginCrypto } from './auth/crypto.mjs';
import { requestLogger } from './middleware/requestLogger.mjs';
import { corsMiddleware } from './middleware/cors.mjs';
import authRoutes from './routes/auth.mjs';
import memoryRoutes from './routes/memory.mjs';
import recordsRoutes from './routes/records.mjs';
import dnsServersRoutes from './routes/dns-servers.mjs';
import logsRoutes from './routes/logs.mjs';
import systemRoutes from './routes/system.mjs';
import statisticsRoutes from './routes/statistics.mjs';
import settingsRoutes from './routes/settings.mjs';
import * as logger from '../../utils/logger.mjs';

let server = null;

export async function startApi() {
    if (!config.api.enabled) {
        logger.info('API disabled (API_ENABLED=false)');
        return;
    }

    initLoginCrypto();
    await ensureBootstrapAdmin();

    const app = express();

    // Nested query keys: filter[source]=CACHE → req.query.filter.source
    app.set('query parser', 'extended');

    // Trust proxy if behind reverse proxy (correct req.ip)
    app.set('trust proxy', 1);

    app.use(corsMiddleware);
    app.use(requestLogger);
    app.use(express.json({ limit: '1mb' }));

    app.get('/api/health', (_req, res) => {
        res.json({ ok: true });
    });

    app.use('/api/auth', authRoutes);
    app.use('/api/memory', memoryRoutes);
    app.use('/api/records', recordsRoutes);
    app.use('/api/dns-servers', dnsServersRoutes);
    app.use('/api/logs', logsRoutes);
    app.use('/api/system', systemRoutes);
    app.use('/api/statistics', statisticsRoutes);
    app.use('/api/settings', settingsRoutes);

    // 404 for anything not matched above
    app.use((req, res) => {
        res.status(404).json({
            error: 'Not found',
            path: req.originalUrl,
            method: req.method
        });
    });

    // Central error handler (must have 4 args)
    app.use((err, _req, res, _next) => {
        logger.error(err);
        res.status(500).json({ error: 'Internal server error' });
    });

    await new Promise((resolve, reject) => {
        server = app.listen(config.api.port, config.api.host, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });

    logger.success(`API listening on http://${config.api.host}:${config.api.port}`);
}

export async function stopApi() {
    if (!server) return;

    await new Promise((resolve) => {
        server.close(() => resolve());
    });

    server = null;
}
