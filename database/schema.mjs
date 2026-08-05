import { authenticate } from './connection.mjs';
import './models/index.mjs';

/**
 * Verifies DB connectivity at startup.
 * Schema is managed by Sequelize migrations (npm run db:migrate).
 */
export async function createSchema() {
    await authenticate();
}
