import { User } from '../../../database/models/index.mjs';
import { config } from '../../../config/config.mjs';
import { hashPassword } from './password.mjs';
import * as logger from '../../../utils/logger.mjs';

/**
 * If the users table is empty and ADMIN_PASSWORD is set,
 * create the initial superadmin from env.
 */
export async function ensureBootstrapAdmin() {
    const count = await User.count();

    if (count > 0) {
        return;
    }

    const { username, password } = config.admin;

    if (!password) {
        logger.warn(
            'No users in DB and ADMIN_PASSWORD is empty — ' +
            'set ADMIN_USERNAME / ADMIN_PASSWORD in .env then restart to create superadmin'
        );
        return;
    }

    const now = Date.now();
    const password_hash = await hashPassword(password);

    await User.create({
        username,
        password_hash,
        role: 'superadmin',
        created_at: now,
        updated_at: now
    });

    logger.success(`Bootstrap superadmin created: ${username}`);
}
