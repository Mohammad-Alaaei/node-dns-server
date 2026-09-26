import AuthService from '../services/AuthService.mjs';

function clearAuthCookies(res) {
    const clear = 'Path=/; Max-Age=0; HttpOnly; SameSite=Strict';
    res.setHeader('Set-Cookie', [
        `token=; ${clear}`,
        `accessToken=; ${clear}`,
        `refreshToken=; ${clear}`,
        `Authorization=; ${clear}`
    ]);
}

function handleError(err, res, next) {
    if (err?.status) {
        return res.status(err.status).json({ error: err.message });
    }
    return next(err);
}

class AuthController {
    getPublicKey(_req, res) {
        res.json(AuthService.getPublicKey());
    }

    async login(req, res, next) {
        try {
            const { username, password: encryptedPassword } = req.body ?? {};
            const data = await AuthService.login({ username, encryptedPassword });
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async refreshToken(req, res, next) {
        try {
            const refreshToken =
                req.body?.refreshToken ||
                req.headers['x-refresh-token'];

            const data = await AuthService.refreshToken(refreshToken);
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async logout(req, res, next) {
        try {
            const refreshToken =
                req.body?.refreshToken ||
                req.headers['x-refresh-token'];

            const data = await AuthService.logout(refreshToken);
            clearAuthCookies(res);
            return res.json(data);
        } catch (err) {
            return next(err);
        }
    }

    async me(req, res) {
        res.json(AuthService.me(req.user));
    }

    async createUser(req, res, next) {
        try {
            const { username, password: encryptedPassword, role = 'viewer' } =
                req.body ?? {};
            const data = await AuthService.createUser({
                username,
                encryptedPassword,
                role
            });
            return res.status(201).json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async getUsers(req, res, next) {
        try {
            const data = await AuthService.getUsers(req.query);
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async getUser(req, res, next) {
        try {
            const data = await AuthService.getUserById(req.params.id, req.user);
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async updateUser(req, res, next) {
        try {
            const data = await AuthService.updateUser(
                req.user,
                req.params.id,
                req.body ?? {}
            );
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async softDeleteUser(req, res, next) {
        try {
            const data = await AuthService.softDeleteUser(
                req.user,
                req.params.id
            );
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async setUserPassword(req, res, next) {
        try {
            const data = await AuthService.setUserPassword(
                req.user,
                req.params.id,
                req.body?.password
            );
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }

    async changeOwnPassword(req, res, next) {
        try {
            const data = await AuthService.changeOwnPassword(req.user, {
                currentPassword: req.body?.currentPassword,
                newPassword: req.body?.newPassword
            });
            return res.json(data);
        } catch (err) {
            return handleError(err, res, next);
        }
    }
}

export default new AuthController();
