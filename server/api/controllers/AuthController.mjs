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
            if (err.status) {
                return res.status(err.status).json({ error: err.message });
            }
            return next(err);
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
            if (err.status) {
                return res.status(err.status).json({ error: err.message });
            }
            return next(err);
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
            const { username, password: encryptedPassword, role = 'viewer' } = req.body ?? {};
            const data = await AuthService.createUser({
                username,
                encryptedPassword,
                role
            });
            return res.status(201).json(data);
        } catch (err) {
            if (err.status) {
                return res.status(err.status).json({ error: err.message });
            }
            return next(err);
        }
    }

    async getUsers(req, res, next) {
        try {
            const data = await AuthService.getUsers(req.query);
            return res.json(data);
        } catch (err) {
            if (err.status) {
                return res.status(err.status).json({ error: err.message });
            }
            return next(err);
        }
    }
}

export default new AuthController();