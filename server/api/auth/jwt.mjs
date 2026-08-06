import jwt from 'jsonwebtoken';
import { config } from '../../../config/config.mjs';

export function signToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        role: user.role
    };

    return jwt.sign(payload, config.api.jwtSecret, {
        expiresIn: config.api.jwtExpiresIn
    });
}

export function verifyToken(token) {
    return jwt.verify(token, config.api.jwtSecret);
}
