import { generateKeyPairSync, privateDecrypt, constants } from 'node:crypto';
import { config } from '../../../config/config.mjs';

/**
 * RSA-OAEP key pair for encrypting passwords on the client before login.
 * Keys are generated once at process start (or loaded from env PEMs).
 * Public key is safe to expose; private key never leaves the server.
 */

let publicKeyPem = null;
let privateKeyPem = null;

export function initLoginCrypto() {
    if (config.api.rsaPublicKey && config.api.rsaPrivateKey) {
        publicKeyPem = config.api.rsaPublicKey;
        privateKeyPem = config.api.rsaPrivateKey;
        return;
    }

    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    publicKeyPem = publicKey;
    privateKeyPem = privateKey;
}

export function getPublicKeyPem() {
    if (!publicKeyPem) {
        throw new Error('Login crypto not initialized — call initLoginCrypto() first');
    }
    return publicKeyPem;
}

/**
 * Decrypt a base64 RSA-OAEP ciphertext to the original password string.
 * Client must encrypt with the public key using RSA-OAEP + SHA-256.
 */
export function decryptPassword(encryptedBase64) {
    if (!privateKeyPem) {
        throw new Error('Login crypto not initialized');
    }

    const buffer = Buffer.from(encryptedBase64, 'base64');

    const decrypted = privateDecrypt(
        {
            key: privateKeyPem,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        buffer
    );

    return decrypted.toString('utf8');
}
