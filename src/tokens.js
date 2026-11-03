import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

// jsonwebtoken 9.x enforces a minimum RSA key size of 2048 bits for RS256.
const RSA_MODULUS_LENGTH = 2048;

const defaultKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: RSA_MODULUS_LENGTH });
const DEFAULT_PRIVATE_PEM = defaultKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const DEFAULT_PUBLIC_PEM = defaultKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

function configuredKeys() {
  const raw = process.env.SESSION_JWT_KEYS;
  if (!raw) return {};
  return JSON.parse(raw);
}

function rsaPrivateKey() {
  return process.env.SESSION_JWT_RSA_PRIVATE_KEY ?? DEFAULT_PRIVATE_PEM;
}

function rsaPublicKey() {
  return process.env.SESSION_JWT_RSA_PUBLIC_KEY ?? DEFAULT_PUBLIC_PEM;
}

export function keyForKid(kid) {
  return configuredKeys()[kid] ?? '';
}

export function signSession(payload) {
  return jwt.sign(payload, rsaPrivateKey(), { algorithm: 'RS256', expiresIn: '1h' });
}

export function resumeSession(store, token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new Error('resume token is not a jwt');

  if (decoded.header.alg === 'RS256') {
    const claims = jwt.verify(token, rsaPublicKey(), { algorithms: ['RS256'] });
    return store.get(claims.sid);
  }

  const claims = jwt.verify(token, keyForKid(decoded.header.kid), { algorithms: ['HS256'] });
  return store.get(claims.sid);
}
