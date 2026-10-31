import jwt from 'jsonwebtoken';

function configuredKeys() {
  const raw = process.env.SESSION_JWT_KEYS;
  if (!raw) return {};
  return JSON.parse(raw);
}

export function keyForKid(kid) {
  return configuredKeys()[kid] ?? '';
}

export function resumeSession(store, token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new Error('resume token is not a jwt');
  const claims = jwt.verify(token, keyForKid(decoded.header.kid));
  return store.get(claims.sid);
}
