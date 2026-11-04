// These assertions pinned the vulnerable behaviour of jsonwebtoken 8.5.1 and were inverted when
// the dependency moved to 9.0.3: each one now asserts that the forgery is rejected.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import { createStore, resumeSession, signSession } from '../src/index.js';

function algNoneToken(kid, payload) {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({ alg: 'none', typ: 'JWT', kid })}.${part(payload)}.`;
}

async function withKeys(fn) {
  const previous = process.env.SESSION_JWT_KEYS;
  process.env.SESSION_JWT_KEYS = JSON.stringify({ k1: 'session-key-one' });
  try {
    return await fn();
  } finally {
    if (previous === undefined) delete process.env.SESSION_JWT_KEYS;
    else process.env.SESSION_JWT_KEYS = previous;
  }
}

function withRsaKeys(privatePem, publicPem, fn) {
  const prevPriv = process.env.SESSION_JWT_RSA_PRIVATE_KEY;
  const prevPub = process.env.SESSION_JWT_RSA_PUBLIC_KEY;
  process.env.SESSION_JWT_RSA_PRIVATE_KEY = privatePem;
  process.env.SESSION_JWT_RSA_PUBLIC_KEY = publicPem;
  try {
    return fn();
  } finally {
    if (prevPriv === undefined) delete process.env.SESSION_JWT_RSA_PRIVATE_KEY;
    else process.env.SESSION_JWT_RSA_PRIVATE_KEY = prevPriv;
    if (prevPub === undefined) delete process.env.SESSION_JWT_RSA_PUBLIC_KEY;
    else process.env.SESSION_JWT_RSA_PUBLIC_KEY = prevPub;
  }
}

test('secure now: resumeSession rejects an alg:none token whose kid is unknown', async () => {
  await withKeys(() => {
    const store = createStore();
    store.put('s1', { userId: 'u1' });
    assert.throws(
      () => resumeSession(store, algNoneToken('attacker-kid', { sid: 's1' })),
      (error) => error instanceof jwt.JsonWebTokenError && /invalid algorithm/.test(error.message),
    );
  });
});

test('secure now: a 1024-bit RSA key is rejected for RS256 session tokens', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

  withRsaKeys(privatePem, publicPem, () => {
    assert.throws(() => jwt.sign({ sid: 's1' }, privatePem, { algorithm: 'RS256' }), /minimum key size of 2048 bits/);
    assert.throws(() => signSession({ sid: 's1' }), /minimum key size of 2048 bits/);
  });
});
