// These assertions pinned the vulnerable behaviour of jsonwebtoken 8.5.1 and were inverted when the
// dependency moved to 9.0.3 (GHSA-8cf7-32gw-wr33, GHSA-hjrf-2m68-5959, GHSA-qwph-4952-7xr6).
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import { createStore, resumeSession } from '../src/index.js';

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
      jwt.JsonWebTokenError,
    );
  });
});

test('secure now: resumeSession rejects an RS256 token signed with a 1024-bit RSA key', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

  withRsaKeys(privatePem, publicPem, () => {
    let token;
    try {
      token = jwt.sign({ sid: 's1' }, privatePem, { algorithm: 'RS256' });
    } catch (error) {
      // Pass only on the specific key-size rejection, not any sign error.
      assert.match(error.message, /minimum key size/i);
      return;
    }
    const store = createStore();
    store.put('s1', { userId: 'u1' });
    assert.throws(() => resumeSession(store, token));
  });
});
