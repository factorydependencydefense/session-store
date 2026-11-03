// These assertions pinned the alg:none signature bypass of jsonwebtoken 8.5.1 and were inverted
// when GHSA-hjrf-2m68-5959 and GHSA-qwph-4952-7xr6 were fixed by the upgrade to jsonwebtoken 9.0.3.
import assert from 'node:assert/strict';
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
