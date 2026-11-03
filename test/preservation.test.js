import assert from 'node:assert/strict';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import { createStore, keyForKid, resumeSession, signSession } from '../src/index.js';

const KEYS = { k1: 'session-key-one', k2: 'session-key-two' };

async function withKeys(fn) {
  const previous = process.env.SESSION_JWT_KEYS;
  process.env.SESSION_JWT_KEYS = JSON.stringify(KEYS);
  try {
    return await fn();
  } finally {
    if (previous === undefined) delete process.env.SESSION_JWT_KEYS;
    else process.env.SESSION_JWT_KEYS = previous;
  }
}

function resumeToken(sid, kid, key = KEYS[kid]) {
  return jwt.sign({ sid }, key, { algorithm: 'HS256', keyid: kid });
}

test('keyForKid returns the configured key and an empty key for an unknown kid', async () => {
  await withKeys(() => {
    assert.equal(keyForKid('k1'), 'session-key-one');
    assert.equal(keyForKid('k9'), '');
  });
});

test('resumeSession returns the stored session for a legitimate token', async () => {
  await withKeys(() => {
    const store = createStore();
    store.put('s1', { userId: 'u1' });
    assert.deepEqual(resumeSession(store, resumeToken('s1', 'k1')), { userId: 'u1' });
  });
});

test('resumeSession accepts any configured kid', async () => {
  await withKeys(() => {
    const store = createStore();
    store.put('s2', { userId: 'u2' });
    assert.deepEqual(resumeSession(store, resumeToken('s2', 'k2')), { userId: 'u2' });
  });
});

test('resumeSession rejects a token signed with the wrong key for its kid', async () => {
  await withKeys(() => {
    const store = createStore();
    store.put('s1', { userId: 'u1' });
    assert.throws(() => resumeSession(store, resumeToken('s1', 'k1', 'not-the-key')), jwt.JsonWebTokenError);
  });
});

test('resumeSession returns undefined once the session has expired', async () => {
  await withKeys(() => {
    let clock = 0;
    const store = createStore(() => clock);
    store.put('s1', { userId: 'u1' }, 10);
    clock = 11;
    assert.equal(resumeSession(store, resumeToken('s1', 'k1')), undefined);
  });
});

test('resumeSession rejects input that is not a jwt', async () => {
  await withKeys(() => {
    assert.throws(() => resumeSession(createStore(), 'not-a-jwt'), /not a jwt/);
  });
});

test('signSession and resumeSession round-trip through the real RS256 code path', () => {
  const store = createStore();
  store.put('s1', { userId: 'u1' });
  const token = signSession({ sid: 's1' });
  assert.deepEqual(resumeSession(store, token), { userId: 'u1' });
});
