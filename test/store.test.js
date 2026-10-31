import assert from 'node:assert/strict';
import test from 'node:test';
import { createStore, sameSession, serializable } from '../src/index.js';

test('put then get returns the session', () => {
  const store = createStore();
  store.put('s1', { userId: 'u1' });
  assert.deepEqual(store.get('s1'), { userId: 'u1' });
});

test('get drops expired sessions', () => {
  let clock = 0;
  const store = createStore(() => clock);
  store.put('s1', { userId: 'u1' }, 10);
  clock = 11;
  assert.equal(store.get('s1'), undefined);
  assert.equal(store.size(), 0);
});

test('userIds de-duplicates users with several sessions', () => {
  const store = createStore();
  store.put('s1', { userId: 'u1' });
  store.put('s2', { userId: 'u1' });
  store.put('s3', { userId: 'u2' });
  assert.deepEqual(store.userIds(), ['u1', 'u2']);
});

test('serializable hides private fields', () => {
  assert.deepEqual(serializable({ userId: 'u1', csrfSecret: 'x', refreshToken: 'y' }), {
    userId: 'u1',
  });
});

test('sameSession ignores private fields', () => {
  assert.equal(sameSession({ userId: 'u1', csrfSecret: 'a' }, { userId: 'u1', csrfSecret: 'b' }), true);
  assert.equal(sameSession({ userId: 'u1' }, { userId: 'u2' }), false);
});
