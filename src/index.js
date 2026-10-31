import isEqual from 'lodash/isEqual.js';
import omit from 'lodash/omit.js';
import uniq from 'lodash/uniq.js';

const PRIVATE_FIELDS = ['csrfSecret', 'refreshToken'];

export function createStore(now = () => Date.now()) {
  const sessions = new Map();

  return {
    put(id, session, ttlMs = 60_000) {
      sessions.set(id, { session, expiresAt: now() + ttlMs });
      return id;
    },
    get(id) {
      const entry = sessions.get(id);
      if (!entry) return undefined;
      if (entry.expiresAt <= now()) {
        sessions.delete(id);
        return undefined;
      }
      return entry.session;
    },
    userIds() {
      return uniq([...sessions.values()].map((entry) => entry.session.userId));
    },
    size() {
      return sessions.size;
    },
  };
}

export function serializable(session) {
  return omit(session, PRIVATE_FIELDS);
}

export function sameSession(a, b) {
  return isEqual(serializable(a), serializable(b));
}
