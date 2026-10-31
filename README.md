# session-store

In-memory session store with expiry and safe serialization. Part of the dependency-defense demo fleet.

```bash
npm ci
npm test
npm run build
```

## Tests

`npm test` runs `test/*.test.js` only: the store expiry and serialization unit tests
(`test/store.test.js`), the legitimate resume-token flows that must keep working across a
`jsonwebtoken` upgrade (`test/preservation.test.js`), and `test/characterization.test.js`, which
pins today's behaviour so a dependency change shows up as a diff rather than a surprise.

`npm run test:security` runs `test/security/**/*.test.js` and is deliberately **not** part of
`npm test`. Its one test is **red today**:

- `resumeSession rejects an alg:none token whose kid is unknown`

It is red because `keyForKid` returns an empty key for a `kid` it does not recognise and
`resumeSession` then calls `jwt.verify(token, key)` with no `algorithms` option. On `jsonwebtoken`
8.5.1 that combination accepts an unsigned `alg: none` token, so an attacker who names an unknown
`kid` can resume any session by `sid`. The `vulnerable today:` test in
`test/characterization.test.js` asserts exactly that and is expected to be inverted when the issue
is fixed.

What these tests do not cover: keys come from `SESSION_JWT_KEYS` and there is no coverage of key
rotation, token expiry or revocation. The security suite checks a single forgery shape, not the
full JWT threat model.
