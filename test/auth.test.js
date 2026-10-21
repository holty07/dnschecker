'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MIN_PASSWORD_LENGTH,
  COOKIE_NAME,
  assertStrongPassword,
  createAuthChecker,
  createSessionManager,
  parseCookies,
} = require('../lib/auth');

const PASSWORD = 'correct-horse-9';

function basic(userAndPass) {
  return 'Basic ' + Buffer.from(userAndPass, 'utf8').toString('base64');
}

function req(authorization) {
  return { headers: authorization === undefined ? {} : { authorization } };
}

test('minimum password length is 12', () => {
  assert.equal(MIN_PASSWORD_LENGTH, 12);
});

test('assertStrongPassword rejects unset, empty and short passwords', () => {
  assert.throws(() => assertStrongPassword(undefined), /AUTH_PASSWORD/);
  assert.throws(() => assertStrongPassword(null), /AUTH_PASSWORD/);
  assert.throws(() => assertStrongPassword(''), /AUTH_PASSWORD/);
  assert.throws(() => assertStrongPassword('a'.repeat(11)), /AUTH_PASSWORD/);
});

test('assertStrongPassword accepts 12 or more characters', () => {
  assert.doesNotThrow(() => assertStrongPassword('a'.repeat(12)));
  assert.doesNotThrow(() => assertStrongPassword('correct horse battery'));
});

test('assertStrongPassword error messages never include the password', () => {
  const secret = 'hunter2-short';
  try {
    assertStrongPassword(secret);
    assert.fail('expected a throw');
  } catch (err) {
    assert.ok(!err.message.includes(secret), 'message must not echo the password');
  }
});

test('createAuthChecker accepts the correct username and password', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req(basic(`admin:${PASSWORD}`))), true);
});

test('createAuthChecker rejects a wrong password', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req(basic(`admin:${PASSWORD}x`))), false);
  assert.equal(check(req(basic('admin:wrong-password-here'))), false);
});

test('createAuthChecker rejects a wrong username', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req(basic(`root:${PASSWORD}`))), false);
  assert.equal(check(req(basic(`Admin:${PASSWORD}`))), false);
});

test('createAuthChecker honours a custom username', () => {
  const check = createAuthChecker({ username: 'ops', password: PASSWORD });
  assert.equal(check(req(basic(`ops:${PASSWORD}`))), true);
  assert.equal(check(req(basic(`admin:${PASSWORD}`))), false);
});

test('createAuthChecker rejects a missing header', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req(undefined)), false);
  assert.equal(check({}), false);
  assert.equal(check(undefined), false);
});

test('createAuthChecker rejects a non-Basic scheme', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req('Bearer x')), false);
  assert.equal(check(req('Bearer ' + Buffer.from(`admin:${PASSWORD}`).toString('base64'))), false);
});

test('createAuthChecker rejects invalid base64', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req('Basic !!!not-base64!!!')), false);
  assert.equal(check(req('Basic abc')), false);
  assert.equal(check(req('Basic ')), false);
});

test('createAuthChecker rejects credentials with no colon', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req('Basic ' + Buffer.from('adminpassword').toString('base64'))), false);
});

test('createAuthChecker accepts a password that contains colons', () => {
  const password = 'pass:word:with:colons-123';
  const check = createAuthChecker({ password });
  assert.equal(check(req(basic(`admin:${password}`))), true);
  assert.equal(check(req(basic('admin:pass'))), false);
});

test('createAuthChecker never throws on odd input', () => {
  const check = createAuthChecker({ password: PASSWORD });
  assert.equal(check(req(42)), false);
  assert.equal(check(req(['Basic', 'x'])), false);
  assert.equal(check({ headers: null }), false);
});

test('createAuthChecker requires a string password', () => {
  assert.throws(() => createAuthChecker({}), TypeError);
});

test('checkCredentials compares both username and password', () => {
  const { checkCredentials } = createAuthChecker({ password: PASSWORD });
  assert.equal(checkCredentials('admin', PASSWORD), true);
  assert.equal(checkCredentials('admin', PASSWORD + 'x'), false);
  assert.equal(checkCredentials('root', PASSWORD), false);
  assert.equal(checkCredentials(null, PASSWORD), false);
  assert.equal(checkCredentials('admin', undefined), false);
});

// ---- Sessions ----

const DAY = 24 * 3600;

function sessions(overrides = {}) {
  const clock = { t: 1_800_000_000_000 };
  const manager = createSessionManager({ password: PASSWORD, now: () => clock.t, ...overrides });
  return { clock, manager };
}

test('an issued session verifies and has the documented shape', () => {
  const { clock, manager } = sessions();
  const value = manager.issue();
  assert.match(value, /^v1\.\d+\.[0-9a-f]{16}\.[A-Za-z0-9_-]{43}$/);
  assert.equal(Number(value.split('.')[1]), clock.t / 1000 + 30 * DAY);
  assert.equal(manager.verify(value), true);
  assert.notEqual(manager.issue(), value, 'each session has a fresh nonce');
});

test('sessions expire, and not before', () => {
  const { clock, manager } = sessions({ maxAgeSeconds: 100 });
  const value = manager.issue();
  clock.t += 99_000;
  assert.equal(manager.verify(value), true);
  clock.t += 1_000;
  assert.equal(manager.verify(value), false);
});

test('tampering with the expiry, nonce or signature fails', () => {
  const { manager } = sessions();
  const [v, exp, nonce, sig] = manager.issue().split('.');
  const flip = (c) => (c === 'a' ? 'b' : 'a');
  const cases = [
    [v, String(Number(exp) + 1), nonce, sig],
    [v, exp, flip(nonce[0]) + nonce.slice(1), sig],
    [v, exp, nonce, flip(sig[0]) + sig.slice(1)],
    ['v2', exp, nonce, sig],
  ];
  for (const parts of cases) assert.equal(manager.verify(parts.join('.')), false, parts.join('.'));
});

test('malformed and wrong-length values fail without throwing', () => {
  const { manager } = sessions();
  const good = manager.issue();
  const [v, exp, nonce, sig] = good.split('.');
  const bad = [
    undefined, null, 42, {}, [], '', 'v1', 'v1...', `${good}.extra`, `${good}A`, good.slice(0, -1),
    [v, exp, nonce, sig.slice(0, 20)].join('.'),
    [v, exp, nonce.slice(1), sig].join('.'),
    [v, '', nonce, sig].join('.'),
    [v, '-5', nonce, sig].join('.'),
    [v, '1e9', nonce, sig].join('.'),
    ' ' + good,
    'x'.repeat(100000),
  ];
  for (const value of bad) assert.equal(manager.verify(value), false, String(value).slice(0, 40));
});

test('a different password invalidates the session', () => {
  const { manager } = sessions();
  const other = createSessionManager({ password: 'another-long-password', now: () => 1_800_000_000_000 });
  const value = manager.issue();
  assert.equal(other.verify(value), false);
  assert.equal(other.verify(other.issue()), true);
});

test('sessions are stateless: a new manager with the same password accepts them', () => {
  const { manager } = sessions();
  const value = manager.issue();
  assert.equal(sessions().manager.verify(value), true);
});

test('cookie headers carry the security attributes', () => {
  const { manager } = sessions();
  const value = manager.issue();
  assert.equal(
    manager.cookieHeader(value),
    `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${30 * DAY}`
  );
  assert.equal(
    manager.clearCookieHeader(),
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  );
});

test('createSessionManager requires a password', () => {
  assert.throws(() => createSessionManager({}), TypeError);
  assert.throws(() => createSessionManager({ password: '' }), TypeError);
});

test('parseCookies reads pairs and ignores malformed parts', () => {
  assert.deepEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' });
  assert.deepEqual(parseCookies('  a = 1 ;b=two=2;;novalue;=x; bad name=1; c="q"'), { a: '1', b: 'two=2', c: 'q' });
  assert.deepEqual(parseCookies('a=1; a=2'), { a: '1' }, 'first occurrence wins');
  assert.deepEqual(parseCookies('a='), { a: '' });
  for (const header of [undefined, null, 5, '', ';;;', '=', ['a=1']]) assert.deepEqual(parseCookies(header), {});
  assert.deepEqual(parseCookies('x'.repeat(9000) + '=1'), {});
});

test('parseCookies does not let a cookie name pollute the prototype', () => {
  const cookies = parseCookies('__proto__=x; constructor=y; toString=z');
  assert.equal(Object.getPrototypeOf(cookies), Object.prototype);
  assert.equal(Object.hasOwn(cookies, '__proto__'), false);
  assert.equal(cookies.constructor, 'y');
  assert.equal(({}).x, undefined);
});
