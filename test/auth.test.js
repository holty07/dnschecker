'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { MIN_PASSWORD_LENGTH, assertStrongPassword, createAuthChecker } = require('../lib/auth');

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
