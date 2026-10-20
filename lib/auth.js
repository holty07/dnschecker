'use strict';

// HTTP Basic authentication. The username is fixed (default 'admin') and the
// password comes from AUTH_PASSWORD. Nothing here logs or echoes the password.

const crypto = require('node:crypto');

const MIN_PASSWORD_LENGTH = 12;
const BASIC_SCHEME = /^basic\s+(\S+)$/i;
// Strict base64 with padding. Buffer.from() silently skips bad characters, so
// the format is checked first.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function assertStrongPassword(password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error(
      `AUTH_PASSWORD is not set. It is required and must be at least ${MIN_PASSWORD_LENGTH} characters.`
    );
  }
  if ([...password].length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `AUTH_PASSWORD is too short. It must be at least ${MIN_PASSWORD_LENGTH} characters.`
    );
  }
}

function digest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

// Returns { username, password } or null. The password may contain colons: the
// header is split at the first colon only (RFC 7617).
function parseBasic(header) {
  if (typeof header !== 'string') return null;
  const match = BASIC_SCHEME.exec(header.trim());
  if (!match) return null;
  const token = match[1];
  if (!BASE64.test(token)) return null;

  const decoded = Buffer.from(token, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  if (colon === -1) return null;
  return { username: decoded.slice(0, colon), password: decoded.slice(colon + 1) };
}

// Hashing both sides gives equal-length buffers, so timingSafeEqual never throws.
function createAuthChecker({ username = 'admin', password } = {}) {
  if (typeof password !== 'string') {
    throw new TypeError('createAuthChecker: password must be a string');
  }
  const expectedUser = digest(username);
  const expectedPass = digest(password);

  return function isAuthorised(req) {
    try {
      const creds = parseBasic(req && req.headers && req.headers.authorization);
      if (!creds) return false;

      // Both comparisons run before they are combined, so no short-circuit leaks
      // which of the two was wrong.
      const userOk = crypto.timingSafeEqual(digest(creds.username), expectedUser);
      const passOk = crypto.timingSafeEqual(digest(creds.password), expectedPass);
      return userOk && passOk;
    } catch {
      return false;
    }
  };
}

module.exports = { MIN_PASSWORD_LENGTH, assertStrongPassword, createAuthChecker, parseBasic };
