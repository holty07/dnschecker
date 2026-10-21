'use strict';

// Authentication. The username is fixed (default 'admin') and the password comes
// from AUTH_PASSWORD. Two ways in: a login form that sets a stateless signed
// session cookie, and HTTP Basic auth (kept for scripts and curl). Nothing here
// logs or echoes the password.

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
function createCredentialChecker({ username = 'admin', password } = {}) {
  if (typeof password !== 'string') {
    throw new TypeError('createAuthChecker: password must be a string');
  }
  const expectedUser = digest(username);
  const expectedPass = digest(password);

  return function checkCredentials(givenUser, givenPass) {
    try {
      if (typeof givenUser !== 'string' || typeof givenPass !== 'string') return false;
      // Both comparisons run before they are combined, so no short-circuit leaks
      // which of the two was wrong.
      const userOk = crypto.timingSafeEqual(digest(givenUser), expectedUser);
      const passOk = crypto.timingSafeEqual(digest(givenPass), expectedPass);
      return userOk && passOk;
    } catch {
      return false;
    }
  };
}

// Checks the Basic Authorization header. The returned function also carries
// checkCredentials(username, password), which the login form uses.
function createAuthChecker(options = {}) {
  const checkCredentials = createCredentialChecker(options);

  function isAuthorised(req) {
    try {
      const creds = parseBasic(req && req.headers && req.headers.authorization);
      if (!creds) return false;
      return checkCredentials(creds.username, creds.password);
    } catch {
      return false;
    }
  }
  isAuthorised.checkCredentials = checkCredentials;
  return isAuthorised;
}

const COOKIE_NAME = 'dnschecker_session';
const SESSION_VERSION = 'v1';
const SESSION_PATTERN = /^v1\.(\d{1,12})\.([0-9a-f]{16})\.([A-Za-z0-9_-]{43})$/;

// Stateless sessions: the cookie value is signed, and nothing is stored on the
// server, so sessions survive restarts.
function createSessionManager({ password, now = Date.now, maxAgeSeconds = 30 * 24 * 3600 } = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('createSessionManager: password must be a non-empty string');
  }
  // The signing key is derived from the password, so changing AUTH_PASSWORD
  // invalidates every existing session (everyone is signed out).
  const key = crypto.createHmac('sha256', password).update('dnschecker session v1').digest();

  const sign = (payload) => crypto.createHmac('sha256', key).update(payload).digest();

  function issue() {
    const expiry = Math.floor(now() / 1000) + maxAgeSeconds;
    const nonce = crypto.randomBytes(8).toString('hex');
    const payload = `${SESSION_VERSION}.${expiry}.${nonce}`;
    return `${payload}.${sign(payload).toString('base64url')}`;
  }

  function verify(value) {
    try {
      if (typeof value !== 'string' || value.length > 200) return false;
      const m = SESSION_PATTERN.exec(value);
      if (!m) return false;
      const [, expiry, nonce, sig] = m;
      const given = Buffer.from(sig, 'base64url');
      // Reject non-canonical base64url (spare bits) so one signature has one spelling.
      if (given.toString('base64url') !== sig) return false;
      const expected = sign(`${SESSION_VERSION}.${expiry}.${nonce}`);
      if (given.length !== expected.length) return false;
      if (!crypto.timingSafeEqual(given, expected)) return false;
      return Number(expiry) > Math.floor(now() / 1000);
    } catch {
      return false;
    }
  }

  const attributes = 'Path=/; HttpOnly; Secure; SameSite=Strict';
  return {
    issue,
    verify,
    cookieHeader: (value) => `${COOKIE_NAME}=${value}; ${attributes}; Max-Age=${maxAgeSeconds}`,
    clearCookieHeader: () => `${COOKIE_NAME}=; ${attributes}; Max-Age=0`,
  };
}

// Small, forgiving Cookie header parser. Malformed parts are skipped; the first
// occurrence of a name wins. Values are not decoded.
function parseCookies(header) {
  const cookies = {};
  if (typeof header !== 'string' || header.length > 8192) return cookies;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const name = part.slice(0, eq).trim();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name) || name === '__proto__') continue;
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    if (!Object.prototype.hasOwnProperty.call(cookies, name)) cookies[name] = value;
  }
  return cookies;
}

module.exports = {
  MIN_PASSWORD_LENGTH,
  COOKIE_NAME,
  assertStrongPassword,
  createAuthChecker,
  createCredentialChecker,
  createSessionManager,
  parseBasic,
  parseCookies,
};
