'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { selftest } = require('./lib/selftest');
const wire = require('./lib/wire');
const {
  COOKIE_NAME,
  assertStrongPassword,
  createAuthChecker,
  createSessionManager,
  parseCookies,
} = require('./lib/auth');
const { validateQuery } = require('./lib/validate');
const { lookupAll } = require('./lib/resolve');
const { checkAuthoritative } = require('./lib/authoritative');
const { checkEmail } = require('./lib/email');
const {
  createRateLimiter,
  createConcurrencyLimiter,
  createSemaphore,
  clientKey,
} = require('./lib/ratelimit');
const DEFAULT_RESOLVERS = require('./resolvers.json');

const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_LOGIN_BODY = 4096;
const MAX_NEXT_LENGTH = 2048;
// Reachable without signing in. Basic auth's WWW-Authenticate header is never sent,
// because it is what makes browsers show the native prompt.
const PUBLIC_GET_PATHS = new Set(['/healthz', '/login.html', '/login.js', '/style.css']);
const PUBLIC_POST_PATHS = new Set(['/login', '/logout']);

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

const DEFAULT_LIMITS = {
  apiPerMinute: 60,
  failedAuthPer15Min: 20,
  maxConcurrentApiPerClient: 10,
  maxConcurrentApi: 20,
  maxOutboundQueries: 64,
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  // Browsers ignore this over plain HTTP, so it is harmless in local development.
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const NO_STORE = { 'Cache-Control': 'no-store' };

// Longest header value echoed back by the self-test (it is the requester's own header).
const MAX_ECHO_LENGTH = 200;

function headerValue(req, name) {
  const v = req.headers[name];
  return typeof v === 'string' ? v.slice(0, MAX_ECHO_LENGTH) : null;
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function sendText(res, status, text) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
  });
  res.end(text);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(303, { Location: location, 'Content-Length': 0, ...NO_STORE, ...extraHeaders });
  res.end();
}

// Only same-site absolute paths are allowed as a post-login destination.
function safeNext(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_NEXT_LENGTH) return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  if (value.includes('\\') || /[\u0000-\u001f\u007f]/.test(value)) return '/';
  return value;
}

function loginUrl(next, error) {
  const params = [];
  if (error) params.push(`error=${error}`);
  if (next !== undefined) params.push(`next=${encodeURIComponent(next)}`);
  return `/login.html${params.length ? `?${params.join('&')}` : ''}`;
}

// Cross-site request guard for POST /login and /logout.
// Sec-Fetch-Site is set by the browser and can't be forged by a page, so when present
// it decides: only same-origin is accepted. It also doesn't depend on the Host header,
// which a proxy could rewrite. Older clients without it fall back to Origin; with
// Referrer-Policy: no-referrer browsers send "Origin: null", which is refused here.
// No Origin at all (curl, scripts) is allowed; they hold no session cookie to abuse.
function originAllowed(req) {
  const site = req.headers['sec-fetch-site'];
  if (site !== undefined) return site === 'same-origin';
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  if (origin === 'null') return false;
  try {
    return typeof origin === 'string' && new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function readLoginForm(req) {
  return new Promise((resolve) => {
    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/x-www-form-urlencoded') return resolve({ status: 415 });
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_LOGIN_BODY) return resolve({ status: 413 });
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_LOGIN_BODY) {
        chunks.length = 0;
        req.removeAllListeners('data');
        req.resume();
        return resolve({ status: 413 });
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve({ form: new URLSearchParams(Buffer.concat(chunks).toString('utf8')) }));
    req.on('error', () => resolve({ status: 400 }));
  });
}

function parseTimeout(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
}

async function handleLookup(req, res, { resolvers, query, timeout }) {
  const url = new URL(req.url, 'http://localhost');
  const domain = url.searchParams.get('domain');
  const type = url.searchParams.get('type');
  if (domain === null) return sendJson(res, 400, { error: 'domain is required' });

  let checked;
  try {
    checked = validateQuery(domain, type);
  } catch (err) {
    if (err && err.code === 'EINVALID') return sendJson(res, 400, { error: err.message });
    throw err;
  }

  const result = await lookupAll({
    resolvers,
    name: checked.name,
    type: checked.type,
    query,
    timeout,
  });
  sendJson(res, 200, { ...result, input: domain });
}

async function handleAuthoritative(req, res, { resolvers, query, timeout }) {
  const url = new URL(req.url, 'http://localhost');
  const domain = url.searchParams.get('domain');
  const type = url.searchParams.get('type');
  if (domain === null) return sendJson(res, 400, { error: 'domain is required' });

  let checked;
  try {
    checked = validateQuery(domain, type);
  } catch (err) {
    if (err && err.code === 'EINVALID') return sendJson(res, 400, { error: err.message });
    throw err;
  }

  let result;
  try {
    result = await checkAuthoritative(checked, { query, resolvers, timeout });
  } catch (err) {
    if (err && err.code === 'ENOZONE') return sendJson(res, 422, { error: 'No nameservers found for this name' });
    if (err && err.code === 'EDISCOVERY') return sendJson(res, 502, { error: 'Could not reach the public resolvers to find the nameservers' });
    throw err;
  }
  sendJson(res, 200, { ...result, input: domain });
}

async function handleEmail(req, res, { resolvers, query, timeout, checkSpf }) {
  const url = new URL(req.url, 'http://localhost');
  const domain = url.searchParams.get('domain');
  if (domain === null) return sendJson(res, 400, { error: 'domain is required' });

  let checked;
  try {
    checked = validateQuery(domain, 'TXT');
  } catch (err) {
    if (err && err.code === 'EINVALID') return sendJson(res, 400, { error: err.message });
    throw err;
  }

  // Selectors may contain dots (for example s1.2024); validate the whole DKIM name.
  const rawSelector = url.searchParams.get('selector');
  const selector = rawSelector === null ? '' : rawSelector.trim();
  if (selector) {
    try {
      validateQuery(`${selector}._domainkey.${checked.name}`, 'TXT');
    } catch (err) {
      if (err && err.code === 'EINVALID') return sendJson(res, 400, { error: 'Invalid DKIM selector' });
      throw err;
    }
  }

  const opts = { query, resolvers, timeout };
  if (checkSpf) opts.checkSpf = checkSpf;
  const result = await checkEmail({ domain: checked.name, selector }, opts);
  sendJson(res, 200, { ...result, input: domain });
}

function describeAddress(address) {
  if (!address) return null;
  if (typeof address === 'string') return `Unix socket ${address}`;
  return `port ${address.port}`;
}

function buildRoutes({ resolvers, query, timeout, checkSpf }) {
  return new Map([
    ['GET /healthz', async (req, res) => sendText(res, 200, 'ok')],
    [
      'GET /api/selftest',
      async (req, res) => {
        const body = await selftest({ resolvers, query });
        // How the platform runs the app, since its runtime logs are hard to reach.
        body.runtime = {
          node: process.version,
          // A port number, or a path when the platform swaps the listener for a Unix socket.
          listeningOn: describeAddress(req.socket.server && req.socket.server.address()),
          portEnv: process.env.PORT === undefined ? null : process.env.PORT,
          // The requester's own address as the app sees it. Only these headers are echoed.
          forwardedFor: headerValue(req, 'x-forwarded-for'),
          realIp: headerValue(req, 'x-real-ip'),
          remoteAddress: req.socket.remoteAddress || null,
          clientKey: clientKey(req),
        };
        sendJson(res, 200, body);
      },
    ],
    [
      'GET /api/lookup',
      async (req, res) => handleLookup(req, res, { resolvers, query, timeout }),
    ],
    [
      'GET /api/authoritative',
      async (req, res) => handleAuthoritative(req, res, { resolvers, query, timeout }),
    ],
    [
      'GET /api/email',
      async (req, res) => handleEmail(req, res, { resolvers, query, timeout, checkSpf }),
    ],
  ]);
}

async function serveStatic(res, pathname) {
  let relative;
  try {
    relative = decodeURIComponent(pathname);
  } catch {
    return sendJson(res, 404, { error: 'not found' });
  }
  if (relative === '/') relative = '/index.html';

  const filePath = path.resolve(PUBLIC_DIR, '.' + relative);
  // Path traversal guard: the resolved file must sit inside public/.
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    return sendJson(res, 404, { error: 'not found' });
  }

  const contentType = CONTENT_TYPES[path.extname(filePath)];
  if (!contentType) return sendJson(res, 404, { error: 'not found' });

  let data;
  try {
    data = await fs.readFile(filePath);
  } catch {
    return sendJson(res, 404, { error: 'not found' });
  }
  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': data.length,
    ...(relative === '/login.html' ? NO_STORE : {}),
  });
  res.end(data);
}

function createServer(options = {}) {
  const {
    password,
    resolvers = DEFAULT_RESOLVERS,
    query: rawQuery = wire.query,
    timeout = DEFAULT_TIMEOUT_MS,
    checkSpf, // optional override, for tests; defaults to lib/spf.js (loaded lazily)
  } = options;
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };

  // Refuse to build a server without a strong password, even when used programmatically.
  assertStrongPassword(password);
  const checkAuth = createAuthChecker({ password });
  const session = createSessionManager({ password });

  // Cap outbound DNS connections. Excess queries wait their turn rather than fail.
  const outbound = createSemaphore(limits.maxOutboundQueries);
  const query = (...args) => outbound.run(() => rawQuery(...args));

  const failedAuth = createRateLimiter({ limit: limits.failedAuthPer15Min, windowMs: 15 * 60 * 1000 });
  const apiRate = createRateLimiter({ limit: limits.apiPerMinute, windowMs: 60 * 1000 });
  const globalInFlight = createConcurrencyLimiter(limits.maxConcurrentApi);
  const clientInFlight = new Map(); // key -> concurrency limiter, removed when idle

  // Take a per-client and a global slot. Returns one release function, or null.
  function acquireSlot(key) {
    let perClient = clientInFlight.get(key);
    if (!perClient) {
      perClient = createConcurrencyLimiter(limits.maxConcurrentApiPerClient);
      clientInFlight.set(key, perClient);
    }
    const releaseClient = perClient.tryAcquire();
    const releaseGlobal = releaseClient ? globalInFlight.tryAcquire() : null;
    if (!releaseGlobal) {
      if (releaseClient) releaseClient();
      if (perClient.active === 0) clientInFlight.delete(key);
      return null;
    }
    return function release() {
      releaseGlobal();
      releaseClient();
      if (perClient.active === 0 && clientInFlight.get(key) === perClient) clientInFlight.delete(key);
    };
  }

  // The log carries only a short tag derived from the client key and a random
  // per-process salt. It lets abuse from one client be correlated without writing
  // IP addresses to the log, and it cannot be reversed or matched across restarts.
  const salt = crypto.randomBytes(16);
  function clientTag(key) {
    return crypto.createHash('sha256').update(key).update(salt).digest('hex').slice(0, 8);
  }

  // Only a client with a usable address can be locked out (see the note in the request handler).
  const lockState = (key) => (key !== 'unknown' ? failedAuth.peek(key) : { allowed: true });

  async function handleLogin(req, res) {
    if (!originAllowed(req)) return sendJson(res, 403, { error: 'Cross-origin request refused' }, NO_STORE);
    const key = clientKey(req);
    const lockable = key !== 'unknown';
    const parsed = await readLoginForm(req);
    if (parsed.status) {
      const messages = { 413: 'Request too large', 415: 'Unsupported content type', 400: 'Bad request' };
      return sendJson(res, parsed.status, { error: messages[parsed.status] }, { ...NO_STORE, Connection: 'close' });
    }
    const next = safeNext(parsed.form.get('next'));
    // A locked-out client is refused without its credentials being looked at.
    if (!lockState(key).allowed) return redirect(res, loginUrl(next, 'locked'));
    if (checkAuth.checkCredentials(parsed.form.get('username'), parsed.form.get('password'))) {
      return redirect(res, next, { 'Set-Cookie': session.cookieHeader(session.issue()) });
    }
    if (lockable) failedAuth.hit(key);
    return redirect(res, loginUrl(next, '1'));
  }

  async function handleLogout(req, res) {
    if (!originAllowed(req)) return sendJson(res, 403, { error: 'Cross-origin request refused' }, NO_STORE);
    return redirect(res, '/login.html', { 'Set-Cookie': session.clearCookieHeader() });
  }

  const routes = buildRoutes({ resolvers, query, timeout, checkSpf });
  routes.set('POST /login', handleLogin);
  routes.set('POST /logout', handleLogout);
  const allowedMethod = new Map([...routes.keys()].map((k) => k.split(' ').reverse()));

  async function handle(req, res, pathname) {
    const route = routes.get(`${req.method} ${pathname}`);
    if (route) return route(req, res);
    if (allowedMethod.has(pathname)) {
      return sendJson(res, 405, { error: 'method not allowed' }, { Allow: allowedMethod.get(pathname) });
    }
    if (req.method === 'GET') return serveStatic(res, pathname);
    return sendJson(res, 404, { error: 'not found' });
  }

  return http.createServer((req, res) => {
    const started = process.hrtime.bigint();
    const pathname = (req.url || '/').split('?')[0];
    const key = clientKey(req);
    const isApi = pathname.startsWith('/api/');

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(name, value);
    }
    if (isApi) res.setHeader('Cache-Control', 'no-store');

    // One line per request. Query strings and headers are never logged.
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      console.log(`${req.method} ${pathname} ${res.statusCode} ${ms.toFixed(1)}ms client=${clientTag(key)}`);
    });

    let release = null;

    Promise.resolve()
      .then(() => {
        const isPublic =
          (req.method === 'GET' && PUBLIC_GET_PATHS.has(pathname)) ||
          (req.method === 'POST' && PUBLIC_POST_PATHS.has(pathname));
        if (isPublic && pathname === '/login.html') res.setHeader('Cache-Control', 'no-store');
        if (!isPublic) {
          // A valid session cookie proves the password was known, so it is accepted
          // without touching the failed-attempt counter.
          const cookie = parseCookies(req.headers.cookie)[COOKIE_NAME];
          if (!(cookie !== undefined && session.verify(cookie))) {
            // Basic credentials are guesses, so a locked-out client is refused before
            // they are looked at. When no client address is visible (no proxy header,
            // Unix socket), every request shares the key 'unknown'; locking that out
            // would let anyone lock out the real user, so the lockout only applies to
            // identified clients.
            const lockable = key !== 'unknown';
            const basicSupplied = Boolean(req.headers.authorization);
            if (basicSupplied) {
              const lock = lockState(key);
              if (!lock.allowed) {
                return sendJson(
                  res,
                  429,
                  { error: 'Too many failed sign-in attempts. Try again later.' },
                  { ...NO_STORE, 'Retry-After': String(lock.retryAfterSeconds) }
                );
              }
            }
            if (!checkAuth(req)) {
              // Only supplied (wrong) credentials count as a failed attempt.
              if (lockable && basicSupplied) failedAuth.hit(key);
              if (req.method === 'GET' && !isApi) return redirect(res, loginUrl(safeNext(req.url)));
              return sendJson(res, 401, { error: 'Sign in required' }, NO_STORE);
            }
          }
        }

        if (isApi) {
          const rate = apiRate.hit(key);
          if (!rate.allowed) {
            return sendJson(
              res,
              429,
              {
                error: `Rate limit reached: ${limits.apiPerMinute} requests per minute. Try again in ${rate.retryAfterSeconds} seconds.`,
              },
              { ...NO_STORE, 'Retry-After': String(rate.retryAfterSeconds) }
            );
          }
          release = acquireSlot(key);
          if (!release) {
            return sendJson(
              res,
              429,
              { error: 'Too many lookups in progress. Wait for them to finish.' },
              { ...NO_STORE, 'Retry-After': '1' }
            );
          }
        }
        return handle(req, res, pathname);
      })
      .catch((err) => {
        // Log the message only; never send a stack trace to the client.
        console.error(`error handling ${req.method} ${pathname}: ${err && err.message}`);
        if (!res.headersSent) {
          sendJson(res, 500, { error: 'internal server error' });
        } else {
          res.end();
        }
      })
      .finally(() => {
        if (release) release(); // idempotent; runs on success, errors and aborted clients
      });
  });
}

if (require.main === module) {
  const password = process.env.AUTH_PASSWORD;
  try {
    assertStrongPassword(password);
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  }

  const envPort = Number.parseInt(process.env.PORT, 10);
  const fromEnv = Number.isInteger(envPort) && envPort > 0;
  const port = fromEnv ? envPort : 3000;
  const source = fromEnv
    ? 'PORT environment variable'
    : 'default 3000 (PORT unset or invalid)';

  createServer({
    password,
    timeout: parseTimeout(process.env.LOOKUP_TIMEOUT_MS),
  }).listen(port, () => {
    console.log(`dnschecker listening on port ${port} (source: ${source})`);
  });
}

module.exports = { createServer };
