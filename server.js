'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { selftest } = require('./lib/selftest');
const wire = require('./lib/wire');
const { assertStrongPassword, createAuthChecker } = require('./lib/auth');
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
const REALM_HEADER = 'Basic realm="DNS Checker", charset="UTF-8"';

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

  // Cap outbound DNS connections. Excess queries wait their turn rather than fail.
  const outbound = createSemaphore(limits.maxOutboundQueries);
  const query = (...args) => outbound.run(() => rawQuery(...args));

  const routes = buildRoutes({ resolvers, query, timeout, checkSpf });
  const knownPaths = new Set([...routes.keys()].map((k) => k.slice(k.indexOf(' ') + 1)));

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

  async function handle(req, res, pathname) {
    const route = routes.get(`${req.method} ${pathname}`);
    if (route) return route(req, res);
    if (knownPaths.has(pathname)) {
      return sendJson(res, 405, { error: 'method not allowed' }, { Allow: 'GET' });
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
        const isPublic = req.method === 'GET' && pathname === '/healthz';
        if (!isPublic) {
          // Locked-out clients are refused before their credentials are looked at.
          // When no client address is visible (no proxy header, Unix socket), every
          // request shares the key 'unknown'; locking that out would let anyone lock
          // out the real user, so the lockout only applies to identified clients.
          const lockable = key !== 'unknown';
          const lock = lockable ? failedAuth.peek(key) : { allowed: true };
          if (!lock.allowed) {
            return sendJson(
              res,
              429,
              { error: 'Too many failed sign-in attempts. Try again later.' },
              { ...NO_STORE, 'Retry-After': String(lock.retryAfterSeconds) }
            );
          }
          if (!checkAuth(req)) {
            // Browsers send no credentials on the first request and only prompt after
            // the 401, so only a wrong password counts as a failed attempt.
            if (lockable && req.headers.authorization) failedAuth.hit(key);
            return sendJson(
              res,
              401,
              { error: 'authentication required' },
              { ...NO_STORE, 'WWW-Authenticate': REALM_HEADER }
            );
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
