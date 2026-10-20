'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { selftest } = require('./lib/selftest');
const wire = require('./lib/wire');
const { assertStrongPassword, createAuthChecker } = require('./lib/auth');
const { validateQuery } = require('./lib/validate');
const { lookupAll } = require('./lib/resolve');
const { checkAuthoritative } = require('./lib/authoritative');
const DEFAULT_RESOLVERS = require('./resolvers.json');

const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_TIMEOUT_MS = 3000;
const REALM_HEADER = 'Basic realm="DNS Checker", charset="UTF-8"';

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
};

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

function describeAddress(address) {
  if (!address) return null;
  if (typeof address === 'string') return `Unix socket ${address}`;
  return `port ${address.port}`;
}

function buildRoutes({ resolvers, query, timeout }) {
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
    query = wire.query,
    timeout = DEFAULT_TIMEOUT_MS,
  } = options;

  // Refuse to build a server without a strong password, even when used programmatically.
  assertStrongPassword(password);
  const checkAuth = createAuthChecker({ password });
  const routes = buildRoutes({ resolvers, query, timeout });

  async function handle(req, res, pathname) {
    const route = routes.get(`${req.method} ${pathname}`);
    if (route) return route(req, res);
    if (req.method === 'GET') return serveStatic(res, pathname);
    return sendJson(res, 404, { error: 'not found' });
  }

  return http.createServer((req, res) => {
    const started = process.hrtime.bigint();
    const pathname = (req.url || '/').split('?')[0];

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(name, value);
    }

    // One line per request. Query strings and headers are never logged.
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      console.log(`${req.method} ${pathname} ${res.statusCode} ${ms.toFixed(1)}ms`);
    });

    Promise.resolve()
      .then(() => {
        const isPublic = req.method === 'GET' && pathname === '/healthz';
        if (!isPublic && !checkAuth(req)) {
          return sendJson(
            res,
            401,
            { error: 'authentication required' },
            { 'WWW-Authenticate': REALM_HEADER }
          );
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
