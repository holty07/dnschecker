'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { selftest } = require('./lib/selftest');
const resolvers = require('./resolvers.json');

const PUBLIC_DIR = path.join(__dirname, 'public');

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

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
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

const routes = new Map([
  ['GET /healthz', async (req, res) => sendText(res, 200, 'ok')],
  [
    'GET /api/selftest',
    async (req, res) => {
      // Loaded lazily so the server (and its tests) do not depend on lib/wire.js.
      const { query } = require('./lib/wire');
      const body = await selftest({ resolvers, query });
      sendJson(res, 200, body);
    },
  ],
]);

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

async function handle(req, res, pathname) {
  const route = routes.get(`${req.method} ${pathname}`);
  if (route) return route(req, res);
  if (req.method === 'GET') return serveStatic(res, pathname);
  return sendJson(res, 404, { error: 'not found' });
}

function createServer() {
  return http.createServer((req, res) => {
    const started = process.hrtime.bigint();
    const pathname = (req.url || '/').split('?')[0];

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(name, value);
    }

    // One line per request. Headers are never logged.
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      console.log(`${req.method} ${pathname} ${res.statusCode} ${ms.toFixed(1)}ms`);
    });

    Promise.resolve()
      .then(() => handle(req, res, pathname))
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
  const envPort = Number.parseInt(process.env.PORT, 10);
  const fromEnv = Number.isInteger(envPort) && envPort > 0;
  const port = fromEnv ? envPort : 3000;
  const source = fromEnv
    ? 'PORT environment variable'
    : 'default 3000 (PORT unset or invalid)';

  createServer().listen(port, () => {
    console.log(`dnschecker listening on port ${port} (source: ${source})`);
  });
}

module.exports = { createServer };
