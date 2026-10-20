'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer } = require('../server');

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};

// Uses the raw request-target, so paths such as /../package.json reach the
// server unchanged (the URL class would normalise them on the client side).
function get(port, rawPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: rawPath }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function withServer(fn) {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn(port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('healthz returns ok with the security headers', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/healthz');
    assert.equal(res.status, 200);
    assert.equal(res.body, 'ok');
    assert.match(res.headers['content-type'], /^text\/plain/);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(res.headers[name], value, `header ${name}`);
    }
  });
});

test('security headers are present on error responses too', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/no-such-route');
    assert.equal(res.status, 404);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(res.headers[name], value, `header ${name}`);
    }
  });
});

test('unknown route returns 404 JSON', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/api/does-not-exist');
    assert.equal(res.status, 404);
    assert.match(res.headers['content-type'], /^application\/json/);
    assert.deepEqual(JSON.parse(res.body), { error: 'not found' });
  });
});

test('static files are served with the right content type', async () => {
  await withServer(async (port) => {
    const index = await get(port, '/');
    assert.equal(index.status, 200);
    assert.match(index.headers['content-type'], /^text\/html/);

    const css = await get(port, '/style.css');
    assert.equal(css.status, 200);
    assert.match(css.headers['content-type'], /^text\/css/);

    const js = await get(port, '/app.js');
    assert.equal(js.status, 200);
    assert.match(js.headers['content-type'], /^text\/javascript/);
  });
});

test('path traversal does not serve files outside public/', async () => {
  const forbidden = ['"name": "dnschecker"', 'createServer', 'SECURITY_HEADERS'];
  const attempts = [
    '/../package.json',
    '/../../package.json',
    '/public/../../package.json',
    '/%2e%2e/package.json',
    '/%2e%2e%2fpackage.json',
    '/..%2fpackage.json',
    '/..%2f..%2fpackage.json',
    '/..%5cpackage.json',
    '/%00',
    '/%E0%A4%A',
  ];
  await withServer(async (port) => {
    for (const p of attempts) {
      const res = await get(port, p);
      assert.equal(res.status, 404, `expected 404 for ${p}`);
      for (const marker of forbidden) {
        assert.ok(!res.body.includes(marker), `leaked content for ${p}`);
      }
    }
  });
});

test('non-GET requests to API routes return 404 JSON, not a crash', async () => {
  await withServer(async (port) => {
    const res = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/healthz' }, (r) => {
        r.resume();
        r.on('end', () => resolve(r.statusCode));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(res, 404);
  });
});
