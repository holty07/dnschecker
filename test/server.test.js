'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer } = require('../server');

const PASSWORD = 'correct-horse-9';
const AUTH = 'Basic ' + Buffer.from(`admin:${PASSWORD}`).toString('base64');
const REALM = 'Basic realm="DNS Checker", charset="UTF-8"';
const RESOLVERS = [
  { name: 'Alpha', address: '10.0.0.1' },
  { name: 'Beta', address: '10.0.0.2' },
];

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};

// Fake transport. Every server answers with one A record, so lookups succeed offline.
function fakeQuery(calls) {
  return async (args) => {
    calls.push(args);
    return {
      rcodeName: 'NOERROR',
      flags: { tc: false },
      answers: [{ name: 'example.com', type: 'A', class: 1, ttl: 60, data: '1.2.3.4' }],
      ms: 1,
    };
  };
}

// Uses the raw request-target, so paths such as /../package.json reach the
// server unchanged (the URL class would normalise them on the client side).
function request(port, method, rawPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: rawPath, headers }, (res) => {
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

const get = (port, rawPath) => request(port, 'GET', rawPath, { Authorization: AUTH });
const getAnon = (port, rawPath) => request(port, 'GET', rawPath);

async function withServer(fn, options = {}) {
  const server = createServer({
    password: PASSWORD,
    resolvers: RESOLVERS,
    query: fakeQuery([]),
    timeout: 1000,
    ...options,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn(port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('createServer refuses a weak password', () => {
  assert.throws(() => createServer({ password: 'short', resolvers: RESOLVERS, query: fakeQuery([]) }), /AUTH_PASSWORD/);
  assert.throws(() => createServer({ resolvers: RESOLVERS, query: fakeQuery([]) }), /AUTH_PASSWORD/);
});

test('healthz returns ok without auth, with the security headers', async () => {
  await withServer(async (port) => {
    const res = await getAnon(port, '/healthz');
    assert.equal(res.status, 200);
    assert.equal(res.body, 'ok');
    assert.match(res.headers['content-type'], /^text\/plain/);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(res.headers[name], value, `header ${name}`);
    }
  });
});

test('/, /api/selftest and /api/lookup return 401 without auth', async () => {
  await withServer(async (port) => {
    for (const p of ['/', '/api/selftest', '/api/lookup?domain=example.com&type=A', '/style.css']) {
      const res = await getAnon(port, p);
      assert.equal(res.status, 401, `expected 401 for ${p}`);
      assert.equal(res.headers['www-authenticate'], REALM, `WWW-Authenticate for ${p}`);
      assert.match(res.headers['content-type'], /^application\/json/);
      assert.deepEqual(JSON.parse(res.body), { error: 'authentication required' });
    }
  });
});

test('wrong credentials return 401', async () => {
  await withServer(async (port) => {
    const wrong = 'Basic ' + Buffer.from(`admin:${PASSWORD}x`).toString('base64');
    const res = await request(port, 'GET', '/', { Authorization: wrong });
    assert.equal(res.status, 401);
  });
});

test('/ returns the lookup page with auth', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /^text\/html/);
    assert.match(res.body, /id="lookup-form"/);
  });
});

test('selftest page and /api/selftest are served with auth', async () => {
  await withServer(async (port) => {
    const page = await get(port, '/selftest.html');
    assert.equal(page.status, 200);
    assert.match(page.body, /src="\/selftest\.js"/);

    const api = await get(port, '/api/selftest');
    assert.equal(api.status, 200);
    const body = JSON.parse(api.body);
    assert.equal(body.target, 'example.com');
    assert.equal(body.runtime.node, process.version);
    assert.equal(body.runtime.listeningOn, `port ${port}`);
  });
});

test('lookup rejects an invalid domain with 400 and a JSON error', async () => {
  await withServer(async (port) => {
    const res = await get(port, `/api/lookup?domain=${encodeURIComponent('bad domain')}&type=A`);
    assert.equal(res.status, 400);
    assert.match(res.headers['content-type'], /^application\/json/);
    const body = JSON.parse(res.body);
    assert.equal(typeof body.error, 'string');
    assert.ok(body.error.length > 0);
  });
});

test('lookup without a domain parameter returns 400', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/api/lookup?type=A');
    assert.equal(res.status, 400);
    assert.deepEqual(JSON.parse(res.body), { error: 'domain is required' });
  });
});

test('lookup with auth queries every resolver and returns the result', async () => {
  const calls = [];
  await withServer(async (port) => {
    const res = await get(port, '/api/lookup?domain=example.com&type=A');
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.results.length, 2);
    assert.equal(body.input, 'example.com');
    assert.equal(body.name, 'example.com');
    assert.equal(body.type, 'A');
    assert.deepEqual(body.results.map((r) => r.server).sort(), ['10.0.0.1', '10.0.0.2']);
  }, { query: fakeQuery(calls) });
  assert.ok(calls.length >= 2, 'each resolver is queried');
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

test('unknown route returns 404 JSON with auth', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/api/does-not-exist');
    assert.equal(res.status, 404);
    assert.match(res.headers['content-type'], /^application\/json/);
    assert.deepEqual(JSON.parse(res.body), { error: 'not found' });
  });
});

test('security headers are present on 401, 404 and 400 responses', async () => {
  await withServer(async (port) => {
    for (const res of [
      await getAnon(port, '/'),
      await get(port, '/no-such-route'),
      await get(port, '/api/lookup?type=A'),
    ]) {
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
        assert.equal(res.headers[name], value, `header ${name} on ${res.status}`);
      }
    }
  });
});

test('non-GET requests return 404 with auth and 401 without (healthz is GET only)', async () => {
  await withServer(async (port) => {
    const anon = await request(port, 'POST', '/healthz');
    assert.equal(anon.status, 401);

    const authed = await request(port, 'POST', '/healthz', { Authorization: AUTH });
    assert.equal(authed.status, 404);
    assert.deepEqual(JSON.parse(authed.body), { error: 'not found' });
  });
});

// Fake for /api/authoritative: public discovery resolvers answer NS/A queries, nameservers answer directly.
function authoritativeFake(calls) {
  const reply = (answers, aa = false) => ({ rcodeName: 'NOERROR', flags: { rcode: 0, aa, tc: false }, answers, ms: 1 });
  const rec = (name, type, data) => ({ name, type, class: 1, ttl: 60, data });
  return async (args) => {
    calls.push(args);
    if (args.server === '10.0.0.1' || args.server === '10.0.0.2') {
      if (args.type === 'NS') return reply([rec('example.com', 'NS', 'ns1.example.com')]);
      if (args.type === 'A') return reply([rec('ns1.example.com', 'A', '45.1.1.1')]);
      return reply([]);
    }
    if (args.type === 'SOA') return reply([rec('example.com', 'SOA', { nsname: 'ns1.example.com', hostmaster: 'h.example.com', serial: 7, refresh: 1, retry: 1, expire: 1, minttl: 1 })], true);
    return reply([rec(args.name, 'A', '1.2.3.4')], true);
  };
}

test('/api/authoritative requires auth', async () => {
  await withServer(async (port) => {
    const res = await getAnon(port, '/api/authoritative?domain=example.com&type=A');
    assert.equal(res.status, 401);
  });
});

test('/api/authoritative rejects a bad domain with 400', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/api/authoritative?domain=http%3A%2F%2Fexample.com&type=A');
    assert.equal(res.status, 400);
    assert.ok(JSON.parse(res.body).error);
    assert.equal((await get(port, '/api/authoritative?type=A')).status, 400);
  });
});

test('/api/authoritative returns 200 with the fake', async () => {
  const calls = [];
  await withServer(async (port) => {
    const res = await get(port, '/api/authoritative?domain=Example.com&type=A');
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.input, 'Example.com');
    assert.equal(body.name, 'example.com');
    assert.equal(body.zone, 'example.com');
    assert.equal(body.results.length, 1);
    assert.equal(body.results[0].nameserver, 'ns1.example.com');
    assert.equal(body.results[0].serial, 7);
    assert.equal(body.consensus.allAgree, true);
    assert.equal(body.serials.allMatch, true);
    assert.deepEqual(body.warnings, []);
    for (const c of calls) assert.equal(c.transport, 'tcp');
  }, { query: authoritativeFake(calls) });
});

test('/api/authoritative gives 422 when no zone is found', async () => {
  await withServer(async (port) => {
    const res = await get(port, '/api/authoritative?domain=example.com&type=A');
    assert.equal(res.status, 422);
    assert.deepEqual(JSON.parse(res.body), { error: 'No nameservers found for this name' });
  }, {
    query: async () => ({ rcodeName: 'NOERROR', flags: { rcode: 0, aa: false }, answers: [], ms: 1 }),
  });
});
