'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer } = require('../server');

const PASSWORD = 'correct-horse-9';
const AUTH = 'Basic ' + Buffer.from(`admin:${PASSWORD}`).toString('base64');
const RESOLVERS = [
  { name: 'Alpha', address: '10.0.0.1' },
  { name: 'Beta', address: '10.0.0.2' },
];

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  'strict-transport-security': 'max-age=31536000',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
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
function request(port, method, rawPath, headers = {}, body) {
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
    req.end(body);
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

test('/api/selftest and /api/lookup return 401 JSON without auth, and never ask for Basic auth', async () => {
  await withServer(async (port) => {
    for (const p of ['/api/selftest', '/api/lookup?domain=example.com&type=A']) {
      const res = await getAnon(port, p);
      assert.equal(res.status, 401, `expected 401 for ${p}`);
      assert.equal(res.headers['www-authenticate'], undefined, `WWW-Authenticate for ${p}`);
      assert.equal(res.headers['cache-control'], 'no-store');
      assert.match(res.headers['content-type'], /^application\/json/);
      assert.deepEqual(JSON.parse(res.body), { error: 'Sign in required' });
    }
  });
});

test('pages without auth redirect to the login page', async () => {
  await withServer(async (port) => {
    const root = await getAnon(port, '/');
    assert.equal(root.status, 303);
    assert.equal(root.headers.location, '/login.html?next=%2F');
    assert.equal(root.headers['www-authenticate'], undefined);
    const page = await getAnon(port, '/selftest.html?x=1');
    assert.equal(page.status, 303);
    assert.equal(page.headers.location, '/login.html?next=%2Fselftest.html%3Fx%3D1');
  });
});

test('wrong credentials return 401', async () => {
  await withServer(async (port) => {
    const wrong = 'Basic ' + Buffer.from(`admin:${PASSWORD}x`).toString('base64');
    const res = await request(port, 'GET', '/', { Authorization: wrong });
    assert.equal(res.status, 303);
    const api = await request(port, 'GET', LOOKUP, { Authorization: wrong });
    assert.equal(api.status, 401);
    assert.equal(api.headers['www-authenticate'], undefined);
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

test('non-GET requests return 405 with auth and 401 without (healthz is GET only)', async () => {
  await withServer(async (port) => {
    const anon = await request(port, 'POST', '/healthz');
    assert.equal(anon.status, 401);
    assert.equal(anon.headers['www-authenticate'], undefined);

    const authed = await request(port, 'POST', '/healthz', { Authorization: AUTH });
    assert.equal(authed.status, 405);
    assert.equal(authed.headers.allow, 'GET');
    assert.deepEqual(JSON.parse(authed.body), { error: 'method not allowed' });
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

// /api/email. checkSpf is injected so the test does not depend on lib/spf.js.
const stubSpf = async (domain) => ({ domain, found: false, record: null, records: [], errors: [], warnings: [] });

test('/api/email returns 401 without auth', async () => {
  await withServer(async (port) => {
    const res = await getAnon(port, '/api/email?domain=example.com');
    assert.equal(res.status, 401);
  }, { checkSpf: stubSpf });
});

test('/api/email rejects a bad domain, a missing domain and a bad selector', async () => {
  await withServer(async (port) => {
    let res = await get(port, '/api/email?domain=exa%20mple.com');
    assert.equal(res.status, 400);
    res = await get(port, '/api/email');
    assert.equal(res.status, 400);
    res = await get(port, '/api/email?domain=example.com&selector=bad%20selector');
    assert.equal(res.status, 400);
    assert.deepEqual(JSON.parse(res.body), { error: 'Invalid DKIM selector' });
  }, { checkSpf: stubSpf });
});

test('/api/email returns the combined result, allowing dotted selectors', async () => {
  const calls = [];
  await withServer(async (port) => {
    const res = await get(port, '/api/email?domain=Example.com&selector=s1.2024');
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.input, 'Example.com');
    assert.equal(body.domain, 'example.com');
    assert.equal(body.dkim.name, 's1.2024._domainkey.example.com');
    assert.deepEqual(Object.keys(body).sort(), ['dkim', 'dmarc', 'domain', 'input', 'mx', 'spf']);
    assert.ok(calls.length > 0 && calls.every((c) => c.transport === 'tcp'));

    const noSel = JSON.parse((await get(port, '/api/email?domain=example.com')).body);
    assert.equal(noSel.dkim, null);
  }, { query: fakeQuery(calls), checkSpf: stubSpf });
});

// ---- Phase 4: rate limits, concurrency, headers and methods ----

const BAD = 'Basic ' + Buffer.from('admin:wrong-password-1').toString('base64');
const LOOKUP = '/api/lookup?domain=example.com&type=A';

test('failed auth is locked out with 429 and Retry-After, even with correct credentials', async () => {
  await withServer(async (port) => {
    for (let i = 0; i < 3; i++) {
      const res = await request(port, 'GET', '/', { Authorization: BAD });
      assert.equal(res.status, 303);
    }
    const locked = await get(port, '/');
    assert.equal(locked.status, 429);
    assert.deepEqual(JSON.parse(locked.body), { error: 'Too many failed sign-in attempts. Try again later.' });
    assert.ok(Number(locked.headers['retry-after']) > 0);
    assert.equal(locked.headers['cache-control'], 'no-store');
    assert.equal((await getAnon(port, '/healthz')).status, 200, 'healthz is exempt');
    assert.equal((await request(port, 'GET', '/healthz', { Authorization: BAD })).status, 200);
  }, { limits: { failedAuthPer15Min: 3 } });
});

test('failed auth lockout is per client', async () => {
  await withServer(async (port) => {
    await request(port, 'GET', '/', { Authorization: BAD, 'X-Forwarded-For': '1.1.1.1' });
    const locked = await request(port, 'GET', '/', { Authorization: AUTH, 'X-Forwarded-For': '1.1.1.1' });
    assert.equal(locked.status, 429);
    const other = await request(port, 'GET', '/', { Authorization: AUTH, 'X-Forwarded-For': '2.2.2.2' });
    assert.equal(other.status, 200);
  }, { limits: { failedAuthPer15Min: 1 } });
});

test('API rate limit gives 429; static files and healthz are not counted', async () => {
  await withServer(async (port) => {
    for (let i = 0; i < 5; i++) assert.equal((await get(port, '/index.html')).status, 200);
    for (let i = 0; i < 5; i++) assert.equal((await getAnon(port, '/healthz')).status, 200);
    assert.equal((await get(port, LOOKUP)).status, 200);
    assert.equal((await get(port, LOOKUP)).status, 200);
    const res = await get(port, LOOKUP);
    assert.equal(res.status, 429);
    const body = JSON.parse(res.body);
    assert.match(body.error, /^Rate limit reached: 2 requests per minute\. Try again in \d+ seconds\.$/);
    assert.ok(Number(res.headers['retry-after']) >= 1);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal((await get(port, '/index.html')).status, 200);
    assert.equal((await getAnon(port, '/healthz')).status, 200);
  }, { limits: { apiPerMinute: 2 } });
});

// A query that blocks until release() is called.
function blockingQuery() {
  const waiters = [];
  const fn = (args) => new Promise((resolve) => {
    waiters.push(() => resolve({
      rcodeName: 'NOERROR',
      flags: { tc: false },
      answers: [{ name: 'example.com', type: 'A', class: 1, ttl: 60, data: '1.2.3.4' }],
      ms: 1,
    }));
  });
  fn.release = () => waiters.splice(0).forEach((w) => w());
  fn.pending = () => waiters.length;
  return fn;
}

async function waitFor(cond) {
  for (let i = 0; i < 200 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
  assert.ok(cond(), 'condition not met in time');
}

test('concurrency cap gives 429 and frees the slot afterwards', async () => {
  const q = blockingQuery();
  await withServer(async (port) => {
    const first = get(port, LOOKUP);
    await waitFor(() => q.pending() > 0);
    const rejected = await get(port, LOOKUP);
    assert.equal(rejected.status, 429);
    assert.deepEqual(JSON.parse(rejected.body), { error: 'Too many lookups in progress. Wait for them to finish.' });
    assert.equal(rejected.headers['cache-control'], 'no-store');
    q.release();
    assert.equal((await first).status, 200);
    const again = get(port, LOOKUP);
    await waitFor(() => q.pending() > 0);
    q.release();
    assert.equal((await again).status, 200);
  }, { query: q, resolvers: [RESOLVERS[0]], limits: { maxConcurrentApiPerClient: 1 } });
});

test('global concurrency cap applies across clients', async () => {
  const q = blockingQuery();
  await withServer(async (port) => {
    const first = request(port, 'GET', LOOKUP, { Authorization: AUTH, 'X-Forwarded-For': '1.1.1.1' });
    await waitFor(() => q.pending() > 0);
    const rejected = await request(port, 'GET', LOOKUP, { Authorization: AUTH, 'X-Forwarded-For': '2.2.2.2' });
    assert.equal(rejected.status, 429);
    q.release();
    assert.equal((await first).status, 200);
  }, { query: q, resolvers: [RESOLVERS[0]], limits: { maxConcurrentApi: 1, maxConcurrentApiPerClient: 5 } });
});

test('concurrency slots are released after handler errors', async () => {
  const failing = { ...fakeQuery([]) };
  await withServer(async (port) => {
    for (let i = 0; i < 4; i++) {
      // Missing domain returns 400 early; an invalid selector too. Both must free the slot.
      assert.equal((await get(port, '/api/lookup')).status, 400);
    }
    for (let i = 0; i < 3; i++) {
      assert.equal((await get(port, LOOKUP)).status, 200);
    }
  }, { query: failing, limits: { maxConcurrentApiPerClient: 1, maxConcurrentApi: 1 } });

  const boom = async () => { throw new Error('kaboom'); };
  await withServer(async (port) => {
    // The injected query throws; per-server errors are reported, never leaving a slot held.
    for (let i = 0; i < 3; i++) {
      const res = await get(port, LOOKUP);
      assert.ok(res.status === 200 || res.status === 500);
    }
    assert.equal((await get(port, '/api/lookup')).status, 400, 'slot is free, so not 429');
  }, { query: boom, resolvers: [RESOLVERS[0]], limits: { maxConcurrentApiPerClient: 1, maxConcurrentApi: 1 } });
});

test('outbound queries are capped and queued, not rejected', async () => {
  let running = 0;
  let peak = 0;
  const q = async () => {
    running += 1;
    peak = Math.max(peak, running);
    await new Promise((r) => setTimeout(r, 10));
    running -= 1;
    return { rcodeName: 'NOERROR', flags: { tc: false }, answers: [], ms: 1 };
  };
  await withServer(async (port) => {
    const res = await get(port, LOOKUP);
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).results.length, 4);
    assert.equal(peak, 1);
  }, {
    query: q,
    resolvers: [1, 2, 3, 4].map((n) => ({ name: `R${n}`, address: `10.0.0.${n}` })),
    timeout: 5000,
    limits: { maxOutboundQueries: 1 },
  });
});

test('security headers appear on 200, 401, 404, 405 and 429', async () => {
  await withServer(async (port) => {
    const responses = {
      200: await get(port, '/index.html'),
      401: await getAnon(port, '/api/lookup'),
      404: await get(port, '/nope.html'),
      405: await request(port, 'POST', '/api/lookup', { Authorization: AUTH }),
    };
    await request(port, 'GET', '/', { Authorization: BAD });
    await request(port, 'GET', '/', { Authorization: BAD });
    responses[429] = await get(port, '/');
    for (const [status, res] of Object.entries(responses)) {
      assert.equal(res.status, Number(status));
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
        assert.equal(res.headers[name], value, `${name} on ${status}`);
      }
    }
    assert.equal(responses[401].headers['cache-control'], 'no-store');
    assert.equal(responses[429].headers['cache-control'], 'no-store');
  }, { limits: { failedAuthPer15Min: 2 } });
});

test('hsts has no includeSubDomains and /api responses are no-store', async () => {
  await withServer(async (port) => {
    const res = await get(port, LOOKUP);
    assert.equal(res.status, 200);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['strict-transport-security'], 'max-age=31536000');
    assert.equal((await get(port, '/api/nothing')).headers['cache-control'], 'no-store');
  });
});

test('non-GET on a known route gives 405 with Allow; unknown routes stay 404', async () => {
  await withServer(async (port) => {
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const res = await request(port, method, '/api/lookup', { Authorization: AUTH });
      assert.equal(res.status, 405);
      assert.equal(res.headers.allow, 'GET');
    }
    assert.equal((await request(port, 'POST', '/healthz', { Authorization: AUTH })).status, 405);
    assert.equal((await request(port, 'POST', '/nowhere', { Authorization: AUTH })).status, 404);
    assert.equal((await request(port, 'POST', '/api/lookup')).status, 401, 'auth is checked first');
  });
});

test('selftest runtime reports how the client address was seen', async () => {
  await withServer(async (port) => {
    const res = await request(port, 'GET', '/api/selftest', {
      Authorization: AUTH,
      'X-Forwarded-For': '9.9.9.9, 203.0.113.7',
      'X-Real-IP': '203.0.113.8',
    });
    const rt = JSON.parse(res.body).runtime;
    assert.equal(rt.forwardedFor, '9.9.9.9, 203.0.113.7');
    assert.equal(rt.realIp, '203.0.113.8');
    assert.equal(rt.clientKey, '203.0.113.7');
    assert.ok(rt.remoteAddress === null || typeof rt.remoteAddress === 'string');
    assert.equal(JSON.stringify(rt).includes('Basic'), false);

    const plain = JSON.parse((await get(port, '/api/selftest')).body).runtime;
    assert.equal(plain.forwardedFor, null);
    assert.equal(plain.realIp, null);
  });
});

test('requests without credentials never count as failed sign-ins', async () => {
  await withServer(async (port) => {
    // Browsers send no credentials until they have seen a 401, so these are normal.
    for (let i = 0; i < 5; i++) assert.equal((await getAnon(port, '/')).status, 303);
    assert.equal((await get(port, '/')).status, 200);
  }, { limits: { failedAuthPer15Min: 2 } });
});

test('the shared "unknown" client key is never locked out', async () => {
  // Over a Unix socket with no proxy headers, every client is 'unknown'. Locking that
  // key out would let anyone lock out the real user.
  const os = require('node:os');
  const path = require('node:path');
  const socketPath = path.join(os.tmpdir(), `dnschecker-test-${process.pid}.sock`);
  const server = createServer({ password: PASSWORD, resolvers: RESOLVERS, query: fakeQuery([]), limits: { failedAuthPer15Min: 1 } });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  const viaSocket = (headers) => new Promise((resolve, reject) => {
    http.get({ socketPath, path: '/', headers }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
  });
  try {
    for (let i = 0; i < 3; i++) assert.equal(await viaSocket({ Authorization: BAD }), 303);
    assert.equal(await viaSocket({ Authorization: AUTH }), 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// ---- Login form and session cookie ----

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const form = (fields) => new URLSearchParams(fields).toString();
const login = (port, fields, headers = {}) =>
  request(port, 'POST', '/login', { ...FORM, ...headers }, form(fields));
const GOOD = { username: 'admin', password: PASSWORD };

function cookieFrom(res) {
  const set = res.headers['set-cookie'];
  assert.ok(set && set.length === 1, 'expected one Set-Cookie');
  return set[0].split(';')[0];
}

test('login page, its script and the stylesheet need no sign-in', async () => {
  await withServer(async (port) => {
    const page = await getAnon(port, '/login.html');
    assert.equal(page.status, 200);
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.match(page.body, /<form method="post" action="\/login"/);
    assert.doesNotMatch(page.body, /<script(?![^>]*src=)|style=/);
    assert.equal((await getAnon(port, '/login.js')).status, 200);
    assert.equal((await getAnon(port, '/style.css')).status, 200);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(page.headers[name], value, name);
    }
  });
});

test('good credentials set a session cookie that unlocks pages and the API', async () => {
  await withServer(async (port) => {
    const res = await login(port, { ...GOOD, next: '/selftest.html' });
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/selftest.html');
    assert.equal(res.headers['cache-control'], 'no-store');
    const set = res.headers['set-cookie'][0];
    for (const attr of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=2592000']) {
      assert.ok(set.includes(attr), `${attr} in ${set}`);
    }
    const cookie = cookieFrom(res);
    assert.equal((await request(port, 'GET', '/', { Cookie: cookie })).status, 200);
    const api = await request(port, 'GET', LOOKUP, { Cookie: cookie });
    assert.equal(api.status, 200);
    assert.equal(api.headers['www-authenticate'], undefined);
  });
});

test('bad credentials redirect with error=1, keep next, and set no cookie', async () => {
  await withServer(async (port) => {
    const res = await login(port, { username: 'admin', password: 'nope-nope-nope', next: '/selftest.html' });
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/login.html?error=1&next=%2Fselftest.html');
    assert.equal(res.headers['set-cookie'], undefined);
    const noUser = await login(port, { password: PASSWORD });
    assert.equal(noUser.headers.location, '/login.html?error=1&next=%2F');
  });
});

test('repeated bad logins lock the client out, even with the right password', async () => {
  await withServer(async (port) => {
    for (let i = 0; i < 3; i++) {
      const res = await login(port, { username: 'admin', password: 'wrong-password-1' });
      assert.equal(res.headers.location, '/login.html?error=1&next=%2F');
    }
    const locked = await login(port, { ...GOOD, next: '/' });
    assert.equal(locked.status, 303);
    assert.equal(locked.headers.location, '/login.html?error=locked&next=%2F');
    assert.equal(locked.headers['set-cookie'], undefined);
  }, { limits: { failedAuthPer15Min: 3 } });
});

test('a locked-out client with a valid session cookie keeps working', async () => {
  await withServer(async (port) => {
    const cookie = cookieFrom(await login(port, GOOD));
    await login(port, { username: 'admin', password: 'wrong-password-1' });
    assert.equal((await login(port, GOOD)).headers.location, '/login.html?error=locked&next=%2F');
    assert.equal((await request(port, 'GET', '/', { Cookie: cookie })).status, 200);
  }, { limits: { failedAuthPer15Min: 1 } });
});

test('the shared "unknown" key is never locked out on the login form either', async () => {
  const os = require('node:os');
  const path = require('node:path');
  const socketPath = path.join(os.tmpdir(), `dnschecker-login-${process.pid}.sock`);
  const server = createServer({ password: PASSWORD, resolvers: RESOLVERS, query: fakeQuery([]), limits: { failedAuthPer15Min: 1 } });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  const post = (fields) => new Promise((resolve, reject) => {
    const req = http.request({ socketPath, method: 'POST', path: '/login', headers: FORM }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.headers.location));
    });
    req.on('error', reject);
    req.end(form(fields));
  });
  try {
    for (let i = 0; i < 3; i++) assert.match(await post({ username: 'admin', password: 'wrong-password-1' }), /error=1/);
    assert.equal(await post(GOOD), '/');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('a foreign Origin is refused, a matching or missing Origin is allowed', async () => {
  await withServer(async (port) => {
    const foreign = await login(port, GOOD, { Origin: 'https://evil.example' });
    assert.equal(foreign.status, 403);
    assert.equal(foreign.headers['set-cookie'], undefined);
    assert.equal((await login(port, GOOD, { Origin: 'null' })).status, 403);
    // Browsers send "Origin: null" on same-origin posts under Referrer-Policy: no-referrer.
    assert.equal((await login(port, GOOD, { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await login(port, GOOD, { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' })).status, 303);
    assert.equal((await login(port, GOOD, { Origin: `http://127.0.0.1:${port}` })).status, 303);
    // Sec-Fetch-Site decides when present, so a proxy rewriting Host can't break sign-in.
    assert.equal((await login(port, GOOD, { Origin: 'https://dnschecker.example', 'Sec-Fetch-Site': 'same-origin' })).status, 303);
    assert.equal((await login(port, GOOD, { Origin: `http://127.0.0.1:${port}`, 'Sec-Fetch-Site': 'same-site' })).status, 403);
    assert.equal((await login(port, GOOD, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await request(port, 'POST', '/logout', { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await request(port, 'POST', '/logout', { Origin: `http://127.0.0.1:${port}` })).status, 303);
  });
});

test('unsafe next values are rewritten to /', async () => {
  await withServer(async (port) => {
    for (const next of ['//evil.com', '/\\evil.com', 'https://evil.com', 'evil.com', '/a\\b', '/a\r\nb', '']) {
      const res = await login(port, { ...GOOD, next });
      assert.equal(res.status, 303);
      assert.equal(res.headers.location, '/', JSON.stringify(next));
    }
    assert.equal((await login(port, { ...GOOD, next: '/selftest.html?a=1' })).headers.location, '/selftest.html?a=1');
  });
});

test('oversized login bodies give 413 and other content types 415', async () => {
  await withServer(async (port) => {
    const big = await login(port, { ...GOOD, next: '/' + 'a'.repeat(5000) });
    assert.equal(big.status, 413);
    const wrong = await request(port, 'POST', '/login', { 'Content-Type': 'application/json' }, JSON.stringify(GOOD));
    assert.equal(wrong.status, 415);
    const none = await request(port, 'POST', '/login', {}, form(GOOD));
    assert.equal(none.status, 415);
    assert.equal(big.headers['set-cookie'], undefined);
  });
});

test('logout clears the cookie and redirects to the login page', async () => {
  await withServer(async (port) => {
    const res = await request(port, 'POST', '/logout');
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/login.html');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.match(res.headers['set-cookie'][0], /^dnschecker_session=; .*Max-Age=0/);
  });
});

test('tampered, foreign and empty session cookies are rejected', async () => {
  await withServer(async (port) => {
    const cookie = cookieFrom(await login(port, GOOD));
    const [, value] = cookie.split('=');
    const parts = value.split('.');
    const flipped = parts[3].slice(0, -2) + (parts[3].endsWith('AA') ? 'BB' : 'AA');
    const bad = [
      `dnschecker_session=${[parts[0], Number(parts[1]) + 1000, parts[2], parts[3]].join('.')}`,
      `dnschecker_session=${[parts[0], parts[1], parts[2], flipped].join('.')}`,
      `dnschecker_session=${value}x`,
      'dnschecker_session=',
      'dnschecker_session=garbage',
    ];
    for (const c of bad) {
      assert.equal((await request(port, 'GET', '/', { Cookie: c })).status, 303, c);
      assert.equal((await request(port, 'GET', LOOKUP, { Cookie: c })).status, 401, c);
    }
    // A cookie from a server with another password is no good here.
    await withServer(async (otherPort) => {
      const foreign = cookieFrom(await login(otherPort, { username: 'admin', password: 'another-long-password' }));
      assert.equal((await request(port, 'GET', '/', { Cookie: foreign })).status, 303);
    }, { password: 'another-long-password' });
  });
});

test('Basic auth still works for scripts, alongside the cookie', async () => {
  await withServer(async (port) => {
    assert.equal((await get(port, LOOKUP)).status, 200);
    assert.equal((await get(port, '/')).status, 200);
  });
});

test('POST /login and /logout are known routes; other methods get 405 with Allow: POST', async () => {
  await withServer(async (port) => {
    const res = await request(port, 'GET', '/login', { Authorization: AUTH });
    assert.equal(res.status, 405);
    assert.equal(res.headers.allow, 'POST');
  });
});

test('the request log never contains credentials or cookies', async () => {
  const lines = [];
  const original = console.log;
  console.log = (...args) => lines.push(args.join(' '));
  try {
    await withServer(async (port) => {
      const res = await login(port, { username: 'admin', password: 'secret-log-check-1' });
      await request(port, 'GET', '/', { Cookie: cookieFrom(await login(port, GOOD)) });
      assert.equal(res.status, 303);
    });
  } finally {
    console.log = original;
  }
  const log = lines.join('\n');
  assert.match(log, /POST \/login 303/);
  assert.doesNotMatch(log, /secret-log-check-1|correct-horse|dnschecker_session|v1\./);
});
