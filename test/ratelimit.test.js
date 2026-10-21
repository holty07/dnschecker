'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createRateLimiter,
  createConcurrencyLimiter,
  createSemaphore,
  clientKey,
} = require('../lib/ratelimit');

function clock(start = 1000000) {
  const c = { t: start, now: () => c.t };
  return c;
}

test('rate limiter counts down remaining and blocks over the limit', () => {
  const c = clock();
  const rl = createRateLimiter({ limit: 3, windowMs: 60000, now: c.now });
  assert.deepEqual(rl.hit('a'), { allowed: true, remaining: 2, retryAfterSeconds: 60 });
  c.t += 10000;
  assert.equal(rl.hit('a').remaining, 1);
  assert.equal(rl.hit('a').remaining, 0);
  const blocked = rl.hit('a');
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 50);
  assert.equal(rl.hit('b').allowed, true, 'keys are independent');
});

test('rate limiter window rolls over', () => {
  const c = clock();
  const rl = createRateLimiter({ limit: 1, windowMs: 1000, now: c.now });
  assert.equal(rl.hit('a').allowed, true);
  assert.equal(rl.hit('a').allowed, false);
  c.t += 999;
  assert.equal(rl.hit('a').allowed, false);
  c.t += 1;
  const r = rl.hit('a');
  assert.equal(r.allowed, true);
  assert.equal(r.remaining, 0);
});

test('peek does not count a hit', () => {
  const c = clock();
  const rl = createRateLimiter({ limit: 2, windowMs: 1000, now: c.now });
  assert.equal(rl.peek('a').allowed, true);
  rl.hit('a');
  assert.equal(rl.peek('a').allowed, true);
  rl.hit('a');
  assert.equal(rl.peek('a').allowed, false);
  assert.equal(rl.peek('a').allowed, false);
  c.t += 1000;
  assert.equal(rl.peek('a').allowed, true);
});

test('rate limiter evicts the oldest keys beyond maxKeys', () => {
  const c = clock();
  const rl = createRateLimiter({ limit: 1, windowMs: 60000, now: c.now, maxKeys: 3 });
  for (const k of ['a', 'b', 'c', 'd', 'e']) {
    rl.hit(k);
    c.t += 1;
  }
  assert.equal(rl.size, 3);
  // 'a' was evicted, so it is allowed again; 'e' is still counted.
  assert.equal(rl.hit('e').allowed, false);
  assert.equal(rl.hit('a').allowed, true);
});

test('rate limiter prunes expired keys before evicting live ones', () => {
  const c = clock();
  const rl = createRateLimiter({ limit: 1, windowMs: 1000, now: c.now, maxKeys: 2 });
  rl.hit('old1');
  rl.hit('old2');
  c.t += 5000;
  rl.hit('live1');
  rl.hit('live2');
  assert.equal(rl.size, 2);
  assert.equal(rl.hit('live1').allowed, false);
});

test('concurrency limiter acquires, rejects and releases idempotently', () => {
  const cl = createConcurrencyLimiter(2);
  const r1 = cl.tryAcquire();
  const r2 = cl.tryAcquire();
  assert.equal(cl.active, 2);
  assert.equal(cl.tryAcquire(), null);
  r1();
  r1(); // second call must not free another slot
  assert.equal(cl.active, 1);
  assert.equal(cl.tryAcquire() !== null, true);
  assert.equal(cl.active, 2);
  assert.equal(cl.tryAcquire(), null);
  r2();
  assert.equal(cl.active, 1);
});

test('semaphore queues in order and never exceeds max', async () => {
  const sem = createSemaphore(2);
  let running = 0;
  let peak = 0;
  const started = [];
  const gates = [];
  const jobs = [0, 1, 2, 3].map((i) => sem.run(() => new Promise((resolve) => {
    started.push(i);
    running += 1;
    peak = Math.max(peak, running);
    gates[i] = () => { running -= 1; resolve(i); };
  })));
  assert.deepEqual(started, [0, 1]);
  assert.equal(sem.queued, 2);
  gates[0]();
  await jobs[0];
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(started, [0, 1, 2]);
  gates[1]();
  gates[2]();
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(started, [0, 1, 2, 3]);
  gates[3]();
  assert.deepEqual(await Promise.all(jobs), [0, 1, 2, 3]);
  assert.equal(peak, 2);
  assert.equal(sem.active, 0);
});

test('semaphore frees its slot when a job rejects or throws', async () => {
  const sem = createSemaphore(1);
  await assert.rejects(sem.run(async () => { throw new Error('boom'); }), /boom/);
  await assert.rejects(sem.run(() => { throw new Error('sync'); }), /sync/);
  assert.equal(await sem.run(async () => 'ok'), 'ok');
});

test('clientKey uses the last X-Forwarded-For entry', () => {
  const req = { headers: { 'x-forwarded-for': '6.6.6.6, 7.7.7.7 ,  203.0.113.9 ' }, socket: { remoteAddress: '10.0.0.1' } };
  assert.equal(clientKey(req), '203.0.113.9');
});

test('clientKey falls back to X-Real-IP, the socket, then unknown', () => {
  assert.equal(clientKey({ headers: { 'x-real-ip': ' 198.51.100.4 ' }, socket: { remoteAddress: '10.0.0.1' } }), '198.51.100.4');
  assert.equal(clientKey({ headers: {}, socket: { remoteAddress: '10.0.0.1' } }), '10.0.0.1');
  assert.equal(clientKey({ headers: {}, socket: {} }), 'unknown');
  assert.equal(clientKey({ headers: { 'x-forwarded-for': ' , ' }, socket: {} }), 'unknown');
});

test('clientKey caps the length at 64', () => {
  const long = 'x'.repeat(200);
  assert.equal(clientKey({ headers: { 'x-forwarded-for': long }, socket: {} }).length, 64);
});
