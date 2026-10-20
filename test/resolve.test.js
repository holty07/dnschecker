'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { formatAnswer, lookupOne, compareResults, lookupAll } = require('../lib/resolve');

const rec = (type, data, ttl = 300, name = 'example.com') => ({ name, type, class: 1, ttl, data });
const resp = (answers, rcode = 0, extra = {}) => ({
  flags: { rcode, tc: false, ...(extra.flags || {}) },
  rcodeName: ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'][rcode],
  answers,
  ms: extra.ms ?? 12.34,
});
const R = { name: 'Google', address: '8.8.8.8' };
const run = (query, type = 'A', extra = {}) => lookupOne({ resolver: R, name: 'example.com', type, query, ...extra });

test('formatAnswer for every type', () => {
  assert.equal(formatAnswer('A', '1.2.3.4'), '1.2.3.4');
  assert.equal(formatAnswer('AAAA', '2001:db8::1'), '2001:db8::1');
  assert.equal(formatAnswer('NS', 'ns1.example.com'), 'ns1.example.com');
  assert.equal(formatAnswer('CNAME', 'host.example.com'), 'host.example.com');
  assert.equal(formatAnswer('PTR', 'host.example.com'), 'host.example.com');
  assert.equal(formatAnswer('MX', { priority: 10, exchange: 'mx.example.com' }), '10 mx.example.com');
  assert.equal(formatAnswer('TXT', 'v=spf1 -all'), 'v=spf1 -all');
  assert.equal(
    formatAnswer('SOA', { nsname: 'ns1.example.com', hostmaster: 'hostmaster.example.com', serial: 2024010101, refresh: 7200, retry: 3600, expire: 1209600, minttl: 300 }),
    'ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 300',
  );
  assert.equal(formatAnswer('CAA', { flags: 0, tag: 'issue', value: 'letsencrypt.org' }), '0 issue "letsencrypt.org"');
  assert.equal(formatAnswer('WEIRD', 42), '42');
});

test('ok result, sorted answers, min TTL, rounded ms, tcp and timeout passed', async () => {
  let seen;
  const query = async (opts) => {
    seen = opts;
    return resp([rec('A', '9.9.9.9', 300), rec('A', '1.1.1.1', 60)], 0, { ms: 12.34 });
  };
  const r = await run(query, 'A', { timeout: 1234 });
  assert.deepEqual(seen, { server: '8.8.8.8', name: 'example.com', type: 'A', transport: 'tcp', timeout: 1234 });
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.answers, ['1.1.1.1', '9.9.9.9']);
  assert.equal(r.ttl, 60);
  assert.equal(r.ms, 12.3);
  assert.equal(r.resolver, 'Google');
  assert.equal(r.server, '8.8.8.8');
  assert.deepEqual(r.cname, []);
  assert.equal(r.error, undefined);
});

test('default timeout is 3000', async () => {
  let seen;
  await run(async (o) => { seen = o; return resp([]); });
  assert.equal(seen.timeout, 3000);
  assert.equal(seen.transport, 'tcp');
});

test('nodata, nxdomain', async () => {
  const nd = await run(async () => resp([]));
  assert.equal(nd.status, 'nodata');
  assert.equal(nd.ttl, null);
  assert.deepEqual(nd.answers, []);
  const nx = await run(async () => resp([], 3));
  assert.equal(nx.status, 'nxdomain');
});

test('nodata when only other types are present', async () => {
  const r = await run(async () => resp([rec('CNAME', 'x.example.com')]), 'A');
  assert.equal(r.status, 'nodata');
  assert.deepEqual(r.cname, ['x.example.com']);
});

test('SERVFAIL and REFUSED are errors with the rcode name', async () => {
  const sf = await run(async () => resp([], 2));
  assert.equal(sf.status, 'error');
  assert.equal(sf.error, 'SERVFAIL');
  const rf = await run(async () => resp([], 5));
  assert.equal(rf.error, 'REFUSED');
  const other = await run(async () => ({ flags: { rcode: 9 }, rcodeName: 'RCODE9', answers: [], ms: 1 }));
  assert.equal(other.status, 'error');
  assert.equal(other.error, 'RCODE9');
});

test('rejections: timeout and other errors never reject', async () => {
  const to = await run(async () => { const e = new Error('Timed out after 3000ms'); e.code = 'ETIMEOUT'; throw e; });
  assert.equal(to.status, 'timeout');
  assert.deepEqual(to.answers, []);
  assert.equal(to.ttl, null);
  assert.equal(typeof to.ms, 'number');
  const ref = await run(async () => { const e = new Error('connect refused'); e.code = 'ECONNREFUSED'; throw e; });
  assert.equal(ref.status, 'error');
  assert.equal(ref.error, 'ECONNREFUSED');
  const plain = await run(async () => { throw new Error('boom'); });
  assert.equal(plain.status, 'error');
  assert.equal(plain.error, 'boom');
});

test('CNAME chain when asking for A', async () => {
  const r = await run(async () => resp([
    rec('CNAME', 'host.example.com', 100, 'www.example.com'),
    rec('A', '1.2.3.4', 50, 'host.example.com'),
  ]));
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.cname, ['host.example.com']);
  assert.deepEqual(r.answers, ['1.2.3.4']);
  assert.equal(r.ttl, 50);
});

test('asking for CNAME gives answers, empty cname chain', async () => {
  const r = await run(async () => resp([rec('CNAME', 'host.example.com')]), 'CNAME');
  assert.deepEqual(r.answers, ['host.example.com']);
  assert.deepEqual(r.cname, []);
});

test('truncated flag is surfaced', async () => {
  const r = await run(async () => resp([rec('A', '1.1.1.1')], 0, { flags: { tc: true } }));
  assert.equal(r.status, 'ok');
  assert.equal(r.truncated, true);
});

test('TXT and MX answers', async () => {
  const t = await run(async () => resp([rec('TXT', 'b'), rec('TXT', 'a')]), 'TXT');
  assert.deepEqual(t.answers, ['a', 'b']);
  const m = await run(async () => resp([rec('MX', { priority: 20, exchange: 'b.example.com' }), rec('MX', { priority: 10, exchange: 'a.example.com' })]), 'MX');
  assert.deepEqual(m.answers, ['10 a.example.com', '20 b.example.com']);
});

const row = (status, answers) => ({ status, answers });

test('compareResults: majority with one outlier', () => {
  const rows = [row('ok', ['1.1.1.1']), row('ok', ['1.1.1.1']), row('ok', ['1.1.1.1']), row('ok', ['2.2.2.2'])];
  const c = compareResults(rows);
  assert.deepEqual(rows.map((r) => r.differs), [false, false, false, true]);
  assert.deepEqual(c, { majority: { status: 'ok', answers: ['1.1.1.1'] }, agreeing: 3, participating: 4, total: 4, allAgree: false });
});

test('compareResults: 2 versus 2 tie has no majority', () => {
  const rows = [row('ok', ['1']), row('ok', ['1']), row('ok', ['2']), row('ok', ['2'])];
  const c = compareResults(rows);
  assert.deepEqual(rows.map((r) => r.differs), [null, null, null, null]);
  assert.deepEqual(c, { majority: null, agreeing: 0, participating: 4, total: 4, allAgree: false });
});

test('compareResults: timeouts and errors are excluded', () => {
  const rows = [row('ok', ['1']), row('ok', ['1']), row('timeout', []), row('error', [])];
  const c = compareResults(rows);
  assert.deepEqual(rows.map((r) => r.differs), [false, false, false, false]);
  assert.equal(c.participating, 2);
  assert.equal(c.total, 4);
  assert.equal(c.agreeing, 2);
  assert.equal(c.allAgree, true);
});

test('compareResults: no participating rows', () => {
  const rows = [row('timeout', []), row('error', [])];
  const c = compareResults(rows);
  assert.deepEqual(c, { majority: null, agreeing: 0, participating: 0, total: 2, allAgree: false });
  assert.deepEqual(rows.map((r) => r.differs), [false, false]);
  assert.equal(compareResults([]).allAgree, false);
});

test('compareResults: status is part of the key, TTL ignored', () => {
  const rows = [
    { status: 'nxdomain', answers: [], ttl: 10 },
    { status: 'nxdomain', answers: [], ttl: 900 },
    { status: 'nodata', answers: [], ttl: 10 },
  ];
  const c = compareResults(rows);
  assert.deepEqual(rows.map((r) => r.differs), [false, false, true]);
  assert.equal(c.majority.status, 'nxdomain');
  const same = [{ status: 'ok', answers: ['1'], ttl: 1 }, { status: 'ok', answers: ['1'], ttl: 999 }];
  assert.equal(compareResults(same).allAgree, true);
});

test('lookupAll: parallel, sorted answers avoid false disagreement, all tcp', async () => {
  const calls = [];
  const query = async (o) => {
    calls.push(o);
    const order = o.server === '1.1.1.1' ? ['1.1.1.1', '2.2.2.2'] : ['2.2.2.2', '1.1.1.1'];
    return resp(order.map((a) => rec('A', a)));
  };
  const resolvers = [{ name: 'A', address: '1.1.1.1' }, { name: 'B', address: '8.8.8.8' }, { name: 'C', address: '9.9.9.9' }];
  const out = await lookupAll({ resolvers, name: 'example.com', type: 'A', query, timeout: 777 });
  assert.equal(out.name, 'example.com');
  assert.equal(out.type, 'A');
  assert.equal(out.results.length, 3);
  assert.equal(out.consensus.allAgree, true);
  assert.equal(calls.length, 3);
  for (const c of calls) {
    assert.equal(c.transport, 'tcp');
    assert.equal(c.timeout, 777);
  }
});

test('lookupAll: outlier and timeout', async () => {
  const query = async (o) => {
    if (o.server === '4.4.4.4') { const e = new Error('t'); e.code = 'ETIMEOUT'; throw e; }
    return resp([rec('A', o.server === '9.9.9.9' ? '6.6.6.6' : '1.1.1.1')]);
  };
  const resolvers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '4.4.4.4'].map((a, i) => ({ name: `R${i}`, address: a }));
  const { results, consensus } = await lookupAll({ resolvers, name: 'example.com', type: 'A', query, timeout: 100 });
  assert.deepEqual(results.map((r) => r.differs), [false, false, true, false]);
  assert.equal(results[3].status, 'timeout');
  assert.equal(consensus.participating, 3);
  assert.equal(consensus.agreeing, 2);
  assert.equal(consensus.allAgree, false);
});
