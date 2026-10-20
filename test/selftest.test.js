'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { selftest } = require('../lib/selftest');

const RESOLVERS = [
  { name: 'Ok', address: '10.0.0.1' },
  { name: 'NoData', address: '10.0.0.2' },
  { name: 'NxDomain', address: '10.0.0.3' },
  { name: 'Timeout', address: '10.0.0.4' },
  { name: 'Broken', address: '10.0.0.5' },
];

// Fake transport: behaviour is chosen by resolver address and transport.
function fakeQuery(calls) {
  return async ({ server, name, type, transport, timeout }) => {
    calls.push({ server, name, type, transport, timeout });
    switch (server) {
      case '10.0.0.1':
        return {
          rcodeName: 'NOERROR',
          flags: { tc: false },
          answers: [
            { type: 'A', ttl: 300, data: '93.184.216.34' },
            { type: 'A', ttl: 120, data: '93.184.216.35' },
            { type: 'CNAME', ttl: 10, data: 'alias.example.net' },
          ],
          ms: 12,
        };
      case '10.0.0.2':
        return { rcodeName: 'NOERROR', flags: { tc: false }, answers: [], ms: 7 };
      case '10.0.0.3':
        return { rcodeName: 'NXDOMAIN', flags: { tc: false }, answers: [], ms: 9 };
      case '10.0.0.4': {
        await new Promise((r) => setTimeout(r, 5));
        const err = new Error('query timed out');
        err.code = 'ETIMEOUT';
        throw err;
      }
      default: {
        const err = new Error('connection refused');
        err.code = 'ECONNREFUSED';
        throw err;
      }
    }
  };
}

function find(result, resolver, transport) {
  return result.results.find((r) => r.resolver === resolver && r.transport === transport);
}

test('maps each response to the expected status', async () => {
  const out = await selftest({ resolvers: RESOLVERS, query: fakeQuery([]) });

  const ok = find(out, 'Ok', 'udp');
  assert.equal(ok.status, 'ok');
  assert.deepEqual(ok.answers, ['93.184.216.34', '93.184.216.35']);
  assert.equal(ok.ttl, 120, 'ttl is the minimum of the A records');
  assert.equal(ok.ms, 12);
  assert.equal(ok.error, undefined);

  const nodata = find(out, 'NoData', 'tcp');
  assert.equal(nodata.status, 'nodata');
  assert.deepEqual(nodata.answers, []);
  assert.equal(nodata.ttl, null);

  const nx = find(out, 'NxDomain', 'udp');
  assert.equal(nx.status, 'nxdomain');
  assert.equal(nx.ttl, null);

  const timeout = find(out, 'Timeout', 'tcp');
  assert.equal(timeout.status, 'timeout');
  assert.equal(typeof timeout.ms, 'number');
  assert.ok(timeout.ms >= 0);
  assert.equal(timeout.error, undefined);

  const broken = find(out, 'Broken', 'udp');
  assert.equal(broken.status, 'error');
  assert.equal(broken.error, 'ECONNREFUSED');
  assert.equal(broken.ttl, null);
});

test('reports SERVFAIL-style rcodes as error with the rcode name', async () => {
  const query = async () => ({ rcodeName: 'SERVFAIL', flags: { tc: false }, answers: [], ms: 3 });
  const out = await selftest({ resolvers: [{ name: 'X', address: '10.9.9.9' }], query });
  assert.equal(out.results[0].status, 'error');
  assert.equal(out.results[0].error, 'SERVFAIL');
});

test('uses the message when a rejection has no code', async () => {
  const query = async () => {
    throw new Error('something odd');
  };
  const out = await selftest({ resolvers: [{ name: 'X', address: '10.9.9.9' }], query });
  assert.equal(out.results[0].status, 'error');
  assert.equal(out.results[0].error, 'something odd');
});

test('queries every resolver over both udp and tcp, with fixed target and type', async () => {
  const calls = [];
  const out = await selftest({ resolvers: RESOLVERS, query: fakeQuery(calls), timeout: 1234 });

  assert.equal(calls.length, RESOLVERS.length * 2);
  for (const r of RESOLVERS) {
    for (const transport of ['udp', 'tcp']) {
      const hit = calls.find((c) => c.server === r.address && c.transport === transport);
      assert.ok(hit, `missing ${transport} query to ${r.address}`);
      assert.equal(hit.name, 'example.com');
      assert.equal(hit.type, 'A');
      assert.equal(hit.timeout, 1234);
    }
  }

  assert.equal(out.target, 'example.com');
  assert.equal(out.type, 'A');
  assert.equal(out.results.length, RESOLVERS.length * 2);
  assert.ok(!Number.isNaN(Date.parse(out.startedAt)));
});

test('summary counts reachable results per transport', async () => {
  const out = await selftest({ resolvers: RESOLVERS, query: fakeQuery([]) });
  // Only ok counts as reachable. nodata and nxdomain for example.com mean interception.
  assert.deepEqual(out.summary, {
    udp: { reachable: 1, total: 5 },
    tcp: { reachable: 1, total: 5 },
  });
  assert.equal(out.warnings.length, 4);
  assert.match(out.warnings[0], /intercepted/);
});

test('no warnings when every resolver answers', async () => {
  const query = async () => ({ rcodeName: 'NOERROR', flags: { tc: false }, answers: [{ type: 'A', ttl: 60, data: '1.2.3.4' }], ms: 1.234 });
  const out = await selftest({ resolvers: RESOLVERS.slice(0, 2), query });
  assert.deepEqual(out.warnings, []);
  assert.equal(out.results[0].ms, 1.2);
});

test('summary reflects a transport that only fails on one protocol', async () => {
  const query = async ({ transport }) => {
    if (transport === 'tcp') {
      const err = new Error('timed out');
      err.code = 'ETIMEOUT';
      throw err;
    }
    return { rcodeName: 'NOERROR', flags: { tc: false }, answers: [{ type: 'A', ttl: 60, data: '1.2.3.4' }], ms: 1 };
  };
  const out = await selftest({ resolvers: RESOLVERS.slice(0, 2), query });
  assert.deepEqual(out.summary, {
    udp: { reachable: 2, total: 2 },
    tcp: { reachable: 0, total: 2 },
  });
});

test('one failing resolver does not reject the whole run', async () => {
  const query = async ({ server }) => {
    if (server === '10.0.0.5') throw new Error('boom');
    return { rcodeName: 'NOERROR', flags: { tc: false }, answers: [{ type: 'A', ttl: 1, data: '1.2.3.4' }], ms: 1 };
  };
  const out = await selftest({ resolvers: RESOLVERS, query });
  assert.equal(out.results.length, 10);
  assert.equal(find(out, 'Broken', 'udp').status, 'error');
  assert.equal(find(out, 'Ok', 'udp').status, 'ok');
});
