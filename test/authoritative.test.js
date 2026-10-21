'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { findZone, resolveNameservers, checkAuthoritative } = require('../lib/authoritative');

const DISCOVERY = [
  { name: 'Alpha', address: '8.8.8.8' },
  { name: 'Beta', address: '1.1.1.1' },
];
const isDiscovery = (server) => DISCOVERY.some((d) => d.address === server);

const rec = (name, type, data, ttl = 300) => ({ name, type, class: 1, ttl, data });
const soa = (name, serial) => rec(name, 'SOA', { nsname: 'ns1.example.com', hostmaster: 'h.example.com', serial, refresh: 1, retry: 1, expire: 1, minttl: 1 });
const reply = (answers, { rcode = 0, aa = false } = {}) => ({
  flags: { rcode, aa, tc: false },
  rcodeName: ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'][rcode],
  answers,
  ms: 1,
});
const fail = (code) => Object.assign(new Error(code), { code });

// Builds a fake `query`.
//   zones:   { apexName: { ns: [hosts], serial: n } }
//   hosts:   { nsHost: { A: [ips], AAAA: [ips] } }
//   direct:  (args) => reply | throws, for queries aimed at nameserver IPs
// Discovery queries (to 8.8.8.8 / 1.1.1.1) are answered from `zones` and `hosts`.
function makeFake({ zones, hosts, direct, discovery }) {
  const calls = [];
  const query = async (args) => {
    calls.push(args);
    if (isDiscovery(args.server)) {
      if (discovery) {
        const custom = discovery(args);
        if (custom !== undefined) return custom;
      }
      const { name, type } = args;
      if (type === 'NS') {
        if (zones[name]) return reply(zones[name].ns.map((h) => rec(name, 'NS', h)));
        const apex = Object.keys(zones).find((z) => name.endsWith(`.${z}`));
        return apex ? reply([], { rcode: name.startsWith('missing.') ? 3 : 0 }) : reply([], { rcode: 0 });
      }
      if (type === 'A' || type === 'AAAA') {
        const h = hosts[name];
        return reply(((h && h[type]) || []).map((ip) => rec(name, type, ip)));
      }
      return reply([]);
    }
    return direct(args);
  };
  return { query, calls };
}

const HOSTS = {
  'ns1.example.com': { A: ['45.1.1.1'], AAAA: ['2606:4700::1'] },
  'ns2.example.com': { A: ['45.1.1.2'], AAAA: ['2606:4700::2'] },
};
const ZONES = { 'example.com': { ns: ['ns2.example.com', 'ns1.example.com'] } };

// A well-behaved authoritative server: SOA at the apex, A at example.com and www.
function goodDirect(overrides = {}) {
  return (args) => {
    const o = overrides[args.server];
    if (o) {
      const r = o(args);
      if (r !== undefined) return r;
    }
    const { name, type } = args;
    if (type === 'SOA' && name === 'example.com') return reply([soa(name, 2024010101)], { aa: true });
    if (type === 'A' && (name === 'example.com' || name === 'www.example.com')) return reply([rec(name, 'A', '93.184.216.34')], { aa: true });
    if (name.startsWith('missing.')) return reply([], { rcode: 3, aa: true });
    return reply([], { aa: true });
  };
}

const opts = (fake, extra = {}) => ({ query: fake.query, resolvers: DISCOVERY, timeout: 500, ...extra });
const allTcp = (calls) => {
  assert.ok(calls.length > 0);
  for (const c of calls) assert.equal(c.transport, 'tcp');
};

test('normal zone: 2 nameservers x (v4 + v6) all agree', async () => {
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  assert.equal(out.zone, 'example.com');
  assert.equal(out.name, 'example.com');
  assert.equal(out.type, 'A');
  assert.deepEqual(out.nameservers.map((n) => n.host), ['ns1.example.com', 'ns2.example.com']);
  assert.deepEqual(out.nameservers[0].addresses, ['45.1.1.1', '2606:4700::1']);
  assert.equal(out.results.length, 4);
  for (const r of out.results) {
    assert.equal(r.status, 'ok');
    assert.equal(r.authoritative, true);
    assert.equal(r.lame, false);
    assert.equal(r.differs, false);
    assert.equal(r.serial, 2024010101);
    assert.ok(r.nameserver.startsWith('ns'));
    assert.equal(r.resolver, r.nameserver);
  }
  assert.equal(out.consensus.allAgree, true);
  assert.equal(out.consensus.participating, 4);
  assert.deepEqual(out.serials.values, [2024010101]);
  assert.equal(out.serials.allMatch, true);
  assert.equal(out.serials.byServer.length, 4);
  assert.deepEqual(out.serials.byServer[0], { nameserver: out.results[0].nameserver, server: out.results[0].server, serial: 2024010101 });
  assert.deepEqual(out.warnings, []);
  allTcp(fake.calls);
});

test('one nameserver lagging: older serial and different answer is flagged', async () => {
  const hosts = { ...HOSTS, 'ns3.example.com': { A: ['45.1.1.3'], AAAA: ['2606:4700::3'] } };
  const zones = { 'example.com': { ns: ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'] } };
  const stale = (args) => {
    if (args.type === 'SOA') return reply([soa('example.com', 2023010101)], { aa: true });
    if (args.type === 'A') return reply([rec(args.name, 'A', '66.1.1.1')], { aa: true });
  };
  const direct = goodDirect({ '45.1.1.3': stale, '2606:4700::3': stale });
  const fake = makeFake({ zones, hosts, direct });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  for (const r of out.results) assert.equal(r.differs, r.nameserver === 'ns3.example.com', `${r.nameserver} ${r.server}`);
  assert.equal(out.consensus.agreeing, 4);
  assert.equal(out.consensus.allAgree, false);
  assert.deepEqual(out.serials.values, [2023010101, 2024010101]);
  assert.equal(out.serials.allMatch, false);
  assert.equal(out.serials.byServer.filter((s) => s.serial === 2023010101).length, 2);
  assert.ok(out.warnings.includes('SOA serials differ: 2023010101, 2024010101. The zone has not synchronised across all nameservers.'));
});

test('single lagging address among several is flagged differs', async () => {
  const stale = (args) => {
    if (args.type === 'SOA') return reply([soa('example.com', 2023010101)], { aa: true });
    if (args.type === 'A') return reply([rec(args.name, 'A', '66.1.1.1')], { aa: true });
  };
  const direct = goodDirect({ '45.1.1.2': stale });
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  const outlier = out.results.find((r) => r.server === '45.1.1.2');
  assert.equal(outlier.differs, true);
  assert.equal(outlier.serial, 2023010101);
  assert.equal(out.results.filter((r) => r.differs).length, 1);
  assert.equal(out.consensus.agreeing, 3);
  assert.ok(out.warnings.some((w) => w.startsWith('SOA serials differ: 2023010101, 2024010101')));
});

test('SOA type reuses the SOA answer (one query per address)', async () => {
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'SOA' }, opts(fake));
  const directCalls = fake.calls.filter((c) => !isDiscovery(c.server));
  assert.equal(directCalls.length, 4);
  assert.equal(out.results[0].serial, 2024010101);
  assert.equal(out.consensus.allAgree, true);
});

test('subdomain without its own NS walks up to the parent zone', async () => {
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'www.example.com', type: 'A' }, opts(fake));
  assert.equal(out.zone, 'example.com');
  assert.equal(out.results.length, 4);
  assert.equal(out.consensus.allAgree, true);
  assert.deepEqual(out.warnings, []);
  const nsQueries = fake.calls.filter((c) => c.type === 'NS' && c.server === '8.8.8.8').map((c) => c.name);
  assert.deepEqual(nsQueries, ['www.example.com', 'example.com']);
});

test('name that is NXDOMAIN under an existing zone', async () => {
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'missing.example.com', type: 'A' }, opts(fake));
  assert.equal(out.zone, 'example.com');
  assert.ok(out.results.every((r) => r.status === 'nxdomain'));
  assert.equal(out.consensus.allAgree, true);
  assert.ok(out.warnings.includes("The name does not exist (NXDOMAIN); showing the zone's nameservers"));
  const z = await findZone('missing.example.com', opts(fake));
  assert.equal(z.nameExists, false);
  assert.equal((await findZone('example.com', opts(fake))).nameExists, true);
});

test('CNAME at the queried name is not treated as a zone apex', async () => {
  const discovery = (args) => {
    if (args.type === 'NS' && args.name === 'alias.example.com') {
      return reply([rec('alias.example.com', 'CNAME', 'target.example.net')]);
    }
    if (args.type === 'NS' && args.name === 'owned.example.com') {
      // NS records owned by another name do not count.
      return reply([rec('other.example.com', 'NS', 'ns9.example.com')]);
    }
  };
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect(), discovery });
  const z = await findZone('alias.example.com', opts(fake));
  assert.equal(z.zone, 'example.com');
  assert.deepEqual(z.nsHosts, ['ns1.example.com', 'ns2.example.com']);
  const z2 = await findZone('owned.example.com', opts(fake));
  assert.equal(z2.zone, 'example.com');
});

test('NS owner comparison is case-insensitive and hosts are sorted and unique', async () => {
  const discovery = (args) => {
    if (args.type === 'NS' && args.name === 'example.com') {
      return reply([rec('EXAMPLE.com.', 'NS', 'NS2.Example.com.'), rec('example.com', 'NS', 'ns1.example.com'), rec('example.com', 'NS', 'ns1.example.com')]);
    }
  };
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect(), discovery });
  const z = await findZone('example.com', opts(fake));
  assert.deepEqual(z.nsHosts, ['ns1.example.com', 'ns2.example.com']);
});

test('lame server (aa false) is flagged and excluded from consensus', async () => {
  const lame = (args) => {
    if (args.type === 'A') return reply([rec(args.name, 'A', '66.1.1.1')], { aa: false });
    if (args.type === 'SOA') return reply([soa('example.com', 2024010101)], { aa: false });
  };
  const direct = goodDirect({ '45.1.1.2': lame });
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  const row = out.results.find((r) => r.server === '45.1.1.2');
  assert.equal(row.lame, true);
  assert.equal(row.authoritative, false);
  assert.equal(row.differs, false);
  assert.equal(out.consensus.participating, 3);
  assert.equal(out.consensus.total, 4);
  assert.equal(out.consensus.allAgree, true);
  assert.ok(out.warnings.includes('1 nameserver answered non-authoritatively (lame delegation)'));
});

test('IPv6 ENETUNREACH is unreachable and excluded from the comparison', async () => {
  const direct = goodDirect();
  const query = async (args) => {
    if (!isDiscovery(args.server) && args.server.includes(':')) throw fail('ENETUNREACH');
    return direct(args);
  };
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: query });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  const v6 = out.results.filter((r) => r.server.includes(':'));
  assert.equal(v6.length, 2);
  for (const r of v6) {
    assert.equal(r.status, 'unreachable');
    assert.equal(r.error, 'ENETUNREACH');
    assert.equal(r.differs, false);
    assert.equal(r.lame, false);
    assert.equal(r.serial, null);
  }
  assert.equal(out.consensus.participating, 2);
  assert.equal(out.consensus.allAgree, true);
  assert.deepEqual(out.serials.values, [2024010101]);
  assert.ok(out.warnings.includes('2 addresses unreachable (IPv6 may not be available from this server)'));
});

test('private and loopback nameserver addresses are rejected and never queried', async () => {
  const hosts = {
    ...HOSTS,
    'ns2.example.com': { A: ['10.0.0.1', '45.1.1.2'], AAAA: ['::1', 'fe80::1', '::ffff:10.0.0.1'] },
  };
  const fake = makeFake({ zones: ZONES, hosts, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  const ns2 = out.nameservers.find((n) => n.host === 'ns2.example.com');
  assert.deepEqual(ns2.addresses, ['45.1.1.2']);
  assert.deepEqual(ns2.rejected.map((r) => r.address).sort(), ['10.0.0.1', '::1', '::ffff:10.0.0.1', 'fe80::1']);
  for (const r of ns2.rejected) assert.equal(r.reason, 'private or reserved address');
  for (const bad of ['10.0.0.1', '::1', 'fe80::1', '::ffff:10.0.0.1']) {
    assert.ok(!fake.calls.some((c) => c.server === bad), `queried ${bad}`);
    assert.ok(!out.results.some((r) => r.server === bad));
  }
  assert.ok(out.warnings.some((w) => w.includes('ns2.example.com') && w.includes('private or reserved') && w.includes('10.0.0.1')));
  allTcp(fake.calls);
});

test('more than 8 NS hosts are capped', async () => {
  const hostNames = Array.from({ length: 11 }, (_, i) => `ns${String(i + 1).padStart(2, '0')}.example.com`);
  const hosts = Object.fromEntries(hostNames.map((h, i) => [h, { A: [`45.2.0.${i + 1}`], AAAA: [] }]));
  const fake = makeFake({ zones: { 'example.com': { ns: hostNames } }, hosts, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  assert.equal(out.nameservers.length, 8);
  assert.equal(out.results.length, 8);
  assert.ok(out.warnings.some((w) => w.startsWith('3 nameservers not queried') && w.includes('ns11.example.com')));
  assert.ok(!fake.calls.some((c) => c.server === '45.2.0.9'));
  assert.ok(!fake.calls.some((c) => c.name === 'ns09.example.com'));

  const direct = await resolveNameservers(hostNames, opts(fake));
  assert.deepEqual(direct.skippedHosts, hostNames.slice(8));
});

test('maxAddresses caps across hosts, IPv4 first', async () => {
  const hosts = {
    'ns1.example.com': { A: ['45.1.1.1', '45.1.1.3'], AAAA: ['2606:4700::1'] },
    'ns2.example.com': { A: ['45.1.1.2'], AAAA: ['2606:4700::2'] },
  };
  const fake = makeFake({ zones: ZONES, hosts, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake, { maxAddresses: 3 }));
  assert.deepEqual(out.results.map((r) => r.server).sort(), ['45.1.1.1', '45.1.1.2', '45.1.1.3']);
  assert.ok(out.warnings.some((w) => w.startsWith('2 addresses not queried')));
});

test('first discovery resolver timing out falls back to the second', async () => {
  const discovery = (args) => {
    if (args.server === '8.8.8.8') throw fail('ETIMEOUT');
  };
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect(), discovery });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  assert.equal(out.zone, 'example.com');
  assert.equal(out.results.length, 4);
  assert.ok(fake.calls.some((c) => c.server === '1.1.1.1'));
  assert.ok(fake.calls.some((c) => c.server === '8.8.8.8'));
  allTcp(fake.calls);
});

test('discovery falls back on SERVFAIL too, and fails when every resolver fails', async () => {
  const servfail = (args) => (args.server === '8.8.8.8' ? reply([], { rcode: 2 }) : undefined);
  const fake = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect(), discovery: servfail });
  assert.equal((await findZone('example.com', opts(fake))).zone, 'example.com');

  const dead = makeFake({ zones: ZONES, hosts: HOSTS, direct: goodDirect(), discovery: () => { throw fail('ETIMEOUT'); } });
  await assert.rejects(findZone('example.com', opts(dead)), (e) => e.code === 'EDISCOVERY');
});

test('ENOZONE when no ancestor has NS records, and the root is never queried', async () => {
  const fake = makeFake({ zones: {}, hosts: {}, direct: goodDirect() });
  await assert.rejects(
    checkAuthoritative({ name: 'nothing.invalid', type: 'A' }, opts(fake)),
    (e) => e.code === 'ENOZONE',
  );
  const names = fake.calls.filter((c) => c.server === '8.8.8.8').map((c) => c.name);
  assert.deepEqual(names, ['nothing.invalid', 'invalid']);
  assert.ok(!names.includes('') && !names.includes('.'));
  allTcp(fake.calls);
});

test('a host with no addresses is reported, not queried', async () => {
  const hosts = { 'ns1.example.com': HOSTS['ns1.example.com'] };
  const fake = makeFake({ zones: ZONES, hosts, direct: goodDirect() });
  const out = await checkAuthoritative({ name: 'example.com', type: 'A' }, opts(fake));
  assert.equal(out.results.length, 2);
  assert.ok(out.warnings.includes('Could not find an address for nameserver ns2.example.com'));
});
