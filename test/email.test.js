'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { checkEmail } = require('../lib/email');
const { resolveVia } = require('../lib/resolve');

const RESOLVERS = [{ name: 'Alpha', address: '10.0.0.1' }, { name: 'Beta', address: '10.0.0.2' }];

// zone: { 'TYPE name': [records] | 'nxdomain' | Error | 'servfail' }, records are [type, data, name?].
function makeQuery(zone, calls = []) {
  return async (args) => {
    calls.push(args);
    const entry = zone[`${args.type} ${args.name}`];
    if (entry instanceof Error) throw entry;
    if (entry === 'servfail') return { rcodeName: 'SERVFAIL', flags: { rcode: 2 }, answers: [] };
    if (entry === 'nxdomain') return { rcodeName: 'NXDOMAIN', flags: { rcode: 3 }, answers: [] };
    const answers = (entry || []).map(([type, data]) => ({ name: args.name, type, class: 1, ttl: 60, data }));
    return { rcodeName: 'NOERROR', flags: { rcode: 0 }, answers, ms: 1 };
  };
}

const stubSpf = async (domain) => ({
  domain, found: true, record: 'v=spf1 -all', records: ['v=spf1 -all'], lookupCount: 0, voidLookups: 0,
  allQualifier: '-', errors: [], warnings: [], tree: null,
});

const run = (zone, input = { domain: 'example.com' }, extra = {}) => {
  const calls = [];
  return checkEmail(input, { query: makeQuery(zone, calls), resolvers: RESOLVERS, checkSpf: stubSpf, ...extra })
    .then((r) => Object.assign(r, { calls }));
};

const dmarcZone = (txt) => ({ 'TXT _dmarc.example.com': [].concat(txt).map((t) => ['TXT', t]) });

test('DMARC reject policy with reports', async () => {
  const r = await run(dmarcZone('v=DMARC1; p=reject; rua=mailto:a@example.com; ruf=mailto:f@example.com'));
  const d = r.dmarc;
  assert.equal(d.found, true);
  assert.equal(d.name, '_dmarc.example.com');
  assert.equal(d.tags.p, 'reject');
  assert.deepEqual(d.errors, []);
  assert.deepEqual(d.warnings, []);
  assert.ok(d.summary.includes('Policy: reject (mail failing DMARC should be rejected)'));
  assert.ok(d.summary.includes('Subdomains inherit the main policy'));
  assert.ok(d.summary.includes('DKIM alignment: relaxed'));
  assert.ok(d.summary.includes('SPF alignment: relaxed'));
  assert.ok(d.summary.includes('Aggregate reports go to mailto:a@example.com'));
  assert.ok(d.summary.includes('Forensic reports go to mailto:f@example.com'));
});

test('DMARC quarantine with sp, pct and strict alignment', async () => {
  const r = await run(dmarcZone('V=dmarc1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; rua=mailto:a@example.com'));
  const d = r.dmarc;
  assert.ok(d.summary.some((s) => s.startsWith('Policy: quarantine')));
  assert.ok(d.summary.includes('Subdomain policy: reject'));
  assert.ok(d.summary.includes('Applies to 50% of failing mail'));
  assert.ok(d.summary.includes('DKIM alignment: strict'));
  assert.ok(d.summary.includes('SPF alignment: relaxed'));
  assert.ok(d.warnings.some((w) => /50%/.test(w)));
  assert.deepEqual(d.errors, []);
});

test('DMARC p=none warns about monitoring and missing rua', async () => {
  const r = await run(dmarcZone('v=DMARC1; p=none'));
  assert.ok(r.dmarc.warnings.some((w) => /monitoring only, no protection/.test(w)));
  assert.ok(r.dmarc.warnings.some((w) => /rua/.test(w)));
});

test('DMARC multiple records and invalid tags are errors', async () => {
  let r = await run(dmarcZone(['v=DMARC1; p=none; rua=mailto:a@example.com', 'v=DMARC1; p=reject']));
  assert.ok(r.dmarc.errors.some((e) => /Multiple DMARC records/.test(e)));
  assert.equal(r.dmarc.records.length, 2);

  r = await run(dmarcZone('v=DMARC1; p=bogus; pct=150; adkim=x'));
  assert.equal(r.dmarc.errors.length, 3);
  r = await run(dmarcZone('v=DMARC1; rua=mailto:a@example.com'));
  assert.ok(r.dmarc.errors.some((e) => /p= tag is missing/.test(e)));
});

test('DMARC ignores unrelated TXT records and reports a missing record', async () => {
  let r = await run({ 'TXT _dmarc.example.com': [['TXT', 'something else']] });
  assert.equal(r.dmarc.found, false);
  assert.deepEqual(r.dmarc.warnings, ['No DMARC record at _dmarc.example.com']);

  r = await run({ 'TXT _dmarc.mail.example.com': 'nxdomain' }, { domain: 'mail.example.com' });
  assert.equal(r.dmarc.found, false);
  assert.equal(r.dmarc.warnings.length, 2);
  assert.match(r.dmarc.warnings[1], /organisational domain/);
});

// DKIM

const rsaKey = (bits) => crypto.generateKeyPairSync('rsa', { modulusLength: bits })
  .publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const dkimZone = (txt, name = 's1.2024._domainkey.example.com') => ({ [`TXT ${name}`]: [].concat(txt).map((t) => ['TXT', t]) });
const dkim = (txt, zone) => run({ ...dkimZone(txt), ...zone }, { domain: 'example.com', selector: 's1.2024' }).then((r) => r.dkim);

test('DKIM is null without a selector', async () => {
  assert.equal((await run({})).dkim, null);
  assert.equal((await run({}, { domain: 'example.com', selector: '  ' })).dkim, null);
});

test('DKIM RSA 2048 key', async () => {
  const d = await dkim(`v=DKIM1; k=rsa; p=${rsaKey(2048)}`);
  assert.equal(d.found, true);
  assert.equal(d.name, 's1.2024._domainkey.example.com');
  assert.equal(d.keyType, 'rsa');
  assert.equal(d.keyBits, 2048);
  assert.equal(d.revoked, false);
  assert.deepEqual(d.errors, []);
  assert.deepEqual(d.warnings, []);
});

test('DKIM RSA 1024 key warns', async () => {
  const d = await dkim(`v=DKIM1; p=${rsaKey(1024)}`);
  assert.equal(d.keyType, 'rsa');
  assert.equal(d.keyBits, 1024);
  assert.ok(d.warnings.some((w) => /2048/.test(w)));
});

test('DKIM RSA under 1024 bits is too weak', async () => {
  const d = await dkim(`v=DKIM1; p=${rsaKey(512)}`);
  assert.equal(d.keyBits, 512);
  assert.ok(d.warnings.some((w) => /too weak/.test(w)));
});

test('DKIM unparseable key is an error', async () => {
  const d = await dkim('v=DKIM1; p=bm90LWEta2V5');
  assert.ok(d.errors.includes('Public key could not be parsed'));
  assert.equal(d.keyBits, null);
});

test('DKIM Ed25519 raw key', async () => {
  const spki = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
  const raw = spki.subarray(spki.length - 32).toString('base64');
  let d = await dkim(`v=DKIM1; k=ed25519; p=${raw}`);
  assert.equal(d.keyType, 'ed25519');
  assert.equal(d.keyBits, 256);
  assert.deepEqual(d.errors, []);

  d = await dkim(`v=DKIM1; k=ed25519; p=${Buffer.alloc(31).toString('base64')}`);
  assert.ok(d.errors.some((e) => /32 bytes/.test(e)));
});

test('DKIM revoked key and testing flag', async () => {
  let d = await dkim('v=DKIM1; k=rsa; p=');
  assert.equal(d.revoked, true);
  assert.ok(d.warnings.includes('Key revoked (empty p=)'));
  d = await dkim(`v=DKIM1; t=y; p=${rsaKey(2048)}`);
  assert.equal(d.testing, true);
  assert.ok(d.warnings.some((w) => /Testing/.test(w)));
});

test('DKIM key reached via CNAME', async () => {
  const target = 's1.2024.dkim.provider.net';
  const zone = {
    'TXT s1.2024._domainkey.example.com': [['CNAME', target], ['TXT', `v=DKIM1; p=${rsaKey(2048)}`]],
  };
  const d = (await run(zone, { domain: 'example.com', selector: 's1.2024' })).dkim;
  assert.deepEqual(d.cname, [target]);
  assert.equal(d.found, true);
  assert.equal(d.keyBits, 2048);
});

test('DKIM missing key and multiple records', async () => {
  let d = await dkim([], {});
  assert.equal(d.found, false);
  assert.ok(d.warnings[0].startsWith('No DKIM key at s1.2024._domainkey.example.com'));
  d = await dkim([`v=DKIM1; p=${rsaKey(2048)}`, 'v=DKIM1; p=']);
  assert.ok(d.errors.some((e) => /Multiple/.test(e)));
});

// MX

const mxZone = (records, extra = {}) => ({ 'MX example.com': records.map((d) => ['MX', d]), ...extra });
const mxRecords = (r) => r.mx.records.map((m) => `${m.priority} ${m.exchange}`);

test('MX records are sorted and resolved', async () => {
  const r = await run(mxZone([{ priority: 20, exchange: 'b.mail.net' }, { priority: 10, exchange: 'z.mail.net.' }, { priority: 20, exchange: 'a.mail.net' }].map((m) => m), {
    'A a.mail.net': [['A', '192.0.2.1']],
    'A b.mail.net': [['A', '192.0.2.2']],
    'AAAA b.mail.net': [['AAAA', '2001:db8::2']],
    'A z.mail.net': [['A', '192.0.2.3']],
  }));
  assert.deepEqual(mxRecords(r), ['10 z.mail.net', '20 a.mail.net', '20 b.mail.net']);
  assert.deepEqual(r.mx.records[2].addresses, ['192.0.2.2', '2001:db8::2']);
  assert.ok(r.mx.records.every((m) => m.status === 'ok'));
  assert.equal(r.mx.found, true);
  assert.equal(r.mx.nullMx, false);
  assert.deepEqual(r.mx.warnings, []);
});

test('null MX', async () => {
  for (const exchange of ['.', '']) {
    const r = await run(mxZone([{ priority: 0, exchange }]));
    assert.equal(r.mx.nullMx, true);
    assert.equal(r.mx.found, true);
    assert.deepEqual(r.mx.records, []);
    assert.ok(r.mx.summary.includes('This domain does not accept mail (null MX)'));
  }
});

test('MX pointing at a CNAME, an IP, or nothing', async () => {
  const r = await run(mxZone([
    { priority: 10, exchange: 'alias.mail.net' },
    { priority: 20, exchange: '192.0.2.9' },
    { priority: 30, exchange: 'empty.mail.net' },
  ], {
    'A alias.mail.net': [['CNAME', 'real.mail.net'], ['A', '192.0.2.5']],
    'A empty.mail.net': [],
  }));
  const [alias, ip, empty] = r.mx.records;
  assert.equal(alias.status, 'ok');
  assert.deepEqual(alias.cname, ['real.mail.net']);
  assert.equal(ip.status, 'error');
  assert.equal(empty.status, 'noaddress');
  assert.equal(r.mx.warnings.length, 3);
  assert.ok(r.mx.warnings.some((w) => /CNAME/.test(w)));
  assert.ok(r.mx.warnings.some((w) => /IP address/.test(w)));
  assert.ok(r.mx.warnings.some((w) => /no A or AAAA/.test(w)));
});

test('MX lookup failure for a host gives status error', async () => {
  const r = await run(mxZone([{ priority: 10, exchange: 'down.mail.net' }], {
    'A down.mail.net': 'servfail', 'AAAA down.mail.net': 'servfail',
  }));
  assert.equal(r.mx.records[0].status, 'error');
});

test('no MX records', async () => {
  const r = await run({ 'MX example.com': [] });
  assert.equal(r.mx.found, false);
  assert.deepEqual(r.mx.records, []);
  assert.deepEqual(r.mx.warnings, ["No MX records; mail will fall back to the domain's A/AAAA record (implicit MX)"]);
});

test('MX checks at most 10 exchanges', async () => {
  const names = Array.from({ length: 12 }, (_, i) => ({ priority: i, exchange: `m${i}.mail.net` }));
  const r = await run(mxZone(names));
  assert.equal(r.mx.records.length, 10);
  assert.ok(r.mx.warnings.some((w) => /first 10 of 12/.test(w)));
});

// Cross-cutting

test('a failing part does not break the others', async () => {
  const zone = {
    'TXT _dmarc.example.com': new Error('boom'),
    'MX example.com': [['MX', { priority: 10, exchange: 'm.mail.net' }]],
    'A m.mail.net': [['A', '192.0.2.1']],
  };
  const boom = Object.assign(new Error('timed out'), { code: 'ETIMEOUT' });
  zone['TXT _dmarc.example.com'] = boom;
  const r = await run(zone, { domain: 'example.com', selector: 'sel' }, {
    checkSpf: async () => { throw new Error('spf exploded'); },
  });
  assert.equal(r.spf.found, false);
  assert.match(r.spf.errors[0], /spf exploded/);
  assert.equal(r.dmarc.found, false);
  assert.match(r.dmarc.errors[0], /DNS lookup failed/);
  assert.equal(r.mx.found, true);
  assert.equal(r.mx.records[0].status, 'ok');
  assert.equal(r.dkim.found, false);
  assert.equal(r.domain, 'example.com');
});

test('every query goes over TCP, and SPF gets a working lookup', async () => {
  let lookupResult;
  const r = await run({ 'TXT example.com': [['TXT', 'v=spf1 -all']] }, { domain: 'example.com', selector: 's1' }, {
    checkSpf: async (domain, { lookup }) => {
      lookupResult = await lookup('example.com', 'TXT');
      return { domain, found: true, errors: [], warnings: [] };
    },
  });
  assert.deepEqual(lookupResult, { status: 'ok', answers: ['v=spf1 -all'] });
  assert.ok(r.calls.length >= 4);
  assert.ok(r.calls.every((c) => c.transport === 'tcp'));
});

// resolveVia

test('resolveVia falls back on rejection and bad rcodes', async () => {
  const seen = [];
  const query = async ({ server }) => {
    seen.push(server);
    if (server === '10.0.0.1') throw Object.assign(new Error('x'), { code: 'ETIMEOUT' });
    if (server === '10.0.0.2') return { rcodeName: 'SERVFAIL', flags: { rcode: 2 }, answers: [] };
    return { rcodeName: 'NOERROR', flags: { rcode: 0 }, answers: [{ type: 'MX', data: { priority: 5, exchange: 'm.net' } }] };
  };
  const res = await resolveVia({ query, resolvers: [...RESOLVERS, { name: 'Gamma', address: '10.0.0.3' }] }, 'example.com', 'MX');
  assert.deepEqual(seen, ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
  assert.deepEqual(res, { status: 'ok', answers: ['5 m.net'], cname: [], resolver: 'Gamma' });
});

test('resolveVia reports nxdomain, nodata and total failure without rejecting', async () => {
  const mk = (rcode, answers = []) => async () => ({ rcodeName: 'X', flags: { rcode }, answers });
  assert.equal((await resolveVia({ query: mk(3), resolvers: RESOLVERS }, 'a.b', 'A')).status, 'nxdomain');
  assert.equal((await resolveVia({ query: mk(0), resolvers: RESOLVERS }, 'a.b', 'A')).status, 'nodata');

  const timeout = async () => { throw Object.assign(new Error('t'), { code: 'ETIMEOUT' }); };
  const t = await resolveVia({ query: timeout, resolvers: RESOLVERS }, 'a.b', 'A');
  assert.equal(t.status, 'timeout');
  assert.deepEqual(t.answers, []);
  assert.ok(t.error);
  const e = await resolveVia({ query: mk(5), resolvers: RESOLVERS }, 'a.b', 'A');
  assert.equal(e.status, 'error');
  assert.equal((await resolveVia({ query: mk(0), resolvers: [] }, 'a.b', 'A')).status, 'error');
});
