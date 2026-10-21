'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSpf, checkSpf } = require('../lib/spf');

// Fake lookup from { name: { TXT: [...], A: [...], MX: [...] } }.
// Unknown name -> nxdomain; known name without that type -> nodata.
// A value of 'timeout' / 'error' for a type returns that status.
function fake(map) {
  const calls = [];
  const lookup = async (name, type) => {
    calls.push(`${type}:${name}`);
    const rec = map[name];
    if (!rec) return { status: 'nxdomain', answers: [] };
    const v = rec[type];
    if (v === 'timeout' || v === 'error') return { status: v, answers: [] };
    if (!v || v.length === 0) return { status: 'nodata', answers: [] };
    return { status: 'ok', answers: v };
  };
  lookup.calls = calls;
  return lookup;
}

const spf = (body) => `v=spf1 ${body}`;
const includes = (n) => Array.from({ length: n }, (_, i) => `include:i${i}.com`).join(' ');
function leafMap(n) {
  const m = {};
  for (let i = 0; i < n; i++) m[`i${i}.com`] = { TXT: [spf('ip4:192.0.2.1 -all')] };
  return m;
}

test('parseSpf handles every mechanism, qualifier and modifier', () => {
  const r = parseSpf('v=spf1 +a -mx ~ptr ?exists:%{i}.x.com include:_spf.google.com ip4:192.0.2.0/24 ip6:2001:db8::/32 a:foo.com/24 mx/24//64 redirect=r.com exp=e.com custom=1 -all');
  assert.deepEqual(r.errors, []);
  const byRaw = Object.fromEntries(r.terms.map((t) => [t.raw, t]));
  assert.equal(byRaw['+a'].qualifier, '+');
  assert.equal(byRaw['-mx'].qualifier, '-');
  assert.equal(byRaw['~ptr'].qualifier, '~');
  assert.equal(byRaw['?exists:%{i}.x.com'].qualifier, '?');
  assert.equal(byRaw['include:_spf.google.com'].value, '_spf.google.com');
  assert.equal(byRaw['include:_spf.google.com'].qualifier, '+');
  assert.equal(byRaw['ip4:192.0.2.0/24'].value, '192.0.2.0/24');
  assert.equal(byRaw['ip6:2001:db8::/32'].name, 'ip6');
  assert.equal(byRaw['a:foo.com/24'].value, 'foo.com');
  assert.equal(byRaw['mx/24//64'].value, null);
  assert.equal(byRaw['-all'].name, 'all');
  assert.equal(byRaw['redirect=r.com'].kind, 'modifier');
  assert.equal(byRaw['redirect=r.com'].value, 'r.com');
  assert.equal(byRaw['custom=1'].kind, 'modifier');
  assert.equal(byRaw['-mx'].kind, 'mechanism');
});

test('parseSpf reports bad ip4/ip6, unknown mechanisms and missing values', () => {
  const cases = [
    ['ip4:1.2.3', /ip4/],
    ['ip4:256.1.1.1', /ip4/],
    ['ip4:1.2.3.4/33', /ip4/],
    ['ip4', /ip4/],
    ['ip6:::g', /ip6/],
    ['ip6:2001:db8::/129', /ip6/],
    ['ip6:1.2.3.4', /ip6/],
    ['foo:bar', /Unknown mechanism/],
    ['include', /include/],
    ['include:', /include/],
    ['exists', /exists/],
    ['redirect=', /redirect/],
    ['exp=', /exp/],
  ];
  for (const [body, re] of cases) {
    const r = parseSpf(spf(body));
    assert.equal(r.errors.length, 1, body);
    assert.match(r.errors[0], re, body);
  }
  assert.deepEqual(parseSpf(spf('ip4:0.0.0.0/0 ip6:::/0 ip6:::1')).errors, []);
});

test('parseSpf reports duplicate redirect and exp', () => {
  const r = parseSpf(spf('redirect=a.com redirect=b.com exp=a.com exp=b.com'));
  assert.deepEqual(r.errors, ['Duplicate redirect modifier', 'Duplicate exp modifier']);
});

test('parseSpf prefix is case-insensitive and must be a whole word', () => {
  assert.deepEqual(parseSpf('V=SPF1 -all').errors, []);
  assert.deepEqual(parseSpf('v=spf1').terms, []);
  assert.equal(parseSpf('v=spf10 -all').errors.length, 1);
  assert.equal(parseSpf('hello').errors.length, 1);
});

test('no SPF record is not an error', async () => {
  const r = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: ['hello world'] } }) });
  assert.equal(r.found, false);
  assert.equal(r.record, null);
  assert.deepEqual(r.errors, []);
  assert.ok(r.warnings.includes('No SPF record found'));
  const r2 = await checkSpf('gone.com', { lookup: fake({}) });
  assert.equal(r2.found, false);
});

test('v=spf10 is not an SPF record; V=SPF1 is', async () => {
  const bad = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: ['v=spf10 -all'] } }) });
  assert.equal(bad.found, false);
  const good = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: ['V=SPF1 -all'] } }) });
  assert.equal(good.found, true);
  assert.equal(good.allQualifier, '-');
});

test('multiple SPF records is an error', async () => {
  const r = await checkSpf('a.com', {
    lookup: fake({ 'a.com': { TXT: [spf('-all'), spf('~all'), 'google-site-verification=x'] } }),
  });
  assert.equal(r.found, true);
  assert.equal(r.records.length, 2);
  assert.ok(r.errors.includes('Multiple SPF records found (2); receivers will return permerror'));
});

test('nested includes three levels deep are counted', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('include:b.com -all')] },
    'b.com': { TXT: [spf('include:c.com a ~all')], A: ['192.0.2.1'] },
    'c.com': { TXT: [spf('include:d.com mx -all')], MX: ['10 mx.c.com'] },
    'd.com': { TXT: [spf('ip4:192.0.2.1 -all')] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.lookupCount, 5);
  assert.equal(r.voidLookups, 0);
  assert.deepEqual(r.errors, []);
  assert.equal(r.allQualifier, '-');
  const b = r.tree.terms[0].include;
  const c = b.terms[0].include;
  const d = c.terms[0].include;
  assert.equal(b.domain, 'b.com');
  assert.equal(c.domain, 'c.com');
  assert.equal(d.domain, 'd.com');
  assert.equal(r.tree.terms[0].lookups, 1);
  assert.equal(d.terms[0].lookups, 0);
});

test('exactly 10 lookups is fine, 11 is an error', async () => {
  const ten = await checkSpf('a.com', {
    lookup: fake({ 'a.com': { TXT: [spf(`${includes(10)} -all`)] }, ...leafMap(10) }),
  });
  assert.equal(ten.lookupCount, 10);
  assert.deepEqual(ten.errors, []);
  assert.ok(ten.warnings.some((w) => /close to the 10-lookup limit/.test(w)));

  const eleven = await checkSpf('a.com', {
    lookup: fake({ 'a.com': { TXT: [spf(`${includes(11)} -all`)] }, ...leafMap(11) }),
  });
  assert.equal(eleven.lookupCount, 11);
  assert.ok(eleven.errors.includes('Too many DNS lookups: 11 (limit 10)'));
});

test('all, ip4 and ip6 do not count; ptr, exists, a and mx do', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('ip4:192.0.2.1 ip6:2001:db8::1 a mx ptr exists:x.com -all')], A: ['192.0.2.1'], MX: ['10 m.a.com'] },
    'x.com': { A: ['127.0.0.2'] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.lookupCount, 4);
});

test('circular include is detected without recursing', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('include:b.com -all')] },
    'b.com': { TXT: [spf('include:a.com -all')] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.ok(r.errors.includes('Circular include: a.com → b.com → a.com'));
  assert.equal(lookup.calls.filter((c) => c === 'TXT:a.com').length, 1);
  assert.equal(r.lookupCount, 2);
});

test('self-include is circular', async () => {
  const r = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: [spf('include:a.com -all')] } }) });
  assert.ok(r.errors.includes('Circular include: a.com → a.com'));
});

test('include target without SPF is an error on the term', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('include:b.com -all')] },
    'b.com': { TXT: ['just text'] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.ok(r.errors.includes('include:b.com has no SPF record'));
  assert.equal(r.tree.terms[0].error, 'include:b.com has no SPF record');
  assert.equal(r.voidLookups, 0);
});

test('void lookups: 2 is fine, 3 is an error', async () => {
  const two = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: [spf('a:x1.com a:x2.com -all')] } }) });
  assert.equal(two.voidLookups, 2);
  assert.deepEqual(two.errors, []);

  const three = await checkSpf('a.com', {
    lookup: fake({ 'a.com': { TXT: [spf('a:x1.com mx:x2.com exists:x3.com -all')] } }),
  });
  assert.equal(three.voidLookups, 3);
  assert.ok(three.errors.includes('Too many void lookups: 3 (limit 2)'));
});

test('a is not void when AAAA answers after an empty A; ptr is never void', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('a:v6.com ptr -all')] },
    'v6.com': { AAAA: ['2001:db8::1'] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.voidLookups, 0);
  assert.deepEqual(lookup.calls, ['TXT:a.com', 'A:v6.com', 'AAAA:v6.com']);
});

test('timeouts and errors warn but are not void', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('include:slow.com a:bad.com -all')] },
    'slow.com': { TXT: 'timeout' },
    'bad.com': { A: 'error' },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.voidLookups, 0);
  assert.ok(r.warnings.some((w) => /slow\.com/.test(w) && /timed out/.test(w)));
  assert.ok(r.warnings.some((w) => /bad\.com/.test(w)));
  assert.deepEqual(r.errors, []);
});

test('a lookup that throws never rejects', async () => {
  const lookup = async (name) => {
    if (name === 'a.com') return { status: 'ok', answers: [spf('include:b.com -all')] };
    throw new Error('boom');
  };
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.found, true);
  assert.ok(r.warnings.some((w) => /b\.com/.test(w)));
});

test('redirect is followed when there is no all', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('redirect=b.com')] },
    'b.com': { TXT: [spf('ip4:192.0.2.1 -all')] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.lookupCount, 1);
  assert.equal(r.allQualifier, '-');
  assert.equal(r.tree.terms[0].include.domain, 'b.com');
  assert.deepEqual(r.errors, []);
  assert.ok(!r.warnings.some((w) => /defaults to neutral/.test(w)));
});

test('redirect to a domain without SPF is an error', async () => {
  const lookup = fake({ 'a.com': { TXT: [spf('redirect=b.com')] }, 'b.com': { TXT: ['x'] } });
  const r = await checkSpf('a.com', { lookup });
  assert.ok(r.errors.includes('redirect=b.com has no SPF record'));
});

test('redirect is ignored when all is present', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('-all redirect=b.com')] },
    'b.com': { TXT: [spf('+all')] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.lookupCount, 0);
  assert.equal(r.allQualifier, '-');
  assert.equal(r.tree.terms[1].include, undefined);
  assert.ok(!lookup.calls.includes('TXT:b.com'));
});

test('circular redirect is detected', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('redirect=b.com')] },
    'b.com': { TXT: [spf('redirect=a.com')] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.ok(r.errors.includes('Circular include: a.com → b.com → a.com'));
});

test('warnings for +all, ?all, ptr, missing all; none for ~all', async () => {
  const run = (body) => checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: [spf(body)] } }) });
  const plus = await run('+all');
  assert.equal(plus.allQualifier, '+');
  assert.ok(plus.warnings.some((w) => /allows any server to send as this domain/.test(w)));
  const bare = await run('all');
  assert.equal(bare.allQualifier, '+');
  const q = await run('?all');
  assert.ok(q.warnings.some((w) => /neutral/.test(w) && /\?all/.test(w)));
  const ptr = await run('ptr -all');
  assert.ok(ptr.warnings.some((w) => /ptr/.test(w) && /deprecated/.test(w)));
  const none = await run('ip4:192.0.2.1');
  assert.equal(none.allQualifier, null);
  assert.ok(none.warnings.some((w) => /defaults to neutral/.test(w)));
  const soft = await run('ip4:192.0.2.1 ~all');
  assert.equal(soft.allQualifier, '~');
  assert.deepEqual(soft.warnings, []);
  assert.deepEqual(soft.errors, []);
});

test('macros are counted but not followed', async () => {
  const lookup = fake({ 'a.com': { TXT: [spf('exists:%{i}._spf.x.com include:%{d}.y.com a:%{d} -all')] } });
  const r = await checkSpf('a.com', { lookup });
  assert.equal(r.lookupCount, 3);
  assert.deepEqual(lookup.calls, ['TXT:a.com']);
  assert.ok(r.warnings.some((w) => /macro/i.test(w) && /sender/.test(w)));
  assert.equal(r.voidLookups, 0);
});

test('hardCap stops following a huge tree', async () => {
  const calls = [];
  // Binary tree of includes, 2^11 domains deep.
  const lookup = async (name, type) => {
    calls.push(`${type}:${name}`);
    if (type !== 'TXT') return { status: 'nodata', answers: [] };
    const depth = name.split('.').length;
    const body = depth < 11 ? `include:l.${name} include:r.${name} -all` : 'ip4:192.0.2.1 -all';
    return { status: 'ok', answers: [spf(body)] };
  };
  const r = await checkSpf('a.com', { lookup, hardCap: 40 });
  assert.ok(calls.length <= 41, `made ${calls.length} queries`);
  assert.ok(r.lookupCount > 40);
  assert.ok(r.errors.some((e) => /Too many DNS lookups/.test(e)));
  assert.ok(r.warnings.some((w) => /Stopped following/.test(w)));
});

test('a and mx without a value use the current domain', async () => {
  const lookup = fake({
    'a.com': { TXT: [spf('include:b.com a mx -all')], A: ['192.0.2.1'], MX: ['10 mx.a.com'] },
    'b.com': { TXT: [spf('a ~all')], A: ['192.0.2.2'] },
  });
  const r = await checkSpf('a.com', { lookup });
  assert.deepEqual(lookup.calls, ['TXT:a.com', 'TXT:b.com', 'A:b.com', 'A:a.com', 'MX:a.com']);
  assert.equal(r.lookupCount, 4);
  assert.equal(r.voidLookups, 0);
});

test('mx with more than 10 hosts is an error', async () => {
  const hosts = Array.from({ length: 11 }, (_, i) => `10 mx${i}.a.com`);
  const r = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: [spf('mx -all')], MX: hosts } }) });
  assert.ok(r.errors.some((e) => /11 hosts/.test(e)));
});

test('syntax errors in the record are reported as errors', async () => {
  const r = await checkSpf('a.com', { lookup: fake({ 'a.com': { TXT: [spf('ip4:999.1.1.1 foo -all')] } }) });
  assert.equal(r.errors.length, 2);
  assert.equal(r.tree.terms[0].error !== undefined, true);
});

test('mechanisms after "all" are ignored and not counted', async () => {
  const records = {
    'example.com': ['v=spf1 include:a.example -all include:b.example mx'],
    'a.example': ['v=spf1 ip4:192.0.2.1 -all'],
    'b.example': ['v=spf1 ip4:192.0.2.2 -all'],
  };
  const calls = [];
  const lookup = async (name, type) => {
    calls.push(`${type} ${name}`);
    if (type === 'TXT' && records[name]) return { status: 'ok', answers: records[name] };
    return { status: 'nodata', answers: [] };
  };
  const r = await checkSpf('example.com', { lookup });
  assert.equal(r.lookupCount, 1);
  assert.deepEqual(r.errors, []);
  assert.ok(!calls.includes('TXT b.example'));
  const ignored = r.tree.terms.filter((t) => t.ignored).map((t) => t.raw);
  assert.deepEqual(ignored, ['include:b.example', 'mx']);
  assert.ok(r.warnings.some((w) => /after "all" will never be evaluated/.test(w)));
});
