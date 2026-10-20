'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TYPES, validateQuery } = require('../lib/validate');

const rejects = (input, type = 'A', re) =>
  assert.throws(() => validateQuery(input, type), (e) => e.code === 'EINVALID' && (!re || re.test(e.message)));

test('exports TYPES', () => {
  assert.deepEqual(TYPES, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'PTR']);
});

test('valid names are normalised', () => {
  assert.deepEqual(validateQuery('example.com', 'A'), { name: 'example.com', type: 'A' });
  assert.equal(validateQuery('Example.COM', 'A').name, 'example.com');
  assert.equal(validateQuery('example.com.', 'A').name, 'example.com');
  assert.equal(validateQuery('  example.com \n', 'A').name, 'example.com');
  assert.equal(validateQuery('com', 'NS').name, 'com');
});

test('underscores are allowed', () => {
  assert.equal(validateQuery('_dmarc.example.com', 'TXT').name, '_dmarc.example.com');
  assert.equal(validateQuery('s1._domainkey.example.com', 'TXT').name, 's1._domainkey.example.com');
});

test('IDNs convert to punycode', () => {
  assert.equal(validateQuery('münchen.de', 'A').name, 'xn--mnchen-3ya.de');
});

test('type handling', () => {
  assert.equal(validateQuery('example.com', 'mx').type, 'MX');
  rejects('example.com', 'ANY', /Unsupported record type/);
  assert.throws(() => validateQuery('example.com', undefined), (e) => e.code === 'EINVALID');
  rejects('example.com', 5, /Unsupported record type/);
});

test('hostile inputs are rejected', () => {
  for (const bad of ['', '   ', 'exa mple.com', 'example.com\nfoo', 'example.com\n.evil', 'a\0b.com', 'a\tb.com', '.', '..', '.example.com', 'a..b.com', '-a.com', 'a-.com', 'a.-b.com', 'ex%41mple.com', 'ex!ample.com']) {
    rejects(bad);
  }
  rejects(null);
  rejects(123);
  rejects('a'.repeat(1025));
});

test('label and total length limits', () => {
  assert.equal(validateQuery(`${'a'.repeat(63)}.com`, 'A').name.length, 67);
  rejects(`${'a'.repeat(64)}.com`);
  const ok = [`${'a'.repeat(63)}`, `${'b'.repeat(63)}`, `${'c'.repeat(63)}`, 'd'.repeat(61)].join('.');
  assert.equal(ok.length, 253);
  assert.equal(validateQuery(ok, 'A').name, ok);
  rejects(`${ok}x`.replace(/x$/, 'ee'));
  const long = [`${'a'.repeat(63)}`, `${'b'.repeat(63)}`, `${'c'.repeat(63)}`, 'd'.repeat(62)].join('.');
  assert.equal(long.length, 254);
  rejects(long);
});

test('URLs and email addresses are rejected with advice', () => {
  rejects('http://example.com', 'A', /just the domain/);
  rejects('example.com/path', 'A', /just the domain/);
  rejects('user@example.com', 'A', /just the domain/);
  rejects('example.com?x=1', 'A', /just the domain/);
  rejects('example.com:8080', 'A', /just the domain/);
});

test('IP literals only for PTR', () => {
  rejects('1.2.3.4', 'A', /only accepted for PTR/);
  rejects('2001:db8::1', 'AAAA', /only accepted for PTR/);
  rejects('[::1]', 'A', /only accepted for PTR/);
  rejects('1.2.3', 'A', /looks like an IP/);
  rejects('0x7f.1', 'A', /looks like an IP/);
  rejects('01.2.3.4', 'A', /looks like an IP/);
});

test('PTR converts IPs to reverse names', () => {
  assert.deepEqual(validateQuery('1.2.3.4', 'PTR'), { name: '4.3.2.1.in-addr.arpa', type: 'PTR' });
  assert.equal(
    validateQuery('2001:db8::1', 'ptr').name,
    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
  );
  assert.equal(validateQuery('::1', 'PTR').name, `1.${'0.'.repeat(31)}ip6.arpa`);
  assert.equal(
    validateQuery('::ffff:1.2.3.4', 'PTR').name,
    '4.0.3.0.2.0.1.0.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa',
  );
  assert.equal(
    validateQuery('1:2:3:4:5:6:7:8', 'PTR').name,
    '8.0.0.0.7.0.0.0.6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa',
  );
});

test('PTR still accepts a plain reverse name', () => {
  assert.equal(validateQuery('4.3.2.1.in-addr.arpa', 'PTR').name, '4.3.2.1.in-addr.arpa');
});
