'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const net = require('node:net');
const { TYPES, buildQuery, parseResponse, query } = require('../lib/wire');

// ---------- helpers to hand-build packets ----------

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const name = (n) => Buffer.concat([
  ...n.split('.').filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])),
  Buffer.from([0]),
]);
const ptr = (offset) => u16(0xc000 | offset);

// Builds a record. `nm` is a Buffer (name or pointer), `rdata` a Buffer.
const rr = (nm, type, ttl, rdata) => Buffer.concat([nm, u16(type), u16(1), u32(ttl), u16(rdata.length), rdata]);

function packet({ id = 0x1234, flags = 0x8180, qname = 'example.com', qtype = 1, answers = [], authority = [] }) {
  const header = Buffer.concat([u16(id), u16(flags), u16(1), u16(answers.length), u16(authority.length), u16(0)]);
  return Buffer.concat([header, name(qname), u16(qtype), u16(1), ...answers, ...authority]);
}

// ---------- buildQuery ----------

test('buildQuery produces the expected bytes', () => {
  const expected = Buffer.from([
    0xab, 0xcd, // id
    0x01, 0x00, // flags: RD
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0,
    0x00, 0x01, // A
    0x00, 0x01, // IN
  ]);
  assert.deepEqual(buildQuery('example.com', 'A', 0xabcd), expected);
  assert.deepEqual(buildQuery('example.com.', 'A', 0xabcd), expected);
});

test('buildQuery uses the right type code', () => {
  const q = buildQuery('example.com', 'CAA', 1);
  assert.equal(q.readUInt16BE(q.length - 4), TYPES.CAA);
});

test('buildQuery rejects bad names', () => {
  assert.throws(() => buildQuery('a'.repeat(64) + '.com', 'A', 1));
  assert.throws(() => buildQuery('a..com', 'A', 1));
  assert.throws(() => buildQuery(Array(60).fill('abcd').join('.'), 'A', 1));
  assert.throws(() => buildQuery('example.com', 'BOGUS', 1));
});

// ---------- parseResponse ----------

test('parses an A record', () => {
  const r = parseResponse(packet({
    answers: [rr(ptr(12), 1, 300, Buffer.from([93, 184, 216, 34]))],
  }));
  assert.equal(r.id, 0x1234);
  assert.equal(r.rcodeName, 'NOERROR');
  assert.deepEqual(r.flags, { qr: true, aa: false, tc: false, rd: true, ra: true, rcode: 0 });
  assert.deepEqual(r.question, { name: 'example.com', type: 'A' });
  assert.deepEqual(r.answers, [{ name: 'example.com', type: 'A', class: 1, ttl: 300, data: '93.184.216.34' }]);
});

test('parses AAAA records with standard compression', () => {
  const addr = (...g) => Buffer.concat(g.map(u16));
  const r = parseResponse(packet({
    qtype: 28,
    answers: [
      rr(ptr(12), 28, 60, addr(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
      rr(ptr(12), 28, 60, addr(0, 0, 0, 0, 0, 0, 0, 1)),
      rr(ptr(12), 28, 60, addr(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)),
      rr(ptr(12), 28, 60, addr(1, 2, 3, 4, 5, 6, 7, 8)),
    ],
  }));
  assert.deepEqual(r.answers.map((a) => a.data), ['2606:4700::1111', '::1', '2001:db8:0:1::1', '1:2:3:4:5:6:7:8']);
});

test('parses MX with a compression pointer in the exchange', () => {
  const rdata = Buffer.concat([u16(10), Buffer.from([4]), Buffer.from('mail'), ptr(12)]);
  const r = parseResponse(packet({ qtype: 15, answers: [rr(ptr(12), 15, 3600, rdata)] }));
  assert.deepEqual(r.answers[0].data, { priority: 10, exchange: 'mail.example.com' });
});

test('joins multi-chunk TXT strings', () => {
  const rdata = Buffer.concat([Buffer.from([6]), Buffer.from('v=spf1'), Buffer.from([8]), Buffer.from(' -all ok')]);
  const r = parseResponse(packet({ qtype: 16, answers: [rr(ptr(12), 16, 120, rdata)] }));
  assert.equal(r.answers[0].data, 'v=spf1 -all ok');
});

test('parses SOA', () => {
  const rdata = Buffer.concat([
    name('ns1.example.com'), name('hostmaster.example.com'),
    u32(2024010101), u32(7200), u32(900), u32(1209600), u32(300),
  ]);
  const r = parseResponse(packet({ qtype: 6, answers: [rr(ptr(12), 6, 60, rdata)] }));
  assert.deepEqual(r.answers[0].data, {
    nsname: 'ns1.example.com',
    hostmaster: 'hostmaster.example.com',
    serial: 2024010101,
    refresh: 7200,
    retry: 900,
    expire: 1209600,
    minttl: 300,
  });
});

test('parses CAA', () => {
  const rdata = Buffer.concat([Buffer.from([0, 5]), Buffer.from('issue'), Buffer.from('letsencrypt.org')]);
  const r = parseResponse(packet({ qtype: 257, answers: [rr(ptr(12), 257, 60, rdata)] }));
  assert.deepEqual(r.answers[0].data, { flags: 0, tag: 'issue', value: 'letsencrypt.org' });
});

test('follows CNAME compression pointers and reads the authority section', () => {
  const cname = rr(ptr(12), 5, 30, Buffer.concat([Buffer.from([3]), Buffer.from('www'), ptr(12)]));
  const ns = rr(ptr(12), 2, 30, Buffer.concat([Buffer.from([3]), Buffer.from('ns1'), ptr(12)]));
  const r = parseResponse(packet({ qtype: 5, answers: [cname], authority: [ns] }));
  assert.equal(r.answers[0].type, 'CNAME');
  assert.equal(r.answers[0].data, 'www.example.com');
  assert.equal(r.authority[0].data, 'ns1.example.com');
  assert.deepEqual(r.additional, []);
});

test('unknown types become hex strings and TYPE<n> names', () => {
  const r = parseResponse(packet({ answers: [rr(ptr(12), 99, 5, Buffer.from([0xde, 0xad]))] }));
  assert.equal(r.answers[0].type, 'TYPE99');
  assert.equal(r.answers[0].data, 'dead');
});

test('reports NXDOMAIN and the AA flag', () => {
  const r = parseResponse(packet({ flags: 0x8583 }));
  assert.equal(r.flags.rcode, 3);
  assert.equal(r.rcodeName, 'NXDOMAIN');
  assert.equal(r.flags.aa, true);
  assert.deepEqual(r.answers, []);
});

test('a compression pointer loop throws EBADRESP', () => {
  // Answer name points at itself (offset 12 + question length).
  const q = packet({});
  const selfOffset = q.length;
  const loop = Buffer.concat([ptr(selfOffset), u16(1), u16(1), u32(0), u16(4), Buffer.from([1, 2, 3, 4])]);
  const buf = Buffer.concat([q, loop]);
  buf.writeUInt16BE(1, 6); // ANCOUNT
  assert.throws(() => parseResponse(buf), { code: 'EBADRESP' });
});

test('truncated packets throw EBADRESP at every length', () => {
  const full = packet({ answers: [rr(ptr(12), 1, 300, Buffer.from([1, 2, 3, 4]))] });
  for (let i = 0; i < full.length; i++) {
    assert.throws(() => parseResponse(full.subarray(0, i)), { code: 'EBADRESP' }, `length ${i}`);
  }
});

// ---------- query() against local fake servers ----------

const answerFor = (id) => packet({
  id,
  answers: [rr(ptr(12), 1, 42, Buffer.from([192, 0, 2, 1]))],
});

function startUdp(handler) {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.on('message', (msg, rinfo) => handler(s, msg, rinfo));
    s.bind(0, '127.0.0.1', () => resolve(s));
  });
}

function startTcp(handler) {
  return new Promise((resolve) => {
    const s = net.createServer(handler);
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

test('query over UDP', async () => {
  const srv = await startUdp((s, msg, rinfo) => s.send(answerFor(msg.readUInt16BE(0)), rinfo.port, rinfo.address));
  try {
    const r = await query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A' });
    assert.equal(r.transport, 'udp');
    assert.equal(r.server, '127.0.0.1');
    assert.equal(r.answers[0].data, '192.0.2.1');
    assert.equal(r.answers[0].ttl, 42);
    assert.equal(typeof r.ms, 'number');
  } finally {
    srv.close();
  }
});

test('query over UDP ignores responses with the wrong id', async () => {
  const srv = await startUdp((s, msg, rinfo) => {
    const id = msg.readUInt16BE(0);
    s.send(answerFor((id + 1) & 0xffff), rinfo.port, rinfo.address); // spoofed
    s.send(answerFor(id), rinfo.port, rinfo.address);
  });
  try {
    const r = await query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A' });
    assert.equal(r.answers[0].data, '192.0.2.1');
  } finally {
    srv.close();
  }
});

test('query over UDP returns the TC flag without retrying', async () => {
  const srv = await startUdp((s, msg, rinfo) => {
    const id = msg.readUInt16BE(0);
    s.send(packet({ id, flags: 0x8380 }), rinfo.port, rinfo.address);
  });
  try {
    const r = await query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A' });
    assert.equal(r.flags.tc, true);
  } finally {
    srv.close();
  }
});

function tcpServer(chunking) {
  return startTcp((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 2 || buf.length < 2 + buf.readUInt16BE(0)) return;
      const reply = answerFor(buf.readUInt16BE(2));
      const framed = Buffer.concat([u16(reply.length), reply]);
      const parts = chunking(framed);
      parts.forEach((p, i) => setTimeout(() => sock.write(p), i * 20));
    });
    sock.on('error', () => {});
  });
}

test('query over TCP', async () => {
  const srv = await tcpServer((b) => [b]);
  try {
    const r = await query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A', transport: 'tcp' });
    assert.equal(r.transport, 'tcp');
    assert.equal(r.answers[0].data, '192.0.2.1');
  } finally {
    srv.close();
  }
});

test('query over TCP with the response split across chunks', async () => {
  // First chunk holds the length prefix and one byte; the rest follows later.
  const srv = await tcpServer((b) => [b.subarray(0, 3), b.subarray(3)]);
  try {
    const r = await query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A', transport: 'tcp' });
    assert.equal(r.answers[0].data, '192.0.2.1');
  } finally {
    srv.close();
  }
});

test('query times out against a silent UDP server', async () => {
  const srv = await startUdp(() => {});
  try {
    await assert.rejects(
      query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A', timeout: 100 }),
      { code: 'ETIMEOUT' },
    );
  } finally {
    srv.close();
  }
});

test('query times out against a silent TCP server', async () => {
  const sockets = [];
  const srv = await startTcp((s) => { sockets.push(s); s.on('error', () => {}); });
  try {
    await assert.rejects(
      query({ server: '127.0.0.1', port: srv.address().port, name: 'example.com', type: 'A', transport: 'tcp', timeout: 100 }),
      { code: 'ETIMEOUT' },
    );
  } finally {
    sockets.forEach((s) => s.destroy());
    srv.close();
  }
});

test('query surfaces socket errors with their code', async () => {
  const srv = await startTcp(() => {});
  const { port } = srv.address();
  await new Promise((resolve) => srv.close(resolve));
  await assert.rejects(
    query({ server: '127.0.0.1', port, name: 'example.com', type: 'A', transport: 'tcp' }),
    { code: 'ECONNREFUSED' },
  );
});

test('query rejects a hostname as the server', async () => {
  await assert.rejects(query({ server: 'dns.google', name: 'example.com', type: 'A' }), { code: 'EBADSERVER' });
});
