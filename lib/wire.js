'use strict';

// Minimal DNS wire-format client (RFC 1035) over UDP and TCP.

const dgram = require('node:dgram');
const net = require('node:net');
const crypto = require('node:crypto');

const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));
const RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
const MAX_JUMPS = 32;

function err(message, code) {
  const e = new Error(message);
  e.code = code;
  return e;
}

const bad = (message) => err(message, 'EBADRESP');

// ---------- building queries ----------

function buildQuery(name, type, id) {
  const qtype = TYPES[type];
  if (qtype === undefined) throw new Error(`Unknown record type: ${type}`);
  let n = String(name);
  if (n.endsWith('.')) n = n.slice(0, -1);
  if (n.length > 253) throw new Error('Name is longer than 253 characters');

  const labels = [];
  if (n !== '') {
    for (const label of n.split('.')) {
      const b = Buffer.from(label, 'latin1');
      if (b.length === 0) throw new Error('Name contains an empty label');
      if (b.length > 63) throw new Error('Label is longer than 63 bytes');
      labels.push(Buffer.from([b.length]), b);
    }
  }

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(qtype, 1);
  tail.writeUInt16BE(1, 3); // class IN
  return Buffer.concat([header, ...labels, tail]);
}

// ---------- parsing ----------

function need(buf, offset, length) {
  if (offset < 0 || length < 0 || offset + length > buf.length) throw bad('Truncated or malformed DNS packet');
}

// Reads a (possibly compressed) name. Returns { name, next } where next is the
// offset after the name in the original position (not following pointers).
function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let next = -1;
  let jumps = 0;
  let total = 0;
  for (;;) {
    need(buf, pos, 1);
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      need(buf, pos, 2);
      if (next === -1) next = pos + 2;
      if (++jumps > MAX_JUMPS) throw bad('Too many compression pointers');
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
    } else if (len & 0xc0) {
      throw bad('Invalid label type');
    } else if (len === 0) {
      if (next === -1) next = pos + 1;
      break;
    } else {
      need(buf, pos + 1, len);
      total += len + 1;
      if (total > 255) throw bad('Name too long');
      labels.push(buf.toString('latin1', pos + 1, pos + 1 + len));
      pos += 1 + len;
    }
  }
  return { name: labels.join('.'), next };
}

// Formats 16 bytes as a compressed IPv6 address (RFC 5952).
function formatIPv6(b) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(b.readUInt16BE(i));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

function parseRdata(buf, type, start, end) {
  const len = end - start;
  switch (type) {
    case 'A':
      if (len !== 4) throw bad('Bad A record length');
      return [...buf.subarray(start, end)].join('.');
    case 'AAAA':
      if (len !== 16) throw bad('Bad AAAA record length');
      return formatIPv6(buf.subarray(start, end));
    case 'NS':
    case 'CNAME':
    case 'PTR': {
      const r = readName(buf, start);
      return r.name;
    }
    case 'MX': {
      if (len < 3) throw bad('Bad MX record length');
      return { priority: buf.readUInt16BE(start), exchange: readName(buf, start + 2).name };
    }
    case 'TXT': {
      const parts = [];
      let p = start;
      while (p < end) {
        const l = buf[p++];
        if (p + l > end) throw bad('Bad TXT record');
        parts.push(buf.toString('utf8', p, p + l));
        p += l;
      }
      return parts.join('');
    }
    case 'SOA': {
      const ns = readName(buf, start);
      const hm = readName(buf, ns.next);
      need(buf, hm.next, 20);
      if (hm.next + 20 > end) throw bad('Bad SOA record');
      const o = hm.next;
      return {
        nsname: ns.name,
        hostmaster: hm.name,
        serial: buf.readUInt32BE(o),
        refresh: buf.readUInt32BE(o + 4),
        retry: buf.readUInt32BE(o + 8),
        expire: buf.readUInt32BE(o + 12),
        minttl: buf.readUInt32BE(o + 16),
      };
    }
    case 'CAA': {
      if (len < 2) throw bad('Bad CAA record');
      const tagLen = buf[start + 1];
      if (2 + tagLen > len) throw bad('Bad CAA record');
      return {
        flags: buf[start],
        tag: buf.toString('latin1', start + 2, start + 2 + tagLen),
        value: buf.toString('utf8', start + 2 + tagLen, end),
      };
    }
    default:
      return buf.toString('hex', start, end);
  }
}

function readRecord(buf, offset) {
  const { name, next } = readName(buf, offset);
  need(buf, next, 10);
  const typeNum = buf.readUInt16BE(next);
  const cls = buf.readUInt16BE(next + 2);
  const ttl = buf.readUInt32BE(next + 4);
  const rdlength = buf.readUInt16BE(next + 8);
  const start = next + 10;
  need(buf, start, rdlength);
  const type = TYPE_NAMES[typeNum] || `TYPE${typeNum}`;
  const data = parseRdata(buf, type, start, start + rdlength);
  return { record: { name, type, class: cls, ttl, data }, next: start + rdlength };
}

function parseResponse(buf) {
  need(buf, 0, 12);
  const id = buf.readUInt16BE(0);
  const f = buf.readUInt16BE(2);
  const flags = {
    qr: !!(f & 0x8000),
    aa: !!(f & 0x0400),
    tc: !!(f & 0x0200),
    rd: !!(f & 0x0100),
    ra: !!(f & 0x0080),
    rcode: f & 0x000f,
  };
  const counts = [buf.readUInt16BE(4), buf.readUInt16BE(6), buf.readUInt16BE(8), buf.readUInt16BE(10)];

  let pos = 12;
  let question = null;
  for (let i = 0; i < counts[0]; i++) {
    const r = readName(buf, pos);
    need(buf, r.next, 4);
    const typeNum = buf.readUInt16BE(r.next);
    if (i === 0) question = { name: r.name, type: TYPE_NAMES[typeNum] || `TYPE${typeNum}` };
    pos = r.next + 4;
  }

  const sections = [];
  for (const count of counts.slice(1)) {
    const list = [];
    for (let i = 0; i < count; i++) {
      const r = readRecord(buf, pos);
      list.push(r.record);
      pos = r.next;
    }
    sections.push(list);
  }

  return {
    id,
    flags,
    rcodeName: RCODES[flags.rcode] || `RCODE${flags.rcode}`,
    question,
    answers: sections[0],
    authority: sections[1],
    additional: sections[2],
  };
}

// ---------- transports ----------

function sameAddress(a, b) {
  const norm = (s) => String(s).split('%')[0].toLowerCase();
  return norm(a) === norm(b);
}

function queryUdp({ server, packet, id, timeout, port }) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIPv6(server) ? 'udp6' : 'udp4');
    let timer;
    const finish = (fn, value) => {
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.on('error', () => {});
      try { socket.close(); } catch { /* already closed */ }
      fn(value);
    };
    timer = setTimeout(() => finish(reject, err(`Timed out after ${timeout}ms`, 'ETIMEOUT')), timeout);
    socket.on('error', (e) => finish(reject, e));
    socket.on('message', (msg, rinfo) => {
      if (rinfo.port !== port || !sameAddress(rinfo.address, server)) return;
      if (msg.length < 12 || msg.readUInt16BE(0) !== id || !(msg[2] & 0x80)) return;
      try {
        finish(resolve, parseResponse(msg));
      } catch (e) {
        finish(reject, e);
      }
    });
    socket.send(packet, port, server, (e) => {
      if (e) finish(reject, e);
    });
  });
}

function queryTcp({ server, packet, id, timeout, port }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: server, port });
    let chunks = [];
    let received = 0;
    let timer;
    const finish = (fn, value) => {
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.on('error', () => {});
      socket.destroy();
      fn(value);
    };
    timer = setTimeout(() => finish(reject, err(`Timed out after ${timeout}ms`, 'ETIMEOUT')), timeout);
    socket.on('error', (e) => finish(reject, e));
    socket.on('connect', () => {
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(packet.length, 0);
      socket.write(Buffer.concat([prefix, packet]));
    });
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      received += chunk.length;
      const all = Buffer.concat(chunks);
      chunks = [all];
      if (received < 2) return;
      const len = all.readUInt16BE(0);
      if (received < 2 + len) return;
      const msg = all.subarray(2, 2 + len);
      try {
        const parsed = parseResponse(msg);
        if (parsed.id !== id) throw bad('Response id mismatch');
        finish(resolve, parsed);
      } catch (e) {
        finish(reject, e);
      }
    });
    socket.on('close', () => finish(reject, bad('Connection closed before a full response arrived')));
  });
}

async function query({ server, name, type, transport = 'udp', timeout = 3000, port = 53 }) {
  if (typeof server !== 'string' || !net.isIP(server)) throw err(`Not an IP literal: ${server}`, 'EBADSERVER');
  if (transport !== 'udp' && transport !== 'tcp') throw new Error(`Unknown transport: ${transport}`);
  const id = crypto.randomInt(0, 65536);
  const packet = buildQuery(name, type, id);
  const started = process.hrtime.bigint();
  const run = transport === 'tcp' ? queryTcp : queryUdp;
  const parsed = await run({ server, packet, id, timeout, port });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  return { ...parsed, ms, transport, server };
}

module.exports = { TYPES, buildQuery, parseResponse, query };
