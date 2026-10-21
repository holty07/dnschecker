'use strict';

// Resolver lookups over TCP using an injected wire-format `query` function.

function formatAnswer(type, data) {
  switch (type) {
    case 'A':
    case 'AAAA':
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'TXT':
      return String(data);
    case 'MX':
      return `${data.priority} ${data.exchange}`;
    case 'SOA':
      return [data.nsname, data.hostmaster, data.serial, data.refresh, data.retry, data.expire, data.minttl].join(' ');
    case 'CAA':
      return `${data.flags} ${data.tag} "${data.value}"`;
    default:
      return String(data);
  }
}

const UNREACHABLE_CODES = ['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'ECONNREFUSED', 'EAFNOSUPPORT'];

const round1 = (n) => Math.round(n * 10) / 10;

async function lookupOne({ resolver, name, type, query, timeout = 3000 }) {
  const base = { resolver: resolver.name, server: resolver.address };
  const started = process.hrtime.bigint();
  let res;
  try {
    res = await query({ server: resolver.address, name, type, transport: 'tcp', timeout });
  } catch (e) {
    const ms = round1(Number(process.hrtime.bigint() - started) / 1e6);
    const failed = { ...base, status: 'error', answers: [], ttl: null, ms, cname: [], authoritative: false };
    if (e && e.code === 'ETIMEOUT') failed.status = 'timeout';
    else if (e && UNREACHABLE_CODES.includes(e.code)) failed.status = 'unreachable';
    failed.error = (e && (e.code || e.message)) || 'error';
    if (failed.status === 'timeout') failed.error = (e && e.message) || 'ETIMEOUT';
    return failed;
  }

  try {
    const records = Array.isArray(res.answers) ? res.answers : [];
    const matching = records.filter((r) => r.type === type);
    const answers = matching.map((r) => formatAnswer(type, r.data)).sort();
    const ttl = matching.length ? Math.min(...matching.map((r) => r.ttl)) : null;
    const cname = type === 'CNAME' ? [] : records.filter((r) => r.type === 'CNAME').map((r) => r.data);
    const ms = round1(typeof res.ms === 'number' ? res.ms : Number(process.hrtime.bigint() - started) / 1e6);

    const out = { ...base, status: 'error', answers, ttl, ms, cname, authoritative: Boolean(res.flags && res.flags.aa) };
    const rcode = res.rcodeName || (res.flags && res.flags.rcode);
    if (res.flags && res.flags.rcode === 0) out.status = answers.length ? 'ok' : 'nodata';
    else if (res.flags && res.flags.rcode === 3) out.status = 'nxdomain';
    else out.error = String(rcode);
    if (res.flags && res.flags.tc) out.truncated = true;
    return out;
  } catch (e) {
    const ms = round1(Number(process.hrtime.bigint() - started) / 1e6);
    return { ...base, status: 'error', answers: [], ttl: null, ms, cname: [], authoritative: false, error: (e && (e.code || e.message)) || 'error' };
  }
}

function compareResults(results) {
  const participating = results.filter((r) => ['ok', 'nodata', 'nxdomain'].includes(r.status) && r.lame !== true);
  const keyOf = (r) => `${r.status}|${r.answers.join('\n')}`;
  const counts = new Map();
  for (const r of participating) counts.set(keyOf(r), (counts.get(keyOf(r)) || 0) + 1);

  let majorityKey = null;
  for (const [k, n] of counts) if (n * 2 > participating.length) majorityKey = k;

  for (const r of results) {
    if (!participating.includes(r)) r.differs = false;
    else r.differs = majorityKey === null ? null : keyOf(r) !== majorityKey;
  }

  if (majorityKey === null) {
    return { majority: null, agreeing: 0, participating: participating.length, total: results.length, allAgree: false };
  }
  const first = participating.find((r) => keyOf(r) === majorityKey);
  const agreeing = counts.get(majorityKey);
  return {
    majority: { status: first.status, answers: first.answers },
    agreeing,
    participating: participating.length,
    total: results.length,
    allAgree: agreeing === participating.length && participating.length > 0,
  };
}

async function lookupAll({ resolvers, name, type, query, timeout }) {
  const results = await Promise.all(resolvers.map((resolver) => lookupOne({ resolver, name, type, query, timeout })));
  return { name, type, results, consensus: compareResults(results) };
}

// Ask the public resolvers in order, over TCP. Falls back to the next resolver on a
// rejection or an rcode other than NOERROR/NXDOMAIN. Never rejects.
async function resolveVia({ query, resolvers, timeout = 3000 }, name, type) {
  let last = null;
  let lastTimedOut = false;
  for (const r of resolvers) {
    try {
      const res = await query({ server: r.address, name, type, transport: 'tcp', timeout });
      const rcode = res && res.flags ? res.flags.rcode : undefined;
      if (rcode === 0 || rcode === 3) {
        const records = Array.isArray(res.answers) ? res.answers : [];
        const answers = records.filter((x) => x.type === type).map((x) => formatAnswer(type, x.data));
        const cname = type === 'CNAME' ? [] : records.filter((x) => x.type === 'CNAME').map((x) => String(x.data));
        const status = rcode === 3 ? 'nxdomain' : answers.length ? 'ok' : 'nodata';
        return { status, answers, cname, resolver: r.name };
      }
      lastTimedOut = false;
      last = `${r.name}: ${(res && res.rcodeName) || `rcode ${rcode}`}`;
    } catch (e) {
      lastTimedOut = Boolean(e && e.code === 'ETIMEOUT');
      last = (e && (e.code || e.message)) || 'error';
    }
  }
  return {
    status: lastTimedOut ? 'timeout' : 'error',
    answers: [],
    cname: [],
    error: last || 'No resolvers configured',
  };
}

module.exports = { formatAnswer, lookupOne, compareResults, lookupAll, resolveVia };
