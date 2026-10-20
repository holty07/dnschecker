'use strict';

// Phase 0 reachability check. Queries a fixed name against every resolver over
// both UDP and TCP. The DNS transport is injected as `query`, so this module
// makes no network calls itself and can be tested offline.

const TARGET = 'example.com';
const TYPE = 'A';
const TRANSPORTS = ['udp', 'tcp'];

function minTtl(records) {
  const ttls = records.map((r) => r.ttl).filter((t) => Number.isFinite(t));
  return ttls.length > 0 ? Math.min(...ttls) : null;
}

function classify(rcodeName, aRecords) {
  if (rcodeName === 'NXDOMAIN') return 'nxdomain';
  if (rcodeName === 'NOERROR') return aRecords.length > 0 ? 'ok' : 'nodata';
  return 'error';
}

async function probe({ resolver, transport, query, timeout }) {
  const started = performance.now();
  const elapsed = () => Math.round(performance.now() - started);
  const base = { resolver: resolver.name, server: resolver.address, transport };

  try {
    const res = await query({
      server: resolver.address,
      name: TARGET,
      type: TYPE,
      transport,
      timeout,
    });
    const aRecords = (res.answers || []).filter((a) => a.type === TYPE);
    const status = classify(res.rcodeName, aRecords);
    const result = {
      ...base,
      status,
      answers: aRecords.map((a) => a.data),
      ttl: minTtl(aRecords),
      ms: typeof res.ms === 'number' ? Math.round(res.ms * 10) / 10 : elapsed(),
    };
    if (status === 'error') result.error = String(res.rcodeName);
    return result;
  } catch (err) {
    const code = err && err.code;
    if (code === 'ETIMEOUT') {
      return { ...base, status: 'timeout', answers: [], ttl: null, ms: elapsed() };
    }
    return {
      ...base,
      status: 'error',
      answers: [],
      ttl: null,
      ms: elapsed(),
      error: String(code || (err && err.message) || 'unknown error'),
    };
  }
}

async function selftest({ resolvers, query, timeout = 3000 }) {
  if (typeof query !== 'function') {
    throw new TypeError('selftest: query must be a function');
  }

  const startedAt = new Date().toISOString();
  const jobs = [];
  for (const resolver of resolvers) {
    for (const transport of TRANSPORTS) {
      jobs.push(probe({ resolver, transport, query, timeout }));
    }
  }
  // probe() never rejects, so one failing resolver cannot reject the whole run.
  const results = await Promise.all(jobs);

  const summary = {};
  for (const transport of TRANSPORTS) {
    const rows = results.filter((r) => r.transport === transport);
    summary[transport] = {
      reachable: rows.filter((r) => r.status === 'ok').length,
      total: rows.length,
    };
  }

  // example.com always has A records. NXDOMAIN or NODATA for it means something on the
  // path (a transparent DNS proxy or sinkhole) is answering instead of the resolver.
  const warnings = results
    .filter((r) => r.status === 'nxdomain' || r.status === 'nodata')
    .map((r) => `${r.resolver} (${r.server}) over ${r.transport.toUpperCase()} returned ${r.status} for ${TARGET}: queries are probably being intercepted`);

  return { target: TARGET, type: TYPE, startedAt, results, summary, warnings };
}

module.exports = { selftest };
