'use strict';

// SPF (RFC 7208) parser and lookup counter. Pure apart from the injected `lookup`:
//   async lookup(name, type) -> { status: 'ok'|'nodata'|'nxdomain'|'timeout'|'error', answers: [string] }

const net = require('node:net');

const SPF_PREFIX = /^v=spf1(?:\s|$)/i;
const MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const MODIFIER = /^([A-Za-z][A-Za-z0-9_.-]*)=([\s\S]*)$/;

function isSpfRecord(text) {
  return typeof text === 'string' && SPF_PREFIX.test(text);
}

function validPrefix(text, max) {
  if (!/^\d{1,3}$/.test(text)) return false;
  if (text.length > 1 && text[0] === '0') return false;
  return Number(text) <= max;
}

function validIp4(text) {
  const parts = text.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && (p === '0' || p[0] !== '0') && Number(p) <= 255);
}

function validIp6(text) {
  return !text.includes('%') && net.isIPv6(text);
}

// Parse the optional "/n" and "//n" suffix used by the a and mx mechanisms.
function validDualCidr(text) {
  const m = /^(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(text);
  if (!m) return false;
  if (m[1] !== undefined && !validPrefix(m[1], 32)) return false;
  if (m[2] !== undefined && !validPrefix(m[2], 128)) return false;
  return true;
}

function parseMechanism(token) {
  let rest = token;
  let qualifier = '+';
  if ('+-~?'.includes(rest[0])) {
    qualifier = rest[0];
    rest = rest.slice(1);
  }
  const m = /^([A-Za-z0-9_.-]*)([\s\S]*)$/.exec(rest);
  const name = m[1].toLowerCase();
  const remainder = m[2];
  const term = { raw: token, kind: 'mechanism', qualifier, name, value: null };
  const fail = (message) => {
    term.error = message;
    return term;
  };

  if (!MECHANISMS.has(name)) return fail(`Unknown mechanism: ${token}`);
  if (remainder !== '' && remainder[0] !== ':' && remainder[0] !== '/') {
    return fail(`Invalid term: ${token}`);
  }

  switch (name) {
    case 'all':
      if (remainder !== '') return fail('all takes no value');
      return term;
    case 'include':
    case 'exists':
      if (remainder[0] !== ':' || remainder.length < 2) return fail(`${name} requires a domain value (${name}:domain)`);
      term.value = remainder.slice(1);
      return term;
    case 'ptr':
      if (remainder[0] === '/') return fail('ptr does not take a CIDR length');
      if (remainder === ':') return fail('ptr requires a domain after the colon');
      if (remainder) term.value = remainder.slice(1);
      return term;
    case 'a':
    case 'mx': {
      if (remainder === '') return term;
      let spec = remainder;
      if (spec[0] === ':') {
        spec = spec.slice(1);
        if (spec.includes('%{')) {
          term.value = spec;
          return term;
        }
        const domain = /^[^/]*/.exec(spec)[0];
        if (!domain) return fail(`${name} requires a domain after the colon`);
        term.value = domain;
        spec = spec.slice(domain.length);
      }
      if (!validDualCidr(spec)) return fail(`Invalid CIDR length in ${token}`);
      return term;
    }
    case 'ip4':
    case 'ip6': {
      if (remainder[0] !== ':' || remainder.length < 2) return fail(`${name} requires an address (${name}:address)`);
      const value = remainder.slice(1);
      term.value = value;
      const slash = value.indexOf('/');
      const addr = slash === -1 ? value : value.slice(0, slash);
      const prefix = slash === -1 ? null : value.slice(slash + 1);
      if (name === 'ip4') {
        if (!validIp4(addr)) return fail(`Invalid ip4 address: ${value}`);
        if (prefix !== null && !validPrefix(prefix, 32)) return fail(`Invalid ip4 prefix length (0 to 32): ${value}`);
      } else {
        if (!validIp6(addr)) return fail(`Invalid ip6 address: ${value}`);
        if (prefix !== null && !validPrefix(prefix, 128)) return fail(`Invalid ip6 prefix length (0 to 128): ${value}`);
      }
      return term;
    }
    default:
      return term;
  }
}

function parseSpf(record) {
  const errors = [];
  const terms = [];
  const text = typeof record === 'string' ? record : '';
  if (!isSpfRecord(text)) {
    return { terms, errors: ['Record does not start with v=spf1'] };
  }
  const tokens = text.trim().split(/\s+/).slice(1);
  const seen = new Set();
  for (const token of tokens) {
    const mod = MODIFIER.exec(token);
    let term;
    if (mod) {
      const name = mod[1].toLowerCase();
      term = { raw: token, kind: 'modifier', qualifier: '+', name, value: mod[2] };
      if (name === 'redirect' || name === 'exp') {
        if (mod[2] === '') term.error = `${name} requires a value (${name}=domain)`;
        else if (seen.has(name)) term.error = `Duplicate ${name} modifier`;
        seen.add(name);
      }
    } else {
      term = parseMechanism(token);
    }
    if (term.error) errors.push(term.error);
    terms.push(term);
  }
  return { terms, errors };
}

const normName = (name) => String(name).trim().toLowerCase().replace(/\.$/, '');
const isVoidStatus = (status) => status === 'nodata' || status === 'nxdomain';
const hasMacro = (value) => typeof value === 'string' && value.includes('%{');

async function checkSpf(domain, opts = {}) {
  const { lookup, maxLookups = 10, maxVoid = 2, hardCap = 40 } = opts;
  const errors = [];
  const warnings = [];
  const addError = (m) => { if (!errors.includes(m)) errors.push(m); };
  const addWarning = (m) => { if (!warnings.includes(m)) warnings.push(m); };
  const state = { lookups: 0, voids: 0, capped: false };

  async function query(name, type) {
    try {
      const r = await lookup(name, type);
      if (!r || typeof r !== 'object') return { status: 'error', answers: [] };
      return { status: String(r.status), answers: Array.isArray(r.answers) ? r.answers.map(String) : [] };
    } catch (err) {
      return { status: 'error', answers: [] };
    }
  }

  // Timeouts and errors are temporary failures: warn, never count as void.
  function tempFailed(res, name, type) {
    if (res.status === 'timeout') addWarning(`${type} lookup for ${name} timed out`);
    else if (res.status === 'error') addWarning(`${type} lookup for ${name} failed`);
    else return false;
    return true;
  }

  // Count the term, then say whether DNS may be queried for it.
  function countLookup(term) {
    term.lookups = 1;
    state.lookups += 1;
    if (state.lookups > hardCap) {
      state.capped = true;
      return false;
    }
    return true;
  }

  function markVoid(term) {
    state.voids += 1;
    term.void = true;
  }

  // Fetch and select the SPF record(s) at a target (include or redirect).
  async function fetchTarget(term, label, target, path) {
    const res = await query(target, 'TXT');
    if (isVoidStatus(res.status)) markVoid(term);
    if (tempFailed(res, target, 'TXT')) {
      term.include = { domain: target, record: null, terms: [], error: `TXT lookup ${res.status === 'timeout' ? 'timed out' : 'failed'}` };
      return null;
    }
    const records = res.answers.filter(isSpfRecord);
    if (records.length === 0) {
      const message = `${label} has no SPF record`;
      term.error = message;
      addError(message);
      term.include = { domain: target, record: null, terms: [], error: message };
      return null;
    }
    if (records.length > 1) {
      addError(`Multiple SPF records found (${records.length}) at ${target}; receivers will return permerror`);
    }
    return evaluate(target, records[0], [...path, target], false);
  }

  async function evaluate(dom, record, path, isTop) {
    const parsed = parseSpf(record);
    const node = { domain: dom, record, terms: [] };
    for (const e of parsed.errors) addError(isTop ? e : `${dom}: ${e}`);

    const allTerm = parsed.terms.find((t) => t.kind === 'mechanism' && t.name === 'all');
    let effectiveAll = allTerm ? allTerm.qualifier : null;
    let redirect = null;

    // Receivers stop at "all" (RFC 7208 section 5.1), so mechanisms after it are never
    // evaluated and don't count toward the lookup limit.
    let seenAll = false;
    const ignored = [];

    for (const t of parsed.terms) {
      const term = { raw: t.raw, qualifier: t.qualifier, name: t.name, value: t.value, lookups: 0 };
      if (t.error) term.error = t.error;
      node.terms.push(term);
      if (t.error) continue;
      if (seenAll && t.kind === 'mechanism') {
        term.ignored = true;
        ignored.push(t.raw);
        continue;
      }
      if (t.kind === 'mechanism' && t.name === 'all') seenAll = true;

      if (t.kind === 'modifier') {
        if (t.name === 'redirect') redirect = term;
        continue;
      }

      switch (t.name) {
        case 'ptr':
          countLookup(term);
          addWarning('ptr is deprecated and slow; RFC 7208 says not to use it');
          break;

        case 'include': {
          const mayQuery = countLookup(term);
          if (hasMacro(t.value)) {
            addWarning(`Macros in "${t.raw}" can't be evaluated without a sender, so it was counted but not followed`);
            break;
          }
          const target = normName(t.value);
          if (path.includes(target)) {
            const message = `Circular include: ${[...path, target].join(' → ')}`;
            term.error = message;
            addError(message);
            break;
          }
          if (!mayQuery) break;
          const child = await fetchTarget(term, `include:${t.value}`, target, path);
          if (child) term.include = child.node;
          break;
        }

        case 'a':
        case 'mx':
        case 'exists': {
          const mayQuery = countLookup(term);
          if (hasMacro(t.value)) {
            addWarning(`Macros in "${t.raw}" can't be evaluated without a sender, so it was counted but not followed`);
            break;
          }
          if (!mayQuery) break;
          const target = t.value ? normName(t.value) : dom;
          if (t.name === 'mx') {
            const res = await query(target, 'MX');
            if (isVoidStatus(res.status)) markVoid(term);
            else if (!tempFailed(res, target, 'MX') && res.answers.length > 10) {
              const message = `MX lookup for ${target} returned ${res.answers.length} hosts; RFC 7208 allows at most 10`;
              term.error = message;
              addError(message);
            }
          } else {
            const res = await query(target, 'A');
            if (t.name === 'a' && res.status === 'nodata') {
              const res6 = await query(target, 'AAAA');
              if (isVoidStatus(res6.status)) markVoid(term);
              else tempFailed(res6, target, 'AAAA');
            } else if (isVoidStatus(res.status)) markVoid(term);
            else tempFailed(res, target, 'A');
          }
          break;
        }

        default:
          break; // all, ip4, ip6: no DNS
      }
    }

    if (ignored.length) {
      addWarning(`${isTop ? '' : `${dom}: `}${ignored.join(' ')} after "all" will never be evaluated`);
    }

    // redirect is evaluated last, and only when there is no "all".
    if (redirect) {
      if (allTerm) {
        addWarning(`redirect=${redirect.value} is ignored because ${dom} has an "all" mechanism`);
      } else {
        const mayQuery = countLookup(redirect);
        if (hasMacro(redirect.value)) {
          addWarning(`Macros in "${redirect.raw}" can't be evaluated without a sender, so it was counted but not followed`);
        } else {
          const target = normName(redirect.value);
          if (path.includes(target)) {
            const message = `Circular include: ${[...path, target].join(' → ')}`;
            redirect.error = message;
            addError(message);
          } else if (mayQuery) {
            const child = await fetchTarget(redirect, `redirect=${redirect.value}`, target, path);
            if (child) {
              redirect.include = child.node;
              effectiveAll = child.all;
            }
          }
        }
      }
    }

    return { node, all: effectiveAll, hasAll: Boolean(allTerm), hasRedirect: Boolean(redirect) && !allTerm };
  }

  const d = normName(domain);
  const result = {
    domain: d,
    found: false,
    record: null,
    records: [],
    lookupCount: 0,
    voidLookups: 0,
    allQualifier: null,
    errors,
    warnings,
    tree: { domain: d, record: null, terms: [] },
  };

  const txt = await query(d, 'TXT');
  result.records = txt.answers.filter(isSpfRecord);
  if (result.records.length === 0) {
    if (!tempFailed(txt, d, 'TXT')) addWarning('No SPF record found');
    return result;
  }

  result.found = true;
  result.record = result.records[0];
  if (result.records.length > 1) {
    addError(`Multiple SPF records found (${result.records.length}); receivers will return permerror`);
  }

  const top = await evaluate(d, result.record, [d], true);
  result.tree = top.node;
  result.allQualifier = top.all;
  result.lookupCount = state.lookups;
  result.voidLookups = state.voids;

  if (state.capped) {
    addWarning(`Stopped following DNS lookups after ${hardCap}; the lookup count is a lower bound`);
  }
  if (state.lookups > maxLookups) {
    addError(`Too many DNS lookups: ${state.lookups} (limit ${maxLookups})`);
  } else if (state.lookups >= maxLookups - 2) {
    addWarning(`Uses ${state.lookups} DNS lookups, which is close to the ${maxLookups}-lookup limit`);
  }
  if (state.voids > maxVoid) {
    addError(`Too many void lookups: ${state.voids} (limit ${maxVoid})`);
  }

  if (top.all === '+') addWarning('+all allows any server to send as this domain');
  else if (top.all === '?') addWarning('?all is neutral, which gives no protection');
  else if (top.all === null) {
    addWarning(top.hasRedirect
      ? 'The redirect target has no "all" mechanism, so the result defaults to neutral'
      : 'No "all" mechanism or redirect, so the result defaults to neutral');
  }

  return result;
}

module.exports = { parseSpf, checkSpf, isSpfRecord };
