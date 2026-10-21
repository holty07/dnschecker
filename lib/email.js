'use strict';

// Email DNS checks: SPF (via lib/spf.js), DMARC, DKIM and MX.
// `query` (the lib/wire.js signature) and `resolvers` are injected; every query goes
// over TCP through resolveVia. A failure in one part never rejects the whole call.

const crypto = require('node:crypto');
const net = require('node:net');
const { resolveVia } = require('./resolve');

const MAX_MX_HOSTS = 10;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const norm = (s) => String(s).toLowerCase().replace(/\.$/, '');
const msgOf = (e) => (e && (e.code || e.message)) || 'error';

// Parse "k=v; k2=v2" into an object (lower-case keys, first occurrence wins).
function parseTags(record) {
  const tags = {};
  for (const part of String(record).split(';')) {
    const piece = part.trim();
    if (!piece) continue;
    const i = piece.indexOf('=');
    if (i < 1) continue;
    const key = piece.slice(0, i).trim().toLowerCase();
    if (!(key in tags)) tags[key] = piece.slice(i + 1).trim();
  }
  return tags;
}

const lookupFailure = (res) => `DNS lookup failed (${res.error || res.status})`;

// DMARC

const POLICIES = {
  none: 'monitoring only; no action is taken on failing mail',
  quarantine: 'mail failing DMARC should be treated as suspicious, for example sent to spam',
  reject: 'mail failing DMARC should be rejected',
};
const ALIGNMENT = { r: 'relaxed', s: 'strict' };

async function checkDmarc(domain, ctx) {
  const name = `_dmarc.${domain}`;
  const out = { name, found: false, record: null, records: [], tags: {}, summary: [], errors: [], warnings: [] };
  const res = await resolveVia(ctx, name, 'TXT');
  if (res.status === 'timeout' || res.status === 'error') {
    out.errors.push(lookupFailure(res));
    return out;
  }

  out.records = res.answers.filter((t) => /^\s*v=DMARC1(?=[;\s]|$)/i.test(t));
  if (!out.records.length) {
    // Receivers fall back to the organisational domain's record when a subdomain has none.
    // Finding that domain needs the Public Suffix List, which is not implemented here.
    out.warnings.push(`No DMARC record at ${name}`);
    if (domain.split('.').length >= 3) {
      out.warnings.push("No DMARC record here; receivers may use the organisational domain's policy");
    }
    return out;
  }

  out.found = true;
  out.record = out.records[0];
  if (out.records.length > 1) out.errors.push('Multiple DMARC records found; receivers will ignore them all');

  const t = parseTags(out.record);
  out.tags = t;
  const p = t.p !== undefined ? t.p.toLowerCase() : undefined;
  if (p === undefined || p === '') out.errors.push('The p= tag is missing (it is required)');
  else if (!POLICIES[p]) out.errors.push(`Invalid p= value "${t.p}" (expected none, quarantine or reject)`);

  const sp = t.sp !== undefined ? t.sp.toLowerCase() : undefined;
  if (sp !== undefined && !POLICIES[sp]) out.errors.push(`Invalid sp= value "${t.sp}" (expected none, quarantine or reject)`);

  let pct = null;
  if (t.pct !== undefined) {
    if (/^\d+$/.test(t.pct) && Number(t.pct) <= 100) pct = Number(t.pct);
    else out.errors.push(`Invalid pct= value "${t.pct}" (expected 0 to 100)`);
  }
  for (const tag of ['adkim', 'aspf']) {
    if (t[tag] !== undefined && !ALIGNMENT[t[tag].toLowerCase()]) {
      out.errors.push(`Invalid ${tag}= value "${t[tag]}" (expected r or s)`);
    }
  }

  if (POLICIES[p]) out.summary.push(`Policy: ${p} (${POLICIES[p]})`);
  out.summary.push(POLICIES[sp] ? `Subdomain policy: ${sp}` : 'Subdomains inherit the main policy');
  if (pct !== null) out.summary.push(`Applies to ${pct}% of failing mail`);
  const dk = ALIGNMENT[(t.adkim || 'r').toLowerCase()];
  const sa = ALIGNMENT[(t.aspf || 'r').toLowerCase()];
  if (dk) out.summary.push(`DKIM alignment: ${dk}`);
  if (sa) out.summary.push(`SPF alignment: ${sa}`);
  if (t.rua) out.summary.push(`Aggregate reports go to ${t.rua}`);
  if (t.ruf) out.summary.push(`Forensic reports go to ${t.ruf}`);
  if (t.fo) out.summary.push(`Failure reporting options: ${t.fo}`);
  if (t.ri) out.summary.push(`Report interval: ${t.ri} seconds`);

  if (p === 'none') out.warnings.push('Policy is none: monitoring only, no protection');
  if (pct !== null && pct < 100) out.warnings.push(`Policy applies to only ${pct}% of failing mail`);
  if (!t.rua) out.warnings.push('No rua= tag: you will not receive aggregate reports');
  return out;
}

// DKIM

function inspectRsa(der, out) {
  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'rsa') {
      out.errors.push('Public key is not an RSA key');
      return;
    }
    out.keyBits = key.asymmetricKeyDetails.modulusLength;
    if (out.keyBits < 1024) out.warnings.push(`${out.keyBits}-bit key is too weak; receivers may ignore it`);
    else if (out.keyBits < 2048) out.warnings.push(`${out.keyBits}-bit key; consider 2048-bit`);
  } catch {
    out.errors.push('Public key could not be parsed');
  }
}

function inspectEd25519(raw, out) {
  // RFC 8463: p is the raw 32-byte key, not SPKI.
  if (raw.length !== 32) {
    out.errors.push(`Ed25519 key must be 32 bytes (got ${raw.length})`);
    return;
  }
  try {
    crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
    out.keyBits = 256;
  } catch {
    out.errors.push('Public key could not be parsed');
  }
}

async function checkDkim(domain, selector, ctx) {
  const name = `${selector}._domainkey.${domain}`;
  const out = {
    selector, name, found: false, record: null, cname: [], keyType: null, keyBits: null,
    revoked: false, testing: false, tags: {}, errors: [], warnings: [],
  };
  const res = await resolveVia(ctx, name, 'TXT');
  if (res.status === 'timeout' || res.status === 'error') {
    out.errors.push(lookupFailure(res));
    return out;
  }
  out.cname = res.cname;
  if (!res.answers.length) {
    out.warnings.push(`No DKIM key at ${name}. Selectors are set by the sending service, so check which selector it uses`);
    return out;
  }

  out.found = true;
  out.record = res.answers[0];
  if (res.answers.length > 1) out.errors.push('Multiple TXT records found at the DKIM name');

  const t = parseTags(out.record);
  out.tags = t;
  if (t.v !== undefined && t.v.toUpperCase() !== 'DKIM1') out.errors.push(`Unexpected v= value "${t.v}" (expected DKIM1)`);
  out.keyType = (t.k || 'rsa').toLowerCase();
  if (out.keyType !== 'rsa' && out.keyType !== 'ed25519') out.warnings.push(`Unknown key type k=${t.k}`);

  const flags = (t.t || '').toLowerCase().split(':').map((s) => s.trim());
  if (flags.includes('y')) {
    out.testing = true;
    out.warnings.push('Testing mode (t=y): receivers should not treat failures as errors');
  }
  if (t.h !== undefined) {
    const hashes = t.h.toLowerCase().split(':').map((s) => s.trim());
    if (!hashes.includes('sha256')) out.warnings.push(`h=${t.h} does not allow sha256; sha1 is deprecated`);
  }
  if (t.s !== undefined) {
    const services = t.s.split(':').map((s) => s.trim().toLowerCase());
    if (!services.includes('*') && !services.includes('email')) out.warnings.push(`s=${t.s} does not cover email`);
  }

  if (t.p === undefined) {
    out.errors.push('The p= tag is missing (it is required)');
    return out;
  }
  const b64 = t.p.replace(/\s+/g, '');
  if (b64 === '') {
    out.revoked = true;
    out.warnings.push('Key revoked (empty p=)');
    return out;
  }
  const der = Buffer.from(b64, 'base64');
  if (out.keyType === 'rsa') inspectRsa(der, out);
  else if (out.keyType === 'ed25519') inspectEd25519(der, out);
  return out;
}

// MX

function parseMx(answer) {
  const m = /^(\d+)\s*(.*)$/.exec(String(answer).trim());
  if (!m) return null;
  return { priority: Number(m[1]), exchange: norm(m[2].trim()) };
}

async function checkMxHost(mx, ctx, warnings) {
  const rec = { priority: mx.priority, exchange: mx.exchange, addresses: [], status: 'ok' };
  if (net.isIP(mx.exchange)) {
    rec.status = 'error';
    warnings.push(`${mx.exchange} is an IP address; an MX target must be a host name (RFC 5321)`);
    return rec;
  }
  const [a, aaaa] = await Promise.all([resolveVia(ctx, mx.exchange, 'A'), resolveVia(ctx, mx.exchange, 'AAAA')]);
  rec.addresses = [...new Set([...a.answers, ...aaaa.answers])];
  const cname = a.cname.length ? a.cname : aaaa.cname;
  if (cname.length) {
    rec.cname = cname;
    warnings.push(`${mx.exchange} is a CNAME (to ${cname[cname.length - 1]}); an MX must not point to an alias (RFC 2181 section 10.3)`);
  }
  const failed = (r) => r.status === 'timeout' || r.status === 'error';
  if (rec.addresses.length) rec.status = 'ok';
  else if (failed(a) && failed(aaaa)) {
    rec.status = 'error';
    warnings.push(`Could not resolve ${mx.exchange} (${a.error || a.status})`);
  } else {
    rec.status = 'noaddress';
    warnings.push(`${mx.exchange} has no A or AAAA records`);
  }
  return rec;
}

async function checkMx(domain, ctx) {
  const out = { found: false, nullMx: false, records: [], summary: [], errors: [], warnings: [] };
  const res = await resolveVia(ctx, domain, 'MX');
  if (res.status === 'timeout' || res.status === 'error') {
    out.errors.push(lookupFailure(res));
    return out;
  }
  const parsed = res.answers.map(parseMx).filter(Boolean)
    .sort((x, y) => x.priority - y.priority || x.exchange.localeCompare(y.exchange));
  if (!parsed.length) {
    out.warnings.push("No MX records; mail will fall back to the domain's A/AAAA record (implicit MX)");
    return out;
  }
  out.found = true;

  // RFC 7505 null MX: a single "0 ." record.
  if (parsed.length === 1 && parsed[0].exchange === '') {
    out.nullMx = true;
    out.summary.push('This domain does not accept mail (null MX)');
    return out;
  }

  const usable = parsed.filter((m) => m.exchange !== '');
  const checked = usable.slice(0, MAX_MX_HOSTS);
  if (usable.length > checked.length) {
    out.warnings.push(`Only the first ${MAX_MX_HOSTS} of ${usable.length} mail servers were checked`);
  }
  if (usable.length !== parsed.length) out.warnings.push('A null MX record (0 .) is mixed with other MX records');
  out.records = await Promise.all(checked.map((m) => checkMxHost(m, ctx, out.warnings)));
  return out;
}

// SPF is injected; the default loads lib/spf.js on first use.
const defaultCheckSpf = (domain, opts) => require('./spf').checkSpf(domain, opts);

async function safe(fn, fallback) {
  try {
    return await fn();
  } catch (e) {
    return { ...fallback, errors: [`Check failed: ${msgOf(e)}`], warnings: [] };
  }
}

async function checkEmail({ domain, selector }, opts) {
  const { query, resolvers, timeout = 3000, checkSpf = defaultCheckSpf } = opts;
  const ctx = { query, resolvers, timeout };
  const sel = typeof selector === 'string' ? selector.trim().toLowerCase() : '';

  const lookup = async (name, type) => {
    const r = await resolveVia(ctx, name, type);
    return { status: r.status, answers: r.answers };
  };

  const [spf, dmarc, dkim, mx] = await Promise.all([
    safe(async () => {
      const r = await checkSpf(domain, { lookup });
      return { ...r, errors: r.errors || [], warnings: r.warnings || [] };
    }, { domain, found: false, record: null }),
    safe(() => checkDmarc(domain, ctx), { name: `_dmarc.${domain}`, found: false, record: null, summary: [] }),
    sel ? safe(() => checkDkim(domain, sel, ctx), { selector: sel, name: `${sel}._domainkey.${domain}`, found: false, record: null })
      : Promise.resolve(null),
    safe(() => checkMx(domain, ctx), { found: false, nullMx: false, records: [], summary: [] }),
  ]);
  return { domain, spf, dmarc, dkim, mx };
}

module.exports = { checkEmail, checkDmarc, checkDkim, checkMx, parseTags };
