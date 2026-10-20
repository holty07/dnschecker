'use strict';

// Authoritative checks: find the zone for a name, resolve its nameservers via the
// public resolvers, then query every nameserver address directly over TCP.
// Everything is injected (`query`, `resolvers`) so tests can supply a fake.

const { lookupOne, compareResults } = require('./resolve');
const { isPublicAddress } = require('./validate');

const norm = (s) => String(s).toLowerCase().replace(/\.$/, '');
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function discoveryError(message, code) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// Ask the public resolvers in order; fall back on a thrown error or a rcode other
// than NOERROR/NXDOMAIN (SERVFAIL, REFUSED and so on).
async function discover({ query, resolvers, timeout = 3000 }, name, type) {
  let last = null;
  for (const r of resolvers) {
    try {
      const res = await query({ server: r.address, name, type, transport: 'tcp', timeout });
      const rcode = res && res.flags ? res.flags.rcode : undefined;
      if (rcode === 0 || rcode === 3) {
        return { rcode, answers: Array.isArray(res.answers) ? res.answers : [] };
      }
      last = discoveryError(`${r.name}: ${res.rcodeName || `rcode ${rcode}`}`, 'EDISCOVERY');
    } catch (e) {
      last = e;
    }
  }
  const err = discoveryError(
    `Could not query any public resolver for ${type} ${name}${last ? ` (${last.code || last.message})` : ''}`,
    'EDISCOVERY',
  );
  throw err;
}

async function findZone(name, opts) {
  const labels = norm(name).split('.');
  let nameExists = true;
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    const res = await discover(opts, candidate, 'NS');
    if (i === 0 && res.rcode === 3) nameExists = false;
    const hosts = res.answers
      .filter((r) => r.type === 'NS' && norm(r.name) === candidate)
      .map((r) => norm(r.data));
    if (hosts.length) {
      return { zone: candidate, nsHosts: [...new Set(hosts)].sort(), nameExists };
    }
  }
  throw discoveryError('No nameservers found for this name', 'ENOZONE');
}

// Returns an array of { host, addresses, rejected, error? }. The array also carries
// `skippedHosts` (beyond maxNameservers) and `skippedAddresses` (beyond maxAddresses).
async function resolveNameservers(nsHosts, opts) {
  const { maxNameservers = 8, maxAddresses = 16 } = opts;
  const hosts = nsHosts.slice(0, maxNameservers);
  const skippedHosts = nsHosts.slice(maxNameservers);

  const found = await Promise.all(hosts.map(async (host) => {
    const entry = { host, addresses: [], rejected: [] };
    const [a, aaaa] = await Promise.allSettled([discover(opts, host, 'A'), discover(opts, host, 'AAAA')]);
    const ips = [];
    for (const s of [a, aaaa]) {
      if (s.status === 'fulfilled') {
        for (const r of s.value.answers) if (r.type === 'A' || r.type === 'AAAA') ips.push(String(r.data));
      }
    }
    if (a.status === 'rejected' && aaaa.status === 'rejected') {
      entry.error = (a.reason && (a.reason.code || a.reason.message)) || 'error';
    }
    for (const ip of [...new Set(ips)]) {
      if (isPublicAddress(ip)) entry.addresses.push(ip);
      else entry.rejected.push({ address: ip, reason: 'private or reserved address' });
    }
    return entry;
  }));

  // Cap total addresses, IPv4 first.
  const all = [];
  for (const e of found) for (const ip of e.addresses) all.push({ e, ip, v6: ip.includes(':') });
  all.sort((x, y) => Number(x.v6) - Number(y.v6));
  const keep = new Set(all.slice(0, maxAddresses));
  const skippedAddresses = all.slice(maxAddresses).map((x) => ({ host: x.e.host, address: x.ip }));
  for (const e of found) e.addresses = all.filter((x) => x.e === e && keep.has(x)).map((x) => x.ip);

  found.skippedHosts = skippedHosts;
  found.skippedAddresses = skippedAddresses;
  return found;
}

const serialOf = (row) => {
  if (row.status !== 'ok' || !row.answers.length) return null;
  const n = Number(String(row.answers[0]).split(' ')[2]);
  return Number.isFinite(n) ? n : null;
};

async function checkAuthoritative({ name, type }, opts) {
  const { query, timeout = 3000 } = opts;
  const full = { timeout: 3000, maxNameservers: 8, maxAddresses: 16, ...opts };
  const { zone, nsHosts, nameExists } = await findZone(name, full);
  const nameservers = await resolveNameservers(nsHosts, full);

  const targets = [];
  for (const ns of nameservers) for (const ip of ns.addresses) targets.push({ host: ns.host, ip });

  const results = await Promise.all(targets.map(async ({ host, ip }) => {
    const resolver = { name: host, address: ip };
    const reuse = type === 'SOA' && norm(name) === zone;
    const mainP = lookupOne({ resolver, name, type, query, timeout });
    const soaP = reuse ? mainP : lookupOne({ resolver, name: zone, type: 'SOA', query, timeout });
    const [main, soa] = await Promise.all([mainP, soaP]);
    const answered = ['ok', 'nodata', 'nxdomain'].includes(main.status);
    return {
      ...main,
      nameserver: host,
      serial: serialOf(soa),
      lame: answered && !main.authoritative,
    };
  }));

  const consensus = compareResults(results);
  const values = [...new Set(results.map((r) => r.serial).filter((s) => s !== null))].sort((a, b) => a - b);
  const serials = {
    values,
    allMatch: values.length === 1,
    byServer: results.map((r) => ({ nameserver: r.nameserver, server: r.server, serial: r.serial })),
  };

  const warnings = [];
  const lameHosts = new Set(results.filter((r) => r.lame).map((r) => r.nameserver));
  if (lameHosts.size) {
    warnings.push(`${plural(lameHosts.size, 'nameserver')} answered non-authoritatively (lame delegation)`);
  }
  if (values.length > 1) {
    warnings.push(`SOA serials differ: ${values.join(', ')}. The zone has not synchronised across all nameservers.`);
  }
  const unreachable = results.filter((r) => r.status === 'unreachable').length;
  if (unreachable) {
    warnings.push(`${plural(unreachable, 'address', 'addresses')} unreachable (IPv6 may not be available from this server)`);
  }
  for (const ns of nameservers) {
    if (ns.rejected.length) {
      warnings.push(
        `${plural(ns.rejected.length, 'address', 'addresses')} for ${ns.host} skipped as private or reserved: ${ns.rejected.map((r) => r.address).join(', ')}`,
      );
    }
    if (!ns.addresses.length && !ns.rejected.length) {
      warnings.push(`Could not find an address for nameserver ${ns.host}`);
    }
  }
  if (nameservers.skippedHosts.length) {
    warnings.push(
      `${plural(nameservers.skippedHosts.length, 'nameserver')} not queried because the limit is ${full.maxNameservers}: ${nameservers.skippedHosts.join(', ')}`,
    );
  }
  if (nameservers.skippedAddresses.length) {
    warnings.push(
      `${plural(nameservers.skippedAddresses.length, 'address', 'addresses')} not queried because the limit is ${full.maxAddresses}`,
    );
  }
  if (!nameExists) {
    warnings.push("The name does not exist (NXDOMAIN); showing the zone's nameservers");
  }

  return {
    name,
    type,
    zone,
    nameservers: nameservers.map((n) => ({ host: n.host, addresses: n.addresses, rejected: n.rejected, ...(n.error ? { error: n.error } : {}) })),
    results,
    consensus,
    serials,
    warnings,
  };
}

module.exports = { findZone, resolveNameservers, checkAuthoritative };
