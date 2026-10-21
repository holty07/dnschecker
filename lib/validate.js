'use strict';

// Input validation for lookups. Throws Error with code 'EINVALID' and a
// user-facing message; returns { name, type }.

const net = require('node:net');
const { domainToASCII } = require('node:url');

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'PTR'];

// Underscores are deliberately allowed in labels: email and ACME DNS records
// live at names such as _dmarc.example.com, selector._domainkey.example.com
// and _acme-challenge.example.com.
const LABEL_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;

function invalid(message) {
  const e = new Error(message);
  e.code = 'EINVALID';
  return e;
}

function reverseIPv4(ip) {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

function expandIPv6(ip) {
  let s = ip;
  // Embedded IPv4 tail (e.g. ::ffff:1.2.3.4) becomes two hex groups.
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m) {
    const o = m[2].split('.').map(Number);
    const hi = ((o[0] << 8) | o[1]).toString(16);
    const lo = ((o[2] << 8) | o[3]).toString(16);
    s = `${m[1]}${hi}:${lo}`;
  }
  let groups;
  if (s.includes('::')) {
    const [head, tail] = s.split('::');
    const h = head === '' ? [] : head.split(':');
    const t = tail === '' ? [] : tail.split(':');
    groups = [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t];
  } else {
    groups = s.split(':');
  }
  return groups.map((g) => g.padStart(4, '0').toLowerCase());
}

function reverseIPv6(ip) {
  const nibbles = expandIPv6(ip).join('').split('');
  return `${nibbles.reverse().join('.')}.ip6.arpa`;
}

const numericLabel = (l) => /^(\d+|0x[0-9a-f]*)$/i.test(l);
const looksNumeric = (labels) => labels.every((l) => /^\d+$/.test(l)) || numericLabel(labels[labels.length - 1]);

function validateQuery(input, type) {
  if (typeof type !== 'string') throw invalid('Unsupported record type');
  const t = type.toUpperCase();
  if (!TYPES.includes(t)) throw invalid('Unsupported record type');

  if (typeof input !== 'string') throw invalid('Enter a domain name');
  if (input.length > 1024) throw invalid('Input is too long');
  const trimmed = input.trim();
  if (trimmed === '') throw invalid('Enter a domain name');
  // Checked before IDN conversion, which could otherwise mask these.
  if (/[\s\x00-\x1f\x7f]/.test(trimmed)) {
    throw invalid('Domain names cannot contain spaces or control characters');
  }

  if (t === 'PTR' && net.isIP(trimmed)) {
    return { name: net.isIPv4(trimmed) ? reverseIPv4(trimmed) : reverseIPv6(trimmed), type: t };
  }

  if (net.isIP(trimmed) || /^\[.*\]$/.test(trimmed)) {
    throw invalid('IP addresses are only accepted for PTR lookups');
  }
  if (/[:/@?]/.test(trimmed)) {
    throw invalid('Enter just the domain name (for example example.com), not a URL or email address');
  }

  let host = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (host === '') throw invalid('Enter a domain name');
  if (looksNumeric(host.split('.'))) throw invalid('That looks like an IP address, not a domain name');

  // domainToASCII percent-decodes its input, so reject '%' before converting.
  if (host.includes('%')) throw invalid('That is not a valid domain name');
  host = domainToASCII(host);
  if (host === '') throw invalid('That is not a valid domain name');
  host = host.toLowerCase();

  if (host.length > 253) throw invalid('Domain name is longer than 253 characters');
  const labels = host.split('.');
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) {
      throw invalid('Each part of a domain name must be 1 to 63 characters long');
    }
    if (!LABEL_RE.test(label)) {
      throw invalid('Domain names may only contain letters, digits, hyphens and underscores, and parts cannot start or end with a hyphen');
    }
  }
  if (looksNumeric(labels)) throw invalid('That looks like an IP address, not a domain name');

  return { name: host, type: t };
}

const RESERVED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
// Only global unicast (2000::/3) is allowed for IPv6, so ::, ::1, ::ffff:0:0/96, 64:ff9b::/96,
// fc00::/7, fe80::/10 and ff00::/8 are rejected by that allow-list. Do not add them to a
// BlockList shared with IPv4: BlockList.check matches IPv4 addresses against ::ffff:0:0/96.
const RESERVED_V6 = [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]];

const reservedV4 = new net.BlockList();
for (const [addr, prefix] of RESERVED_V4) reservedV4.addSubnet(addr, prefix, 'ipv4');
const reservedV6 = new net.BlockList();
for (const [addr, prefix] of RESERVED_V6) reservedV6.addSubnet(addr, prefix, 'ipv6');
const globalUnicastV6 = new net.BlockList();
globalUnicastV6.addSubnet('2000::', 3, 'ipv6');

// True only for a public unicast address. Anything that is not an IP literal is false.
function isPublicAddress(ip) {
  if (typeof ip !== 'string' || ip.includes('%')) return false;
  const family = net.isIP(ip);
  if (family === 4) return !reservedV4.check(ip, 'ipv4');
  if (family === 6) return globalUnicastV6.check(ip, 'ipv6') && !reservedV6.check(ip, 'ipv6');
  return false;
}

module.exports = { TYPES, validateQuery, isPublicAddress };
