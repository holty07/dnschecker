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

module.exports = { TYPES, validateQuery };
