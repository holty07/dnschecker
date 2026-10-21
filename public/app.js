'use strict';

// Lookup page. Every element is built with createElement and textContent, so
// user input and resolver answers are never parsed as markup.

const ALL_VALUE = 'ALL';
// PTR takes an IP address, not a domain name, so "All common" leaves it out.
const SKIP_IN_ALL = ['PTR'];
const COLUMNS = ['Resolver', 'Server', 'Status', 'Answers', 'TTL', 'Time (ms)'];
const AUTH_COLUMNS = ['Nameserver', 'Address', 'Status', 'Answers', 'Serial', 'TTL', 'Time (ms)'];
const PARTICIPATING = ['ok', 'nodata', 'nxdomain'];
const MODE_PUBLIC = 'public';
const MODE_AUTHORITATIVE = 'authoritative';
const MODE_EMAIL = 'email';
const MODE_KEY = 'dnschecker.mode';
// Limits from RFC 7208: at most 10 DNS-querying terms and 2 void lookups.
const SPF_LOOKUP_LIMIT = 10;
const SPF_VOID_LIMIT = 2;
// DKIM records longer than this are cut short, with the full text one click away.
const RECORD_PREVIEW = 120;
const ALL_QUALIFIERS = {
  '-': '-all: fail',
  '~': '~all: softfail',
  '?': '?all: neutral',
  '+': '+all: pass-all (anyone may send)'
};
const VERDICT_LABELS = { pass: 'Pass', warn: 'Warning', fail: 'Fail', muted: 'Not checked' };
// Recent lookups are kept in this browser only.
const RECENT_KEY = 'dnschecker.recent';
const RECENT_MAX = 10;
const MAX_DOMAIN_LENGTH = 253;
// A DKIM selector is a DNS label; the server does the full check.
const SELECTOR_PATTERN = /^[A-Za-z0-9._-]{1,63}$/;
// Control characters and whitespace never belong in a stored domain.
const UNSAFE_DOMAIN_PATTERN = /[\u0000-\u001f\u007f\s]/;
const COPY_FEEDBACK_MS = 2000;
// dateStyle/timeStyle cannot be combined with timeZoneName (it throws), so the same
// medium date and short time are spelled out as components, with the zone name added.
const TEXT_STAMP_OPTIONS = { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' };

const form = document.getElementById('lookup-form');
const domainInput = document.getElementById('domain');
const typeSelect = document.getElementById('type');
const typeField = document.getElementById('type-field');
const modeSelect = document.getElementById('mode');
const selectorField = document.getElementById('selector-field');
const selectorInput = document.getElementById('selector');
const presetBox = document.getElementById('selector-presets');
const submitButton = document.getElementById('submit');
const statusLine = document.getElementById('status');
const errorBox = document.getElementById('error');
const resultsBox = document.getElementById('results');
const recentBox = document.getElementById('recent');
const recentChips = document.getElementById('recent-chips');
const recentClear = document.getElementById('recent-clear');

// Each submit gets a number. A slow earlier request must not overwrite a newer one.
let latestRequest = 0;
// One plain-text builder per result section on screen, for "Copy all".
let copyBuilders = [];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function statusClass(status) {
  if (status === 'ok') return 'status-ok';
  if (status === 'nodata' || status === 'nxdomain' || status === 'unreachable') return 'status-amber';
  return 'status-red';
}

// A lame nameserver answers, but is not authoritative for the zone, so it gets the warning colour.
function rowStatusClass(row) {
  return row.lame ? 'status-amber' : statusClass(row.status);
}

function isParticipating(row) {
  return PARTICIPATING.indexOf(row.status) !== -1;
}

function showErrors(messages) {
  clear(errorBox);
  if (messages.length === 0) {
    errorBox.hidden = true;
    return;
  }
  messages.forEach(function (message) {
    errorBox.appendChild(el('p', null, message));
  });
  errorBox.hidden = false;
}

function consensusText(consensus) {
  if (!consensus || !consensus.majority) return 'No majority answer';
  if (consensus.allAgree) return 'All resolvers agree';
  return consensus.agreeing + ' of ' + consensus.participating + ' agree; differences highlighted';
}

function renderAnswers(cell, row) {
  if (!Array.isArray(row.answers) || row.answers.length === 0) {
    cell.appendChild(el('span', 'muted', '—'));
  } else {
    row.answers.forEach(function (answer) {
      cell.appendChild(el('div', 'mono', answer));
    });
  }
  if (Array.isArray(row.cname) && row.cname.length > 0) {
    cell.appendChild(el('div', 'cname', 'via CNAME: ' + row.cname.join(' → ')));
  }
}

function applyRowClass(tr, row) {
  if (row.differs === true) {
    tr.className = 'differs';
  } else if (row.differs === null && isParticipating(row)) {
    tr.className = 'no-majority';
  }
}

function statusText(row) {
  let text = row.status;
  if (row.lame) text += ' (not authoritative)';
  if (row.error) text += ' (' + row.error + ')';
  if (row.truncated) text += ' (truncated)';
  return text;
}

function renderRow(row) {
  const tr = el('tr');
  applyRowClass(tr, row);

  tr.appendChild(el('td', null, row.resolver));
  tr.appendChild(el('td', 'mono server', row.server));
  tr.appendChild(el('td', 'status ' + rowStatusClass(row), statusText(row)));

  const answers = el('td');
  renderAnswers(answers, row);
  tr.appendChild(answers);

  tr.appendChild(el('td', null, row.ttl === null || row.ttl === undefined ? '—' : row.ttl));
  tr.appendChild(el('td', null, row.ms));
  return tr;
}

// The most common SOA serial across the nameservers, or null when there is no
// single most common one (a tie), so a tie does not highlight anything.
function commonSerial(results) {
  const counts = new Map();
  results.forEach(function (row) {
    if (typeof row.serial !== 'number') return;
    counts.set(row.serial, (counts.get(row.serial) || 0) + 1);
  });
  let best = null;
  let bestCount = 0;
  let tied = false;
  counts.forEach(function (count, serial) {
    if (count > bestCount) {
      best = serial;
      bestCount = count;
      tied = false;
    } else if (count === bestCount) {
      tied = true;
    }
  });
  return tied ? null : best;
}

function renderAuthRow(row, common) {
  const tr = el('tr');
  applyRowClass(tr, row);

  tr.appendChild(el('td', null, row.nameserver));
  tr.appendChild(el('td', 'mono server', row.server));
  tr.appendChild(el('td', 'status ' + rowStatusClass(row), statusText(row)));

  const answers = el('td');
  renderAnswers(answers, row);
  tr.appendChild(answers);

  const hasSerial = typeof row.serial === 'number';
  const serialCell = el('td', hasSerial && common !== null && row.serial !== common ? 'serial-differs' : null,
    hasSerial ? row.serial : '—');
  tr.appendChild(serialCell);

  tr.appendChild(el('td', null, row.ttl === null || row.ttl === undefined ? '—' : row.ttl));
  tr.appendChild(el('td', null, row.ms));
  return tr;
}

function serialLine(serials) {
  const values = serials && Array.isArray(serials.values) ? serials.values : [];
  if (values.length === 0) return el('p', 'serial muted', 'No SOA serial returned');
  if (serials.allMatch) return el('p', 'serial', 'SOA serial ' + values[0] + ' on every nameserver');
  return null; // The server's warnings already list differing serials.
}

// Lines for nameservers that could not be resolved. Skipped private addresses are
// already covered by the server's warnings.
function nameserverNotes(nameservers) {
  const notes = [];
  (nameservers || []).forEach(function (ns) {
    if (ns.error) notes.push(ns.host + ': ' + ns.error);
  });
  return notes.map(function (text) { return el('p', 'note', text); });
}

function appendTable(section, columns, rows) {
  const wrap = el('div', 'table-wrap');
  const table = el('table');

  const thead = el('thead');
  const headRow = el('tr');
  columns.forEach(function (name) {
    headRow.appendChild(el('th', null, name));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el('tbody');
  rows.forEach(function (tr) {
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);

  wrap.appendChild(table);
  section.appendChild(wrap);
}

// A section heading with its "Copy as text" button. buildLines returns the plain-text
// lines for this section, built from the response data.
function makeSection(title, buildLines) {
  const section = el('section', 'result-section');
  const head = el('div', 'section-head');
  head.appendChild(el('h2', null, title));
  head.appendChild(copyButton('Copy as text', buildLines));
  section.appendChild(head);
  copyBuilders.push(buildLines);
  return section;
}

// body is one /api/lookup response: { name, type, results, consensus, input }.
function renderSection(body) {
  const stamp = textStamp(new Date());
  const section = makeSection(body.type + ' · ' + body.name, function () { return publicText(body, stamp); });
  section.appendChild(el('p', 'consensus', consensusText(body.consensus)));
  appendTable(section, COLUMNS, (body.results || []).map(renderRow));
  return section;
}

// body is one /api/authoritative response: { name, type, zone, nameservers, results, consensus, serials, warnings }.
function renderAuthoritativeSection(body) {
  const stamp = textStamp(new Date());
  const heading = body.zone ? body.type + ' · ' + body.name + ' — zone ' + body.zone : body.type + ' · ' + body.name;
  const section = makeSection(heading, function () { return authoritativeText(body, stamp); });
  section.appendChild(el('p', 'consensus', consensusText(body.consensus)));
  const serial = serialLine(body.serials);
  if (serial) section.appendChild(serial);
  (body.warnings || []).forEach(function (message) {
    section.appendChild(el('p', 'warning', message));
  });

  const results = body.results || [];
  const common = commonSerial(results);
  appendTable(section, AUTH_COLUMNS, results.map(function (row) { return renderAuthRow(row, common); }));

  nameserverNotes(body.nameservers).forEach(function (note) {
    section.appendChild(note);
  });
  return section;
}

// Email DNS

function asList(value) {
  return Array.isArray(value) ? value : [];
}

function checkVerdict(found, errors, warnings) {
  if (errors.length > 0 || !found) return 'fail';
  if (warnings.length > 0) return 'warn';
  return 'pass';
}

// Errors are listed in red and warnings in amber, under the card's own content.
function findingsList(errors, warnings) {
  if (errors.length === 0 && warnings.length === 0) return null;
  const list = el('ul', 'findings');
  errors.forEach(function (message) { list.appendChild(el('li', 'check-error', message)); });
  warnings.forEach(function (message) { list.appendChild(el('li', 'warning', message)); });
  return list;
}

function checkCard(title, kind, nodes, errors, warnings) {
  const card = el('article', 'check-card' + (kind === 'muted' ? ' check-muted' : ''));
  const head = el('div', 'check-head');
  head.appendChild(el('h3', null, title));
  head.appendChild(el('span', 'badge badge-' + kind, VERDICT_LABELS[kind]));
  card.appendChild(head);
  nodes.forEach(function (node) { card.appendChild(node); });
  const findings = findingsList(errors, warnings);
  if (findings) card.appendChild(findings);
  return card;
}

// A record in a monospace block that wraps. Long records are cut short when truncate is set.
function recordBlock(text, truncate) {
  const full = String(text);
  if (!truncate || full.length <= RECORD_PREVIEW) return el('div', 'mono record', full);
  const wrap = el('div');
  wrap.appendChild(el('div', 'mono record', full.slice(0, RECORD_PREVIEW) + '…'));
  const details = el('details', 'record-details');
  details.appendChild(el('summary', null, 'Show full record'));
  details.appendChild(el('div', 'mono record', full));
  wrap.appendChild(details);
  return wrap;
}

function mxAddressCell(row) {
  const cell = el('td');
  const addresses = asList(row.addresses);
  if (addresses.length > 0) {
    addresses.forEach(function (ip) { cell.appendChild(el('div', 'mono', ip)); });
  } else if (row.status === 'error') {
    cell.appendChild(el('span', 'status-red status-pill', 'lookup error'));
  } else if (row.status === 'noaddress') {
    cell.appendChild(el('span', 'status-amber status-pill', 'no address record'));
  } else {
    cell.appendChild(el('span', 'muted', '—'));
  }
  return cell;
}

function mxTable(records) {
  const wrap = el('div', 'table-wrap');
  const table = el('table', 'mx-table');
  const thead = el('thead');
  const headRow = el('tr');
  ['Priority', 'Mail server', 'Addresses'].forEach(function (name) { headRow.appendChild(el('th', null, name)); });
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el('tbody');
  records.forEach(function (row) {
    const tr = el('tr');
    tr.appendChild(el('td', null, row.priority));
    tr.appendChild(el('td', 'mono', row.exchange));
    tr.appendChild(mxAddressCell(row));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function mxCard(mx) {
  const errors = asList(mx.errors);
  const warnings = asList(mx.warnings);
  const records = asList(mx.records);
  const found = Boolean(mx.found || mx.nullMx);
  const nodes = [];
  if (mx.nullMx) {
    nodes.push(el('p', 'null-mx', 'This domain does not accept mail (null MX)'));
  } else if (records.length === 0) {
    nodes.push(el('p', 'muted', 'No MX records found'));
  } else {
    nodes.push(mxTable(records));
  }
  // No MX isn't fatal: mail falls back to the domain's A/AAAA record (implicit MX).
  const kind = found || errors.length > 0 ? checkVerdict(found, errors, warnings) : 'warn';
  return checkCard('MX', kind, nodes, errors, warnings);
}

// A meter line such as "DNS lookups: 7 of 10", highlighted when over the limit.
function meterLine(label, value, limit) {
  const count = typeof value === 'number' ? value : 0;
  const over = count > limit;
  const meter = el('div', over ? 'meter over' : 'meter');
  let text = label + ': ' + count + ' of ' + limit;
  if (over) text += ' (over the limit)';
  meter.appendChild(el('p', 'meter-label', text));
  const bar = el('div', 'meter-bar');
  const fill = el('div', 'meter-fill');
  fill.style.width = Math.min(100, (count / limit) * 100) + '%';
  bar.appendChild(fill);
  meter.appendChild(bar);
  return meter;
}

function allQualifierText(qualifier) {
  const key = typeof qualifier === 'string' ? qualifier.charAt(0) : '';
  return ALL_QUALIFIERS[key] || 'No all mechanism';
}

function treeList(terms) {
  const list = el('ul', 'tree');
  asList(terms).forEach(function (term) { list.appendChild(treeItem(term)); });
  return list;
}

// Appends a tree node's own error and its terms to parent.
function appendTree(parent, tree) {
  if (tree.error) parent.appendChild(el('div', 'term-error', tree.error));
  parent.appendChild(treeList(tree.terms));
}

function treeItem(term) {
  const li = el('li');
  const line = el('div', 'term');
  line.appendChild(el('span', 'mono', term.raw));
  if (term.lookups === 1) line.appendChild(el('span', 'tag', '+1 lookup'));
  if (term.void) line.appendChild(el('span', 'tag tag-void', 'void'));
  li.appendChild(line);
  if (term.error) li.appendChild(el('div', 'term-error', term.error));
  if (term.include) appendTree(li, term.include);
  return li;
}

function treeDetails(tree) {
  const details = el('details', 'tree-details');
  details.appendChild(el('summary', null, 'Include tree'));
  if (!tree) {
    details.appendChild(el('p', 'muted', 'No tree available'));
    return details;
  }
  appendTree(details, tree);
  return details;
}

function spfCard(spf) {
  const errors = asList(spf.errors);
  const warnings = asList(spf.warnings);
  const found = Boolean(spf.found);
  const nodes = [];
  if (!found) {
    nodes.push(el('p', 'muted', 'No SPF record found'));
  } else {
    nodes.push(recordBlock(spf.record, false));
    nodes.push(meterLine('DNS lookups', spf.lookupCount, SPF_LOOKUP_LIMIT));
    nodes.push(meterLine('Void lookups', spf.voidLookups, SPF_VOID_LIMIT));
    nodes.push(el('p', 'qualifier', 'Default for other senders: ' + allQualifierText(spf.allQualifier)));
    nodes.push(treeDetails(spf.tree));
  }
  return checkCard('SPF', checkVerdict(found, errors, warnings), nodes, errors, warnings);
}

function dmarcCard(dmarc) {
  const errors = asList(dmarc.errors);
  const warnings = asList(dmarc.warnings);
  const found = Boolean(dmarc.found);
  const nodes = [];
  if (dmarc.name) nodes.push(el('p', 'muted', 'Queried ' + dmarc.name));
  if (!found) {
    nodes.push(el('p', 'muted', 'No DMARC record found'));
  } else {
    nodes.push(recordBlock(dmarc.record, false));
    const summary = asList(dmarc.summary);
    if (summary.length > 0) {
      const list = el('ul', 'bullets');
      summary.forEach(function (line) { list.appendChild(el('li', null, line)); });
      nodes.push(list);
    }
  }
  return checkCard('DMARC', checkVerdict(found, errors, warnings), nodes, errors, warnings);
}

function dkimKeyText(dkim) {
  if (!dkim.keyType) return 'Key type not reported';
  const type = String(dkim.keyType);
  if (type.toUpperCase() === 'RSA' && typeof dkim.keyBits === 'number') return 'RSA ' + dkim.keyBits + '-bit';
  return type;
}

function labelled(label, value, mono) {
  const p = el('p', 'fact');
  p.appendChild(el('span', 'fact-label', label + ' '));
  p.appendChild(el('span', mono ? 'mono' : null, value));
  return p;
}

function dkimCard(dkim) {
  if (dkim === null || dkim === undefined) {
    return checkCard('DKIM', 'muted', [el('p', null, 'Enter a selector, or try one of the common ones above')], [], []);
  }
  const errors = asList(dkim.errors);
  const warnings = asList(dkim.warnings);
  const found = Boolean(dkim.found);
  const nodes = [labelled('Queried', dkim.name, true)];
  const cname = asList(dkim.cname);
  if (cname.length > 0) nodes.push(el('p', 'cname-line', 'via CNAME: ' + cname.join(' → ')));

  if (!found) {
    nodes.push(el('p', 'muted', 'No DKIM key published at this selector'));
  } else {
    nodes.push(labelled('Key', dkimKeyText(dkim), false));
    const flags = el('p', 'flags');
    if (dkim.revoked) flags.appendChild(el('span', 'tag tag-red', 'Revoked'));
    if (dkim.testing) flags.appendChild(el('span', 'tag tag-amber', 'Testing mode'));
    if (flags.firstChild) nodes.push(flags);
    if (dkim.record) nodes.push(recordBlock(dkim.record, true));
  }

  // A key that is not published is amber, not red: selectors vary by provider.
  const kind = found ? checkVerdict(true, errors, warnings) : 'warn';
  return checkCard('DKIM', kind, nodes, errors, warnings);
}

function renderEmailSection(body) {
  const stamp = textStamp(new Date());
  const section = makeSection('Email DNS · ' + (body.domain || body.input || ''), function () { return emailText(body, stamp); });
  const cards = el('div', 'email-cards');
  cards.appendChild(mxCard(body.mx || {}));
  cards.appendChild(spfCard(body.spf || {}));
  cards.appendChild(dmarcCard(body.dmarc || {}));
  cards.appendChild(dkimCard(body.dkim));
  section.appendChild(cards);
  return section;
}

// Plain text for support tickets. Built from the response data, never from the DOM.
// Lines are aligned with spaces only: no tabs and no markdown.

function textStamp(date) {
  return date.toLocaleString('en-AU', TEXT_STAMP_OPTIONS);
}

function padRight(text, width) {
  return text + ' '.repeat(Math.max(0, width - text.length));
}

// Lays out rows in aligned columns. A cell may be an array of lines (several
// answers); continuation lines sit under the same column. A row's marker, such as
// " <- differs", goes after its last cell on the first line.
function tabulate(rows) {
  const cells = rows.map(function (row) {
    return row.cells.map(function (cell) {
      const lines = Array.isArray(cell) ? cell.map(String) : [String(cell)];
      return lines.length ? lines : [''];
    });
  });
  const columnCount = cells.reduce(function (max, row) { return Math.max(max, row.length); }, 0);
  const widths = [];
  for (let c = 0; c < columnCount; c += 1) {
    widths[c] = 0;
    cells.forEach(function (row) {
      (row[c] || []).forEach(function (line) { widths[c] = Math.max(widths[c], line.length); });
    });
  }

  const lines = [];
  rows.forEach(function (row, r) {
    const rowCells = cells[r];
    const height = rowCells.reduce(function (max, cell) { return Math.max(max, cell.length); }, 1);
    for (let i = 0; i < height; i += 1) {
      let text = '';
      rowCells.forEach(function (cell, c) {
        const value = cell[i] || '';
        text += c === rowCells.length - 1 ? value : padRight(value, widths[c] + 2);
      });
      if (i === 0 && row.marker) text += row.marker;
      lines.push(text.replace(/\s+$/, ''));
    }
  });
  return lines;
}

function recordTitle(type) {
  return type + ' records';
}

function textConsensus(consensus, who) {
  if (!consensus || !consensus.majority) return 'No majority answer.';
  if (consensus.allAgree) return 'All ' + who + ' agree.';
  return consensus.agreeing + ' of ' + consensus.participating + ' agree. Rows marked "<- differs" do not match.';
}

// Answers, plus the CNAME chain when there is one. An empty answer reads "none".
function answerLines(row) {
  const lines = asList(row.answers).map(String);
  if (asList(row.cname).length > 0) lines.push('via CNAME: ' + row.cname.join(' -> '));
  return lines.length > 0 ? lines : ['none'];
}

function ttlText(ttl) {
  return ttl === null || ttl === undefined ? '' : 'TTL ' + ttl;
}

function msText(ms) {
  return typeof ms === 'number' ? ms + ' ms' : '';
}

function publicText(body, stamp) {
  const lines = [recordTitle(body.type) + ' for ' + body.name + ' (public resolvers), ' + stamp];
  lines.push(textConsensus(body.consensus, 'resolvers'));
  const rows = asList(body.results).map(function (row) {
    return {
      cells: [row.resolver, row.server, statusText(row), answerLines(row), ttlText(row.ttl), msText(row.ms)],
      marker: row.differs === true ? ' <- differs' : ''
    };
  });
  return lines.concat(tabulate(rows));
}

function authoritativeText(body, stamp) {
  const results = asList(body.results);
  const lines = [recordTitle(body.type) + ' for ' + body.name + ' (authoritative nameservers), ' + stamp];
  if (body.zone) lines.push('Zone: ' + body.zone);
  lines.push(textConsensus(body.consensus, 'nameservers'));

  const values = asList(body.serials && body.serials.values);
  if (values.length === 0) lines.push('No SOA serial returned.');
  else if (body.serials.allMatch) lines.push('SOA serial ' + values[0] + ' on every nameserver.');
  asList(body.warnings).forEach(function (message) { lines.push('Warning: ' + message); });

  lines.push('');
  const common = commonSerial(results);
  const rows = [{ cells: ['Nameserver', 'Address', 'Status', 'Answers', 'Serial'] }];
  results.forEach(function (row) {
    const markers = [];
    if (row.differs === true) markers.push('differs');
    const hasSerial = typeof row.serial === 'number';
    if (hasSerial && common !== null && row.serial !== common) markers.push('serial differs');
    rows.push({
      cells: [row.nameserver, row.server, statusText(row), answerLines(row), hasSerial ? String(row.serial) : 'none'],
      marker: markers.length > 0 ? ' <- ' + markers.join(', ') : ''
    });
  });
  tabulate(rows).forEach(function (line) { lines.push(line); });

  asList(body.nameservers).forEach(function (ns) {
    if (ns.error) lines.push('Warning: ' + ns.host + ': ' + ns.error);
  });
  return lines;
}

// Errors first, then warnings, each on its own line.
function findingLines(card) {
  return asList(card.errors).map(function (message) { return 'Error: ' + message; })
    .concat(asList(card.warnings).map(function (message) { return 'Warning: ' + message; }));
}

function textMeter(label, value, limit) {
  const count = typeof value === 'number' ? value : 0;
  return label + ': ' + count + ' of ' + limit + (count > limit ? ' (over the limit)' : '');
}

function mxAddressLines(row) {
  const addresses = asList(row.addresses);
  if (addresses.length > 0) return addresses.map(String);
  if (row.status === 'error') return ['lookup error'];
  if (row.status === 'noaddress') return ['no address record'];
  return ['none'];
}

function mxText(mx) {
  const records = asList(mx.records);
  const lines = [];
  if (mx.nullMx) {
    lines.push('This domain does not accept mail (null MX).');
  } else if (records.length === 0) {
    lines.push('No MX records found.');
  } else {
    const rows = [{ cells: ['Priority', 'Mail server', 'Addresses'] }].concat(records.map(function (row) {
      return { cells: [String(row.priority), row.exchange, mxAddressLines(row)] };
    }));
    tabulate(rows).forEach(function (line) { lines.push(line); });
  }
  return lines.concat(findingLines(mx));
}

function spfText(spf) {
  if (!spf.found) return ['No SPF record found.'].concat(findingLines(spf));
  return [
    'Record: ' + spf.record,
    textMeter('DNS lookups', spf.lookupCount, SPF_LOOKUP_LIMIT),
    textMeter('Void lookups', spf.voidLookups, SPF_VOID_LIMIT),
    'Default for other senders: ' + allQualifierText(spf.allQualifier)
  ].concat(findingLines(spf));
}

function dmarcText(dmarc) {
  const lines = [];
  if (dmarc.name) lines.push('Queried: ' + dmarc.name);
  if (!dmarc.found) {
    lines.push('No DMARC record found.');
  } else {
    lines.push('Record: ' + dmarc.record);
    asList(dmarc.summary).forEach(function (line) { lines.push('  ' + line); });
  }
  return lines.concat(findingLines(dmarc));
}

function dkimText(dkim) {
  if (dkim === null || dkim === undefined) return ['DKIM: no selector given, so not checked.'];
  const lines = ['Queried: ' + dkim.name];
  asList(dkim.cname).forEach(function (name) { lines.push('via CNAME: ' + name); });
  if (!dkim.found) {
    lines.push('No DKIM key published at this selector.');
  } else {
    lines.push('Key: ' + dkimKeyText(dkim));
    if (dkim.revoked) lines.push('Revoked: yes');
    if (dkim.testing) lines.push('Testing mode: yes');
    if (dkim.record) lines.push('Record: ' + dkim.record);
  }
  return lines.concat(findingLines(dkim));
}

function emailText(body, stamp) {
  const lines = ['Email DNS for ' + (body.domain || body.input || '') + ', ' + stamp];
  const parts = [
    ['MX', mxText(body.mx || {})],
    ['SPF', spfText(body.spf || {})],
    ['DMARC', dmarcText(body.dmarc || {})],
    ['DKIM', dkimText(body.dkim)]
  ];
  parts.forEach(function (part) {
    lines.push('', part[0]);
    part[1].forEach(function (line) { lines.push(line); });
  });
  return lines;
}

// Clipboard: the async API first, then a hidden read-only textarea with execCommand.
function fallbackCopy(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.readOnly = true;
  area.tabIndex = -1;
  area.setAttribute('aria-hidden', 'true');
  area.className = 'copy-fallback';
  document.body.appendChild(area);
  let copied = false;
  try {
    area.select();
    area.setSelectionRange(0, text.length);
    copied = document.execCommand('copy') === true;
  } catch (_err) {
    copied = false;
  } finally {
    document.body.removeChild(area);
  }
  return copied;
}

function copyToClipboard(text) {
  let attempt = null;
  try {
    attempt = navigator.clipboard.writeText(text);
  } catch (_err) {
    attempt = null;
  }
  if (!attempt || typeof attempt.then !== 'function') return Promise.resolve(fallbackCopy(text));
  return attempt.then(function () { return true; }, function () { return fallbackCopy(text); });
}

// A button that copies buildLines() and says "Copied" or "Copy failed" for a few seconds.
function copyButton(label, buildLines) {
  const button = el('button', 'secondary copy-button', label);
  button.type = 'button';
  let timer = null;
  button.addEventListener('click', function () {
    const text = buildLines().join('\n');
    copyToClipboard(text).then(function (ok) {
      button.textContent = ok ? 'Copied' : 'Copy failed';
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(function () {
        button.textContent = label;
        timer = null;
      }, COPY_FEEDBACK_MS);
    });
  });
  return button;
}

// Copies every section on screen, separated by a blank line.
function addCopyAll() {
  if (copyBuilders.length < 2) return;
  const builders = copyBuilders.slice();
  const toolbar = el('div', 'results-toolbar');
  toolbar.appendChild(copyButton('Copy all as text', function () {
    const lines = [];
    builders.forEach(function (build, index) {
      if (index > 0) lines.push('');
      build().forEach(function (line) { lines.push(line); });
    });
    return lines;
  }));
  resultsBox.insertBefore(toolbar, resultsBox.firstChild);
}

// Recent lookups (browser only). Storage can be blocked, so every access is guarded:
// readRecent returns null when storage cannot be used, and the feature then hides itself.

function recentKey(entry) {
  return [entry.domain.toLowerCase(), entry.mode, entry.type, entry.selector || ''].join('\n');
}

function isValidRecent(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  if (typeof entry.domain !== 'string' || entry.domain.length === 0 || entry.domain.length > MAX_DOMAIN_LENGTH) return false;
  if (UNSAFE_DOMAIN_PATTERN.test(entry.domain)) return false;
  if ([MODE_PUBLIC, MODE_AUTHORITATIVE, MODE_EMAIL].indexOf(entry.mode) === -1) return false;
  if (Array.from(typeSelect.options).map(function (o) { return o.value; }).indexOf(entry.type) === -1) return false;
  if (entry.selector !== undefined && (typeof entry.selector !== 'string' || !SELECTOR_PATTERN.test(entry.selector))) return false;
  return typeof entry.at === 'number' && isFinite(entry.at);
}

function normaliseRecent(entry) {
  const out = { domain: entry.domain, mode: entry.mode, type: entry.type, at: entry.at };
  if (entry.selector) out.selector = entry.selector;
  return out;
}

// Returns the saved list (malformed items dropped, duplicates removed), [] when nothing
// is saved, or null when storage cannot be read.
function readRecent() {
  let raw;
  try {
    raw = window.localStorage.getItem(RECENT_KEY);
  } catch (_err) {
    return null;
  }
  if (raw === null) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_err) {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const seen = Object.create(null);
  const list = [];
  parsed.forEach(function (entry) {
    if (!isValidRecent(entry)) return;
    const key = recentKey(entry);
    if (seen[key]) return;
    seen[key] = true;
    list.push(normaliseRecent(entry));
  });
  return list.slice(0, RECENT_MAX);
}

function saveRecent(list) {
  try {
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(list));
    return true;
  } catch (_err) {
    return false;
  }
}

function removeRecent() {
  try {
    window.localStorage.removeItem(RECENT_KEY);
    return true;
  } catch (_err) {
    return false;
  }
}

function typeName(type) {
  return type === ALL_VALUE ? 'All common' : type;
}

function recentLabel(entry) {
  if (entry.mode === MODE_EMAIL) {
    return entry.domain + ' · email' + (entry.selector ? ' (' + entry.selector + ')' : '');
  }
  if (entry.mode === MODE_AUTHORITATIVE) return entry.domain + ' · authoritative ' + typeName(entry.type);
  return entry.domain + ' · ' + typeName(entry.type);
}

function hideRecent() {
  clear(recentChips);
  recentBox.hidden = true;
}

function renderRecent(list) {
  clear(recentChips);
  if (list.length === 0) {
    recentBox.hidden = true;
    return;
  }
  list.forEach(function (entry) {
    const chip = el('button', 'chip', recentLabel(entry));
    chip.type = 'button';
    chip.addEventListener('click', function () { runRecent(entry); });
    recentChips.appendChild(chip);
  });
  recentBox.hidden = false;
}

// Restores a saved lookup into the form and runs it.
function runRecent(entry) {
  domainInput.value = entry.domain;
  typeSelect.value = entry.type;
  modeSelect.value = entry.mode;
  storeMode(entry.mode);
  applyModeLayout();
  selectorInput.value = entry.selector || '';
  form.requestSubmit();
}

// Adds a successful lookup to the top of the list, removing any earlier copy of it.
function rememberLookup(lookup) {
  const current = readRecent();
  if (current === null) {
    hideRecent();
    return;
  }
  const entry = Object.assign({}, lookup, { at: Date.now() });
  if (!isValidRecent(entry)) return;
  const key = recentKey(entry);
  const next = [normaliseRecent(entry)].concat(current.filter(function (item) {
    return recentKey(item) !== key;
  })).slice(0, RECENT_MAX);
  if (!saveRecent(next)) {
    hideRecent();
    return;
  }
  renderRecent(next);
}

function clearRecent() {
  if (!removeRecent()) {
    renderRecent(readRecent() || []);
    return;
  }
  renderRecent([]);
}

function getJson(url) {
  return fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (body) {
      if (res.status === 401) {
        // The session has expired or was never started.
        window.location.assign('/login.html?next=' + encodeURIComponent(window.location.pathname));
        throw new Error('Sign in required');
      }
      if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
      return body;
    });
  });
}

function lookup(domain, type, mode) {
  const path = mode === MODE_AUTHORITATIVE ? '/api/authoritative' : '/api/lookup';
  return getJson(path + '?domain=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
}

function lookupEmail(domain, selector) {
  return getJson('/api/email?domain=' + encodeURIComponent(domain) + '&selector=' + encodeURIComponent(selector));
}

function runEmailCheck(domain, selector, requestId) {
  statusLine.textContent = 'Checking email DNS for ' + domain + '...';
  lookupEmail(domain, selector).then(function (body) {
    // A 200 response is a successful lookup, even if a newer one has since started.
    rememberLookup(selector
      ? { domain: domain, mode: MODE_EMAIL, type: 'MX', selector: selector }
      : { domain: domain, mode: MODE_EMAIL, type: 'MX' });
    if (requestId !== latestRequest) return;
    resultsBox.appendChild(renderEmailSection(body));
    statusLine.textContent = 'Checked email DNS for ' + domain + '.';
  }, function (err) {
    if (requestId !== latestRequest) return;
    showErrors([err.message]);
    statusLine.textContent = '';
  }).finally(function () {
    if (requestId === latestRequest) setBusy(false);
  });
}

function typesToRun(choice) {
  if (choice !== ALL_VALUE) return [choice];
  return Array.from(typeSelect.options)
    .map(function (option) { return option.value; })
    .filter(function (value) { return value !== ALL_VALUE && SKIP_IN_ALL.indexOf(value) === -1; });
}

function setBusy(busy) {
  submitButton.disabled = busy;
  if (busy) submitButton.setAttribute('aria-busy', 'true');
  else submitButton.removeAttribute('aria-busy');
}

// The chosen mode is remembered for the next visit. Storage can be blocked, so failures are ignored.
function readStoredMode() {
  try {
    const stored = window.localStorage.getItem(MODE_KEY);
    return stored === MODE_AUTHORITATIVE || stored === MODE_EMAIL ? stored : MODE_PUBLIC;
  } catch (_err) {
    return MODE_PUBLIC;
  }
}

function storeMode(mode) {
  try {
    window.localStorage.setItem(MODE_KEY, mode);
  } catch (_err) {
    // Not remembered this time; the page still works.
  }
}

function currentMode() {
  const value = modeSelect.value;
  if (value === MODE_AUTHORITATIVE || value === MODE_EMAIL) return value;
  return MODE_PUBLIC;
}

// The record type and DKIM selector fields only apply to some modes.
function applyModeLayout() {
  const email = currentMode() === MODE_EMAIL;
  typeField.hidden = email;
  selectorField.hidden = !email;
  presetBox.hidden = !email;
}

function onSubmit(event) {
  event.preventDefault();
  const domain = domainInput.value.trim();
  const mode = currentMode();
  const requestId = ++latestRequest;

  setBusy(true);
  clear(resultsBox);
  copyBuilders = [];
  showErrors([]);

  if (mode === MODE_EMAIL) {
    runEmailCheck(domain, selectorInput.value.trim(), requestId);
    return;
  }

  const choice = typeSelect.value;
  const types = typesToRun(choice);
  statusLine.textContent = mode === MODE_AUTHORITATIVE
    ? 'Querying authoritative nameservers for ' + domain + '...'
    : 'Looking up ' + domain + '...';

  // Each type is requested on its own. One failure does not hide the others.
  const jobs = types.map(function (type) {
    return lookup(domain, type, mode).then(
      function (body) { return { ok: true, body: body }; },
      function (err) { return { ok: false, error: err.message }; }
    );
  });

  Promise.all(jobs).then(function (outcomes) {
    // Any 200 response counts as a successful lookup, even if a newer one has since started.
    if (outcomes.some(function (outcome) { return outcome.ok; })) {
      rememberLookup({ domain: domain, mode: mode, type: choice });
    }
    if (requestId !== latestRequest) return;
    const errors = [];
    outcomes.forEach(function (outcome) {
      if (outcome.ok) {
        resultsBox.appendChild(mode === MODE_AUTHORITATIVE
          ? renderAuthoritativeSection(outcome.body)
          : renderSection(outcome.body));
      } else if (errors.indexOf(outcome.error) === -1) {
        errors.push(outcome.error);
      }
    });
    addCopyAll();
    showErrors(errors);
    const count = outcomes.length;
    const noun = 'record type' + (count === 1 ? '' : 's');
    if (count === 0) {
      statusLine.textContent = '';
    } else if (mode === MODE_AUTHORITATIVE) {
      statusLine.textContent = 'Checked ' + count + ' ' + noun + ' against authoritative nameservers for ' + domain + '.';
    } else {
      statusLine.textContent = 'Showing ' + count + ' ' + noun + ' for ' + domain + '.';
    }
  }).finally(function () {
    if (requestId === latestRequest) setBusy(false);
  });
}

modeSelect.value = readStoredMode();
applyModeLayout();
modeSelect.addEventListener('change', function () {
  storeMode(modeSelect.value);
  applyModeLayout();
});

// A preset fills the selector and submits straight away.
Array.from(presetBox.querySelectorAll('button[data-selector]')).forEach(function (button) {
  button.addEventListener('click', function () {
    selectorInput.value = button.getAttribute('data-selector');
    form.requestSubmit();
  });
});

recentClear.addEventListener('click', clearRecent);
renderRecent(readRecent() || []);

form.addEventListener('submit', onSubmit);
