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

// Each submit gets a number. A slow earlier request must not overwrite a newer one.
let latestRequest = 0;

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

// body is one /api/lookup response: { name, type, results, consensus, input }.
function renderSection(body) {
  const section = el('section', 'result-section');
  section.appendChild(el('h2', null, body.type + ' · ' + body.name));
  section.appendChild(el('p', 'consensus', consensusText(body.consensus)));
  appendTable(section, COLUMNS, (body.results || []).map(renderRow));
  return section;
}

// body is one /api/authoritative response: { name, type, zone, nameservers, results, consensus, serials, warnings }.
function renderAuthoritativeSection(body) {
  const section = el('section', 'result-section');
  const heading = body.zone ? body.type + ' · ' + body.name + ' — zone ' + body.zone : body.type + ' · ' + body.name;
  section.appendChild(el('h2', null, heading));
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
  const section = el('section', 'result-section');
  section.appendChild(el('h2', null, 'Email DNS · ' + (body.domain || body.input || '')));
  const cards = el('div', 'email-cards');
  cards.appendChild(mxCard(body.mx || {}));
  cards.appendChild(spfCard(body.spf || {}));
  cards.appendChild(dmarcCard(body.dmarc || {}));
  cards.appendChild(dkimCard(body.dkim));
  section.appendChild(cards);
  return section;
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
  showErrors([]);

  if (mode === MODE_EMAIL) {
    runEmailCheck(domain, selectorInput.value.trim(), requestId);
    return;
  }

  const types = typesToRun(typeSelect.value);
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

form.addEventListener('submit', onSubmit);
