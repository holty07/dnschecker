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
const MODE_KEY = 'dnschecker.mode';

const form = document.getElementById('lookup-form');
const domainInput = document.getElementById('domain');
const typeSelect = document.getElementById('type');
const modeSelect = document.getElementById('mode');
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

function lookup(domain, type, mode) {
  const path = mode === MODE_AUTHORITATIVE ? '/api/authoritative' : '/api/lookup';
  const url = path + '?domain=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type);
  return fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (body) {
      if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
      return body;
    });
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
    return window.localStorage.getItem(MODE_KEY) === MODE_AUTHORITATIVE ? MODE_AUTHORITATIVE : MODE_PUBLIC;
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

function onSubmit(event) {
  event.preventDefault();
  const domain = domainInput.value.trim();
  const mode = modeSelect.value === MODE_AUTHORITATIVE ? MODE_AUTHORITATIVE : MODE_PUBLIC;
  const types = typesToRun(typeSelect.value);
  const requestId = ++latestRequest;

  setBusy(true);
  clear(resultsBox);
  showErrors([]);
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
modeSelect.addEventListener('change', function () { storeMode(modeSelect.value); });
form.addEventListener('submit', onSubmit);
