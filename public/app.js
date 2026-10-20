'use strict';

// Lookup page. Every element is built with createElement and textContent, so
// user input and resolver answers are never parsed as markup.

const ALL_VALUE = 'ALL';
// PTR takes an IP address, not a domain name, so "All common" leaves it out.
const SKIP_IN_ALL = ['PTR'];
const COLUMNS = ['Resolver', 'Server', 'Status', 'Answers', 'TTL', 'Time (ms)'];
const PARTICIPATING = ['ok', 'nodata', 'nxdomain'];

const form = document.getElementById('lookup-form');
const domainInput = document.getElementById('domain');
const typeSelect = document.getElementById('type');
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
  if (status === 'nodata' || status === 'nxdomain') return 'status-amber';
  return 'status-red';
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

function renderRow(row) {
  const tr = el('tr');
  if (row.differs === true) {
    tr.className = 'differs';
  } else if (row.differs === null && isParticipating(row)) {
    tr.className = 'no-majority';
  }

  tr.appendChild(el('td', null, row.resolver));
  tr.appendChild(el('td', 'mono server', row.server));

  let statusText = row.status;
  if (row.error) statusText += ' (' + row.error + ')';
  if (row.truncated) statusText += ' (truncated)';
  tr.appendChild(el('td', 'status ' + statusClass(row.status), statusText));

  const answers = el('td');
  renderAnswers(answers, row);
  tr.appendChild(answers);

  tr.appendChild(el('td', null, row.ttl === null || row.ttl === undefined ? '—' : row.ttl));
  tr.appendChild(el('td', null, row.ms));
  return tr;
}

// body is one /api/lookup response: { name, type, results, consensus, input }.
function renderSection(body) {
  const section = el('section', 'result-section');
  section.appendChild(el('h2', null, body.type + ' · ' + body.name));
  section.appendChild(el('p', 'consensus', consensusText(body.consensus)));

  const wrap = el('div', 'table-wrap');
  const table = el('table');

  const thead = el('thead');
  const headRow = el('tr');
  COLUMNS.forEach(function (name) {
    headRow.appendChild(el('th', null, name));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el('tbody');
  (body.results || []).forEach(function (row) {
    tbody.appendChild(renderRow(row));
  });
  table.appendChild(tbody);

  wrap.appendChild(table);
  section.appendChild(wrap);
  return section;
}

function lookup(domain, type) {
  const url = '/api/lookup?domain=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type);
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

function onSubmit(event) {
  event.preventDefault();
  const domain = domainInput.value.trim();
  const types = typesToRun(typeSelect.value);
  const requestId = ++latestRequest;

  setBusy(true);
  clear(resultsBox);
  showErrors([]);
  statusLine.textContent = 'Looking up ' + domain + '...';

  // Each type is requested on its own. One failure does not hide the others.
  const jobs = types.map(function (type) {
    return lookup(domain, type).then(
      function (body) { return { ok: true, body: body }; },
      function (err) { return { ok: false, error: err.message }; }
    );
  });

  Promise.all(jobs).then(function (outcomes) {
    if (requestId !== latestRequest) return;
    const errors = [];
    outcomes.forEach(function (outcome) {
      if (outcome.ok) {
        resultsBox.appendChild(renderSection(outcome.body));
      } else if (errors.indexOf(outcome.error) === -1) {
        errors.push(outcome.error);
      }
    });
    showErrors(errors);
    statusLine.textContent = outcomes.length === 0
      ? ''
      : 'Showing ' + outcomes.length + ' record type' + (outcomes.length === 1 ? '' : 's') + ' for ' + domain + '.';
  }).finally(function () {
    if (requestId === latestRequest) setBusy(false);
  });
}

form.addEventListener('submit', onSubmit);
