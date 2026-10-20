'use strict';

// Phase 0 self-test page. Every element is built with createElement and
// textContent. Never use innerHTML here: the CSP and the output rules forbid it.

const COLUMNS = ['Resolver', 'Server', 'Transport', 'Status', 'Answers', 'TTL', 'ms'];

const button = document.getElementById('run');
const statusLine = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const resultsBox = document.getElementById('results');

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

function formatAnswers(answers) {
  return Array.isArray(answers) && answers.length > 0 ? answers.join(', ') : '—';
}

function renderSummary(summary) {
  clear(summaryBox);
  Object.keys(summary || {}).forEach(function (transport) {
    const s = summary[transport];
    summaryBox.appendChild(
      el('p', 'summary-item', transport.toUpperCase() + ': ' + s.reachable + ' of ' + s.total + ' reachable')
    );
  });
}

function renderWarnings(warnings) {
  (warnings || []).forEach(function (w) {
    summaryBox.appendChild(el('p', 'warning', w));
  });
}

function renderTable(results) {
  clear(resultsBox);
  const table = el('table');

  const thead = el('thead');
  const headRow = el('tr');
  COLUMNS.forEach(function (name) {
    headRow.appendChild(el('th', null, name));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el('tbody');
  (results || []).forEach(function (r) {
    const row = el('tr');
    row.appendChild(el('td', null, r.resolver));
    row.appendChild(el('td', 'mono', r.server));
    row.appendChild(el('td', null, r.transport));
    row.appendChild(el('td', 'status ' + statusClass(r.status), r.status + (r.error ? ' (' + r.error + ')' : '')));
    row.appendChild(el('td', 'mono', formatAnswers(r.answers)));
    row.appendChild(el('td', null, r.ttl === null || r.ttl === undefined ? '—' : r.ttl));
    row.appendChild(el('td', null, r.ms));
    tbody.appendChild(row);
  });
  table.appendChild(tbody);
  resultsBox.appendChild(table);
}

function renderRuntime(runtime) {
  if (!runtime) return;
  const lines = [
    'Node ' + runtime.node + ', listening on port ' + runtime.listeningPort +
      (runtime.portEnv === null ? ' (PORT not set, using the default)' : ' (PORT=' + runtime.portEnv + ')'),
  ];
  lines.forEach(function (text) {
    summaryBox.appendChild(el('p', 'summary-item', text));
  });
}

function render(body) {
  renderSummary(body.summary);
  renderWarnings(body.warnings);
  renderTable(body.results);
  renderRuntime(body.runtime);
  statusLine.textContent = 'Started ' + body.startedAt + ' for ' + body.target + ' (' + body.type + ').';
}

function run() {
  button.disabled = true;
  statusLine.textContent = 'Running...';
  clear(summaryBox);
  clear(resultsBox);

  fetch('/api/selftest', { cache: 'no-store', headers: { Accept: 'application/json' } })
    .then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        if (!res.ok) throw new Error(body.error || 'HTTP ' + res.status);
        return body;
      });
    })
    .then(render)
    .catch(function (err) {
      statusLine.textContent = 'Self-test failed: ' + err.message;
    })
    .then(function () {
      button.disabled = false;
    });
}

button.addEventListener('click', run);
