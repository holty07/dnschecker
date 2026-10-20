'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SERVER = path.join(__dirname, '..', 'server.js');

// Only PATH is passed through, so AUTH_PASSWORD is never inherited from the test runner.
function start(extraEnv = {}) {
  return spawnSync(process.execPath, [SERVER], {
    env: { PATH: process.env.PATH, ...extraEnv },
    encoding: 'utf8',
    timeout: 10000,
  });
}

test('server refuses to start without AUTH_PASSWORD', () => {
  const res = start();
  assert.equal(res.status, 1);
  assert.match(res.stderr, /AUTH_PASSWORD/);
});

test('server refuses to start with a short AUTH_PASSWORD', () => {
  const res = start({ AUTH_PASSWORD: 'too-short' });
  assert.equal(res.status, 1);
  assert.match(res.stderr, /AUTH_PASSWORD/);
  assert.ok(!res.stderr.includes('too-short'), 'stderr must not echo the password');
});
