'use strict';

// In-memory limiters. Nothing here uses timers: expired entries are pruned lazily
// on access, so the process can always exit and tests can drive a fake clock.

const MAX_KEY_LENGTH = 64;

// Fixed-window counter per key. A window starts at a key's first hit and lasts
// windowMs. peek() reads the state without counting a hit.
function createRateLimiter({ limit, windowMs, now = Date.now, maxKeys = 10000 } = {}) {
  if (!Number.isInteger(limit) || limit < 1) throw new TypeError('limit must be a positive integer');
  if (!(windowMs > 0)) throw new TypeError('windowMs must be positive');
  // Map iteration order is insertion order. A key is re-inserted when its window
  // restarts, so the first entries are always the oldest windows.
  const entries = new Map();

  function state(key, t) {
    const entry = entries.get(key);
    if (!entry) return null;
    if (t - entry.start >= windowMs) {
      entries.delete(key);
      return null;
    }
    return entry;
  }

  function result(entry, t) {
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.start + windowMs - t) / 1000));
    return {
      allowed: entry.count <= limit,
      remaining: Math.max(0, limit - entry.count),
      retryAfterSeconds,
    };
  }

  function evict(t) {
    if (entries.size <= maxKeys) return;
    for (const [key, entry] of entries) {
      if (t - entry.start >= windowMs) entries.delete(key);
    }
    // Still too many live keys: drop the oldest so memory stays bounded.
    for (const key of entries.keys()) {
      if (entries.size <= maxKeys) break;
      entries.delete(key);
    }
  }

  return {
    hit(key) {
      const t = now();
      let entry = state(key, t);
      if (!entry) {
        entry = { start: t, count: 0 };
        entries.set(key, entry);
        evict(t);
      }
      entry.count += 1;
      return result(entry, t);
    },
    peek(key) {
      const t = now();
      const entry = state(key, t);
      if (!entry) return { allowed: true, remaining: limit, retryAfterSeconds: 0 };
      // Blocked once the limit has been used up, without counting this check.
      const r = result(entry, t);
      return { ...r, allowed: entry.count < limit };
    },
    get size() {
      return entries.size;
    },
  };
}

// Rejects excess work. release() is idempotent, so it is safe in a finally.
function createConcurrencyLimiter(max) {
  if (!Number.isInteger(max) || max < 1) throw new TypeError('max must be a positive integer');
  let active = 0;
  return {
    tryAcquire() {
      if (active >= max) return null;
      active += 1;
      let released = false;
      return function release() {
        if (released) return;
        released = true;
        active -= 1;
      };
    },
    get active() {
      return active;
    },
  };
}

// Runs at most max functions at once. The rest wait in FIFO order.
function createSemaphore(max) {
  if (!Number.isInteger(max) || max < 1) throw new TypeError('max must be a positive integer');
  let active = 0;
  const waiting = [];

  function next() {
    if (active >= max || waiting.length === 0) return;
    active += 1;
    const { fn, resolve, reject } = waiting.shift();
    let p;
    try {
      p = Promise.resolve(fn());
    } catch (err) {
      p = Promise.reject(err);
    }
    p.then(resolve, reject).finally(() => {
      active -= 1;
      next();
    });
  }

  return {
    run(fn) {
      return new Promise((resolve, reject) => {
        waiting.push({ fn, resolve, reject });
        next();
      });
    },
    get active() {
      return active;
    },
    get queued() {
      return waiting.length;
    },
  };
}

// The key a client is limited by. Behind nginx the socket address may be missing
// (Unix socket) or be the proxy itself, so the forwarding headers come first.
function clientKey(req) {
  const headers = (req && req.headers) || {};
  const xff = headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    // Use the LAST entry. Each proxy appends the address it saw, so the nearest
    // proxy (ours) wrote the final entry. Earlier entries are whatever the client
    // chose to send, so using the first would let anyone dodge the limiter by
    // inventing a new address on every request.
    const parts = xff.split(',');
    const last = parts[parts.length - 1].trim();
    if (last) return last.slice(0, MAX_KEY_LENGTH);
  }
  const realIp = headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) return realIp.trim().slice(0, MAX_KEY_LENGTH);
  const remote = req && req.socket && req.socket.remoteAddress;
  if (remote) return String(remote).slice(0, MAX_KEY_LENGTH);
  return 'unknown';
}

module.exports = { createRateLimiter, createConcurrencyLimiter, createSemaphore, clientKey };
