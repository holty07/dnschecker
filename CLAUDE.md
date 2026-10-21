# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

## What this is

A private, self-hosted DNS lookup tool (a personal replacement for dnschecker.org). It runs as a
Node.js Project on SiteGround Cloud and deploys from GitHub. It compares answers from several
public resolvers, queries a domain's authoritative nameservers directly, and checks email DNS
(SPF, DKIM, DMARC, MX).

The full brief is in [`docs/PLAN.md`](docs/PLAN.md). Read it before starting any phase. If the
plan and this file disagree, this file wins (it records decisions made after the plan was written).

## Hard rules

- **Zero npm dependencies.** Use only Node built-ins (`node:http`, `node:dns`, `node:dgram`,
  `node:net`, `node:crypto`, `node:test`, `node:fs`, `node:path`). If a dependency seems justified,
  explain why in the PR description first. Do not add it without agreement.
- **Don't guess platform behaviour.** Anything about SiteGround that isn't confirmed (see "Open
  questions") is treated as unknown. Record what you find in `README.md`.
- **Australian spelling** in all user-facing text and docs: colour, behaviour, organisation,
  initialise, normalise, licence (noun).
- **Never reflect user input as HTML.** Render with `textContent`, never `innerHTML`.
- **Never log secrets.** Don't log the `Authorization` header, the password or `AUTH_PASSWORD`.
- **No server-side storage.** No database, no history, no user accounts.
- **Fact-check, don't assume.** Verify claims (in the plan, in review comments or in your own
  memory of an API) against docs or a quick experiment before relying on them.

## Workflow

- One phase per branch or PR, in order (see `docs/PLAN.md` section 4). Copy the phase's acceptance
  criteria into the PR description as a checklist and tick them off.
- Small, focused commits.
- Phase 0 is a **decision gate**. Stop after Phase 0 and report the `/api/selftest` output from the
  deployed SiteGround instance before starting Phase 1.
- Run `npm test` before every push. Tests must run offline.

## Commands

```sh
npm start          # node server.js (listens on $PORT, default 3000)
npm test           # node --test
AUTH_PASSWORD='at-least-12-chars' npm start   # once auth exists (Phase 1 onwards, see below)
```

There is no build step and no install step.

## Architecture

- `server.js`: `node:http` server. A small route table, JSON responses, and static files from
  `public/`.
- `lib/`: one module per concern (`validate`, `resolve`, `authoritative`, `email`, `spf`, `auth`,
  `ratelimit`). Keep modules pure where possible and pass I/O in as parameters (dependency
  injection) so tests can supply a fake resolver.
- `public/`: `index.html`, `app.js`, `style.css`. No framework and no bundler.
- `resolvers.json`: the resolver list. Edit it without touching code.
- `test/`: `node:test` files named `*.test.js`.

Every per-server result has this shape:

```js
{ server, status /* ok | nxdomain | nodata | timeout | error */, answers, ttl, ms, error? }
```

## Decisions and corrections to the plan

These came from reviewing `docs/PLAN.md` against Node's actual behaviour and the plan's own goals.

1. **`node:dns` can't force TCP, and returns TTLs only for A and AAAA.** `Resolver` (c-ares) has no
   TCP-only option, and `{ ttl: true }` is honoured only by `resolve4` and `resolve6`. It also
   doesn't expose the AA flag or raw RCODEs. Plan: Phase 0 includes a minimal DNS wire-format
   client (`lib/wire.js`: build a query, parse the answer section) over `node:dgram` (UDP) and
   `node:net` (TCP, 2-byte length prefix).
   **Phase 0 gate outcome (2026-10-20):** on SiteGround, outbound UDP 53 times out for every
   resolver, but TCP 53 works (all four resolvers answered in 5 to 13 ms). So **all DNS queries go
   over TCP via `lib/wire.js`**. Do not use `node:dns`: c-ares tries UDP first and only falls
   back to TCP on truncation, so every query would time out.
2. **Auth ships before any open query endpoint.** The plan puts auth in Phase 4, but every push to
   `main` redeploys, so `/api/lookup` would be public from Phase 1. That contradicts the
   "not exposed as an open query endpoint" goal. Basic auth (`lib/auth.js`) and the startup
   password check move into Phase 1. Every route except `/healthz` requires auth, including
   `/api/selftest`. Sign-in is a login form with a stateless HMAC-signed session cookie (password managers can't fill the native Basic prompt); Basic auth is still accepted for scripts.
3. **PTR needs IP input.** `validate.js` rejects IP literals, but PTR lookups take an IP. Accept an
   IPv4 or IPv6 literal **only** when `type=PTR`, and convert it to its `in-addr.arpa` or
   `ip6.arpa` name.
4. **Rate limiting behind a proxy.** SiteGround probably proxies requests, so `req.socket.remoteAddress`
   may be the proxy's address. Check whether `X-Forwarded-For` is set and trustworthy before keying
   the limiter on it.
5. **No outbound IPv6 on SiteGround** (observed 2026-10-21: every IPv6 nameserver address for
   immersemarketing.com.au was `unreachable` in authoritative mode). Keep reporting IPv6 addresses as
   `unreachable` and excluding them from the comparison; don't count them as disagreeing. A
   nameserver with only IPv6 addresses can't be checked from this host.
6. **TCP only.** Because queries use TCP, the 512-byte UDP limit and EDNS0 don't apply (TCP
   messages go up to 65,535 bytes). Keep UDP support in `lib/wire.js` and in `/api/selftest` so it
   is obvious if the platform ever opens UDP. Some authoritative nameservers may not answer over
   TCP (RFC 7766 requires them to); report those as `error`, not as disagreeing.
7. **SPF:** besides the 10-lookup limit, also report void lookups (RFC 7208 limit of 2).
8. **Repo name** is `dnschecker` (not `dns-checker` as in the plan). Files live at the repository
   root.

## Open questions (verify, then record the answer in README.md)

- Answered: SiteGround allows outbound TCP 53 but not UDP 53 (see decision 1). Note: the Claude
  Code cloud sandbox behaves differently (TCP 53 times out, UDP 53 is intercepted with fake
  NXDOMAIN answers), so real DNS behaviour can only be checked on the deployed instance.
- Answered: SiteGround sets `PORT` (seen as 64321); keep `process.env.PORT || 3000`. The request
  socket had no local port, so the listener is probably redirected to a Unix socket by a wrapper
  (unverified; the self-test now reports the listener address). SiteGround's Error Log shows nginx
  entries, not the app's console output, so `/api/selftest` also reports the Node version, the
  listening port and the `PORT` value under `runtime`.
- Answered: SiteGround runs Node 22.23.2; `engines` is `>=22`.
- What start command does it expect (`npm start` or `node server.js`)? Provide both: a `start`
  script that runs `node server.js`.
- Answered: `main` is the deploy branch, and every merge deploys straight to production.
