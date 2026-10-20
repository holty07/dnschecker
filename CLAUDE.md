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
   `node:net` (TCP, 2-byte length prefix). If it works on SiteGround, Phases 1 and 2 may use it
   instead of `node:dns`, so every record type gets a TTL and authoritative answers can be checked
   for the AA flag. Decide this at the Phase 0 gate.
2. **Auth ships before any open query endpoint.** The plan puts auth in Phase 4, but every push to
   `main` redeploys, so `/api/lookup` would be public from Phase 1. That contradicts the
   "not exposed as an open query endpoint" goal. Basic auth (`lib/auth.js`) and the startup
   password check move into Phase 1. Phase 0's `/api/selftest` only queries fixed targets, so it can
   stay unauthenticated.
3. **PTR needs IP input.** `validate.js` rejects IP literals, but PTR lookups take an IP. Accept an
   IPv4 or IPv6 literal **only** when `type=PTR`, and convert it to its `in-addr.arpa` or
   `ip6.arpa` name.
4. **Rate limiting behind a proxy.** SiteGround probably proxies requests, so `req.socket.remoteAddress`
   may be the proxy's address. Check whether `X-Forwarded-For` is set and trustworthy before keying
   the limiter on it.
5. **IPv6 reachability is unknown.** If the server has no outbound IPv6, report AAAA-only
   nameservers as `unreachable`. Don't count them as disagreeing.
6. **SPF:** besides the 10-lookup limit, also report void lookups (RFC 7208 limit of 2).
7. **Repo name** is `dnschecker` (not `dns-checker` as in the plan). Files live at the repository
   root.

## Open questions (verify, then record the answer in README.md)

- Can a SiteGround Node project make outbound UDP and TCP queries on port 53? (Phase 0 answers this.)
  Note: the Claude Code cloud sandbox blocks outbound port 53, so this can't be tested from a
  session. Only the deployed instance can answer it.
- How does SiteGround tell the app which port to listen on? Until confirmed, use
  `process.env.PORT || 3000` and log the value at startup.
- Which Node versions can be selected in Site Tools? Set `engines` to match. Local development uses
  Node 22.
- What start command does it expect (`npm start` or `node server.js`)? Provide both: a `start`
  script that runs `node server.js`.
- Which branch deploys? The plan says `main`. Work happens on feature branches, so `main` must exist
  and be the deploy branch.
