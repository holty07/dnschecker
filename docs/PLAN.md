# DNS Checker: Build Plan

A private, self-hosted DNS lookup tool. It runs as a Node.js Project on SiteGround (Cloud plan), deploys from GitHub, and replaces the need for dnschecker.org for day-to-day propagation checks.

This document is the brief for a Claude Code session. Work through the phases in order and stop at the decision gate in Phase 0.

---

## 1. Goals and non-goals

**Goals**

- Look up A, AAAA, CNAME, MX, NS, TXT, SOA, CAA and PTR records for any domain.
- Compare answers from several public resolvers side by side, with TTLs, and highlight mismatches.
- Query a domain's **authoritative nameservers directly** and flag any that disagree (the real propagation check).
- Email DNS panel: SPF (including lookup count), DKIM (given a selector) and DMARC.
- Private: password protected, on its own subdomain, not exposed as an open query endpoint.

**Non-goals**

- Geographic diversity. Public resolvers such as 8.8.8.8 and 1.1.1.1 are anycast, so every query is answered by the nearest node to the SiteGround server. This tool offers resolver diversity, not location diversity. State this plainly in the UI footer.
- A database, user accounts, or history stored server-side.

---

## 2. Verified facts and open questions

**Confirmed from SiteGround's own documentation**

- Node.js Projects are available on GrowBig, GoGeek and Cloud (StartUp is not supported). Cloud allows an unlimited number of projects.
- Deployment is either a connected GitHub repository and branch (every push to that branch redeploys) or a ZIP upload.
- Node version, package manager, build command, output directory and environment variables are configured in Site Tools > Node.js.
- Build logs are in Site Tools > Node.js > Logs. Runtime errors are in Site Tools > Statistics > Error Log. Runtime logs are not available over SSH.

**Not yet confirmed (verify, do not assume)**

1. Whether a Node project can make **outbound UDP and TCP DNS queries on port 53** to arbitrary servers. Phase 0 exists to answer this.
2. How the platform tells the app which **port** to listen on. Read the SiteGround Node.js KB articles before writing the listener. Until confirmed, use `process.env.PORT` with a fallback of `3000` and log the value at startup.
3. Which **Node versions** Site Tools offers. Pin `engines` in `package.json` to a version that is actually selectable.

---

## 3. Architecture

- **Runtime:** Node.js, **zero npm dependencies**. Use only built-ins: `node:http`, `node:dns`, `node:test`, `node:crypto`, `node:net`. This removes install and build failures from the deploy path.
- **DNS engine:** `dns.Resolver` with `setServers()`. Create a new resolver per target server, with explicit `timeout` and `tries` options. Use `{ ttl: true }` where supported so TTLs are returned.
- **Frontend:** one static HTML page, one JS file, one CSS file in `public/`, served by the same server. No framework, no build step.
- **Auth:** HTTP Basic auth against a password held in an environment variable. Constant-time comparison.
- **Config:** resolver list in `resolvers.json` so it can be edited without touching code.

### Repository layout

```
dns-checker/
├── PLAN.md
├── README.md
├── package.json
├── server.js
├── resolvers.json
├── .env.example
├── lib/
│   ├── auth.js          # basic auth + constant-time compare
│   ├── resolve.js       # resolver wrapper, per-query timeouts, normalisation
│   ├── authoritative.js # NS discovery + direct nameserver queries
│   ├── email.js         # SPF / DKIM / DMARC checks
│   ├── spf.js           # SPF parser + DNS lookup counter
│   ├── validate.js      # domain validation, private-range filtering
│   └── ratelimit.js     # simple in-memory limiter
├── public/
│   ├── index.html
│   ├── app.js
│   └── style.css
└── test/
    ├── validate.test.js
    ├── spf.test.js
    └── resolve.test.js
```

### API (all routes behind auth except `/healthz`)

| Route | Purpose |
|---|---|
| `GET /healthz` | Returns `ok`. No auth. For uptime monitoring. |
| `GET /api/selftest` | Tries a fixed query against each configured resolver over UDP and TCP and reports reachability. |
| `GET /api/lookup?domain=&type=` | Queries every configured resolver for one record type. |
| `GET /api/authoritative?domain=&type=` | Finds the domain's nameservers, queries each directly, reports agreement. |
| `GET /api/email?domain=&selector=` | SPF, DMARC, and DKIM (if a selector is given). |

All responses are JSON. Every per-server result includes: server, status (`ok`, `nxdomain`, `nodata`, `timeout`, `error`), answers, TTL, and response time in milliseconds.

---

## 4. Phases

### Phase 0: Reachability spike (decision gate)

**Purpose:** prove outbound DNS works from a SiteGround Node project before building anything else.

1. Create the GitHub repo and a minimal `server.js` that serves `/healthz` and `/api/selftest`.
2. `selftest` queries `example.com` (A record) against 8.8.8.8, 1.1.1.1, 9.9.9.9 and 208.67.222.222, over **UDP and TCP separately** (use `resolver.setServers` plus a TCP-forced query where possible, otherwise report what the platform allows and note the limitation).
3. Deploy to SiteGround (see section 6) and load `/api/selftest`.

**Decision gate**

- **UDP/TCP 53 works:** continue to Phase 1 as written.
- **Blocked:** stop and report back. Fallback options, in order of preference:
  1. DNS-over-HTTPS from the server (`fetch` to `dns.google/resolve` and `cloudflare-dns.com/dns-query`). Works over port 443, but no direct authoritative queries.
  2. Move the backend to a Cloudflare Worker (TCP port 53 via `connect()`, noting that Cloudflare IP ranges are blocked, so 1.1.1.1 and Cloudflare-hosted nameservers would need DoH from the browser).

**Acceptance:** `selftest` output shows reachability per resolver and per protocol, visible in the browser.

### Phase 1: Core lookup

- `lib/validate.js`: accept only valid hostnames (labels 1 to 63 characters, total 253 maximum, letters/digits/hyphens, optional trailing dot, punycode allowed). Reject IP literals and anything with whitespace or control characters.
- `lib/resolve.js`: one function that takes a resolver address, domain and type, and returns the normalised result shape described above. Handle `ENOTFOUND`, `ENODATA`, `ETIMEOUT` and `ESERVFAIL` explicitly.
- TXT answers arrive as arrays of chunks. Join each record's chunks into one string.
- `/api/lookup` queries all resolvers **in parallel** with a per-query timeout (default 3 seconds, configurable).
- Frontend: domain field, record-type selector (including "All common"), results grid with resolvers as rows. Rows that differ from the majority answer are highlighted. Show TTL and response time.

**Acceptance:** looking up a known domain returns consistent results across resolvers, and a deliberately mismatched case (temporarily changed record) shows highlighted differences.

### Phase 2: Authoritative checks

- `lib/authoritative.js`: resolve the domain's NS records (walk up to the parent zone if the name is a subdomain without its own NS), resolve each nameserver's A and AAAA, then query each directly for the requested type.
- For SOA, compare **serial numbers** across nameservers and flag any that differ. This is the clearest indicator of an unsynchronised zone.
- Compare answer sets across nameservers and report "all agree" or list the outliers.
- **Safety:** before querying any nameserver IP, reject private, loopback, link-local and other reserved ranges (IPv4 and IPv6). Cap the number of nameservers queried per request (for example 8). This prevents the tool being used to probe internal networks.

**Acceptance:** a domain with split or lagging nameservers is flagged correctly. A normal domain reports full agreement.

### Phase 3: Email DNS panel

- **SPF:** find the `v=spf1` TXT record, flag multiple SPF records (an error), and count DNS-lookup mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`), following includes recursively. Warn when the count exceeds 10. Flag `+all`, `?all` and `ptr` usage.
- **DMARC:** query `_dmarc.<domain>`, parse tags (`p`, `sp`, `rua`, `ruf`, `pct`, `adkim`, `aspf`) and summarise the policy in plain English.
- **DKIM:** given a selector, query `<selector>._domainkey.<domain>` (TXT, then CNAME if needed) and report whether a public key is present. Offer a short list of common selectors to try (`default`, `google`, `selector1`, `selector2`, `k1`, `s1`, `s2`) as quick buttons.
- **MX:** list and sort by priority, and check each MX host resolves.

**Acceptance:** unit tests for the SPF lookup counter cover nested includes, circular includes and the 10-lookup boundary. Panel renders for a domain with and without each record.

### Phase 4: Security and hardening

- `lib/auth.js`: HTTP Basic auth, username fixed (for example `admin`), password from `AUTH_PASSWORD`. Compare with `crypto.timingSafeEqual` on equal-length buffers. Refuse to start if `AUTH_PASSWORD` is unset or shorter than 12 characters.
- `lib/ratelimit.js`: in-memory limiter per client address (for example 60 requests per minute). Cap concurrent in-flight lookups.
- Security headers on every response: `Content-Security-Policy` (self only), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- Never reflect raw user input into HTML. Render results with `textContent`, not `innerHTML`.
- Log request outcome and duration only. Do not log the password or the Authorization header.

**Acceptance:** requests without credentials return 401. Invalid domains return 400 with a clear message. The server will not start without a strong password.

### Phase 5: Polish

- Copy results as plain text (useful for pasting into client tickets).
- Recent lookups list in the browser's `localStorage` (client side only, wrapped in try/catch).
- Light and dark mode via `prefers-color-scheme`.
- Footer note on the anycast limitation.
- `README.md` covering setup, environment variables, deployment and troubleshooting.

---

## 5. Testing

- Use `node:test`, run with `node --test`. No test framework dependency.
- Unit tests: domain validation (including hostile inputs), SPF parser and counter, private-range filter, result normalisation.
- Resolver tests should use dependency injection (pass in a fake resolver) so tests run offline.
- Manual checklist before each release: lookup, authoritative check, email panel, 401 without credentials, 400 on bad input.

---

## 6. Deployment (SiteGround Cloud)

1. Create a GitHub repository (suggested name: `dns-checker`) and push to `main`.
2. In the SiteGround Client Area, create a new **Node.js Project** and connect the repository and the `main` branch. Confirm the exact menu path in the SiteGround KB article "What is a Node.js Project?" as the interface is new.
3. In Site Tools > Node.js, set:
   - Node version (matching `engines`)
   - Package manager: npm
   - Build command: none required (zero dependencies), or `npm install` if the platform insists
   - Start command: `node server.js` (confirm how the platform expects this to be specified)
   - Environment variables: `AUTH_PASSWORD` (required), `PORT` only if the platform does not inject it
4. Point a **dedicated subdomain** at the project. Do not host it inside a client website.
5. Confirm HTTPS is active before using the password.
6. Load `/healthz`, then `/api/selftest` and review the Phase 0 outcome.
7. If something fails, check Site Tools > Node.js > Logs (build) and Statistics > Error Log (runtime).

---

## 7. Notes for the Claude Code session

- **Do not guess platform behaviour.** Where section 2 lists an open question, read SiteGround's KB and note what you found in `README.md`.
- Keep it dependency-free. If you believe a dependency is justified, explain why in the PR description first.
- Use Australian spelling in all user-facing text and documentation (colour, behaviour, organisation, initialise).
- Work in small commits, one phase per branch or PR, with the acceptance criteria copied into the PR description and ticked off.
- Report back after Phase 0 with the self-test output before starting Phase 1.
