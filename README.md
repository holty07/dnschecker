# DNS Checker

A private, self-hosted DNS lookup tool, a personal replacement for dnschecker.org. It compares answers from several public resolvers, queries a domain's authoritative nameservers directly, and checks email DNS (SPF, DKIM, DMARC, MX).

It runs as a Node.js Project on SiteGround Cloud and deploys from GitHub. It has zero npm dependencies and uses only Node built-ins.

The full brief is in [docs/PLAN.md](docs/PLAN.md). Project rules are in [CLAUDE.md](CLAUDE.md).

**Status:** Phases 1 to 4 are built: resolver comparison, authoritative checks, the email DNS panel, and rate limiting and hardening. Phase 5 (polish) is next.

Endpoints (all need sign-in, by session cookie or HTTP Basic auth, except `/healthz`):

- `/` is the lookup page. Enter a domain or IP and choose a record type, or "All common" for every common type at once.
- `GET /api/lookup?domain=&type=` returns the per-resolver results and the consensus as JSON.
- `GET /api/authoritative?domain=&type=` finds the zone, queries each of its nameservers directly over TCP (at most 8 nameservers and 16 addresses, public addresses only) and returns their answers, SOA serials and warnings. It returns 422 if no zone is found and 502 if the public resolvers can't be reached.
- `GET /api/email?domain=&selector=` checks SPF (lookup count, void lookups, include tree), DMARC (policy in plain English), MX (with null MX and CNAME checks) and, if a selector is given, DKIM (key type and size). Selectors may contain dots.
- `/selftest.html` and `GET /api/selftest` are the Phase 0 reachability check.
- `/healthz` returns `ok` and needs no auth.

## Authentication

Every route except `/healthz` and the sign-in page needs authentication. Open the site and you are sent to a sign-in form (username `admin`, password from the `AUTH_PASSWORD` environment variable), so password managers can fill it. A successful sign-in sets a session cookie that lasts 30 days. Use the "Sign out" button in the page header to end it sooner.

- `AUTH_PASSWORD` is **required**. The server refuses to start if it is unset or shorter than 12 characters, and logs the reason to stderr.
- **Session cookie:** `dnschecker_session` is `HttpOnly`, `Secure` and `SameSite=Strict`. It is signed with a key derived from `AUTH_PASSWORD`, and nothing is stored on the server, so sessions survive restarts. **Changing `AUTH_PASSWORD` signs everyone out.** There is no way to revoke a single session before it expires, other than changing the password.
- **Scripts and curl:** HTTP Basic auth (`curl -u admin:... https://host/api/lookup?...`) still works on every route. The server never sends a `WWW-Authenticate` header, so browsers show the form rather than the native prompt. Unauthenticated API calls get `401` JSON; unauthenticated page requests get a redirect to `/login.html`.
- **Login form checks:** the form accepts only small `application/x-www-form-urlencoded` bodies, refuses a request whose `Origin` host differs from its `Host` header, and only redirects to a same-site path after sign-in.
- Use a long random password. The limits below apply to the form as well as to Basic auth.

## Limits and hardening

| Limit | Default |
|---|---|
| Failed sign-ins (wrong password on the form or in a Basic header) | 20 per 15 minutes per client, then 429 |
| API requests | 60 per minute per client (page files are not counted) |
| Lookups in progress | 10 per client, 20 in total, then 429 |
| Outbound DNS connections | 64 at once (extra queries wait) |

- **Client address:** a client is identified by the last `X-Forwarded-For` entry, then `X-Real-IP`, then the socket address. The last `X-Forwarded-For` entry is the one the nearest proxy added; earlier entries come from the client and can be faked.
- **Unknown clients:** if none of these is available, all requests share one key. The sign-in lockout is then switched off, so that bots can't lock out the real user. The password length makes guessing impractical anyway.
- **Response headers:** every response sends a strict Content Security Policy, HSTS, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` and a Permissions Policy. API, 401 and 429 responses are `no-store`.
- **Request log:** one line per request, with a salted 8-character client tag in place of the IP address.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `AUTH_PASSWORD` | yes | Password for user `admin`. At least 12 characters. |
| `LOOKUP_TIMEOUT_MS` | no | Per-resolver query timeout in milliseconds. Default 3000. |
| `PORT` | no | Listening port. SiteGround sets this itself, so don't set it there. |

See `.env.example`.

## Running locally

Developed on Node 22. `engines` requires Node 22 or later.

```sh
AUTH_PASSWORD='at-least-12-chars' npm start   # node server.js, listens on $PORT (default 3000)
npm test                                      # node --test, runs offline
```

There is no install step and no build step.

## Deployment

Condensed from [docs/PLAN.md](docs/PLAN.md) section 6.

1. Create the GitHub repository `dnschecker`. `main` is the deploy branch.
2. In the SiteGround Client Area, create a Node.js Project and connect the repository and the `main` branch. Confirm the menu path in the SiteGround KB article "What is a Node.js Project?".
3. In Site Tools > Node.js, set the Node version to 22 (the build log shows 22.23.2), package manager to npm, no build command, and start command `npm start` (or `node server.js`).
4. Add `AUTH_PASSWORD` (and optionally `LOOKUP_TIMEOUT_MS`) as environment variables. Where SiteGround takes them is unverified: check the Node.js project settings and record the menu path here.
5. Point a dedicated subdomain at the project. Do not host it inside a client website.
6. Confirm HTTPS is active.
7. Load `/healthz`, then sign in at `/` and run `/selftest.html`.
8. If something fails, check Site Tools > Node.js > Logs (build) and Statistics > Error Log (runtime).

Every push to `main` is a production deploy. Merge only what has passed `npm test`.

## Platform findings

Items still marked unverified need confirming. Record the answer here once checked against SiteGround's documentation or a deployed instance.

- **Outbound UDP and TCP port 53.** **Confirmed 2026-10-20 from the deployed `/api/selftest`:** TCP 53 works and UDP 53 does not. Every resolver timed out over UDP after 3 seconds, and every resolver answered over TCP in 5 to 13 ms. The tool therefore queries over TCP only. (For comparison, the Claude Code sandbox times out on TCP 53 and fakes NXDOMAIN answers on UDP 53, so test DNS behaviour on the deployed instance.)
- **Node version.** **Confirmed from the build log: SiteGround runs Node 22.23.2.** `engines` is `>=22`.
- **Build steps.** **Confirmed from the build log:** the build deletes `package-lock.json` and then runs `npm install`. This project has no dependencies, so the install is a no-op.
- **Deploy branch.** **Confirmed: `main` is the deploy branch.** Each build deploys straight to production, with no staging step.
- **Listening port.** **Confirmed 2026-10-20 from the deployed self-test:** SiteGround sets `PORT` (it was `64321`), and the server listens on it. Don't set `PORT` yourself. The incoming connection had no local port, which in Node only happens on a Unix socket, so SiteGround probably wraps the app and redirects its listener. That is unverified: `/selftest.html` now shows the actual listener address.
- **Logs.** Statistics > Error Log shows nginx entries, not the app's console output. Use `/selftest.html` for runtime details.
- **Start command.** Does the platform expect `npm start` or `node server.js`? Status: unverified – to confirm on deploy. A `start` script runs `node server.js`, so either works if the platform accepts it.
- **Outbound IPv6.** **Observed 2026-10-21:** in authoritative mode, every IPv6 nameserver address for immersemarketing.com.au showed as unreachable, while IPv4 worked. SiteGround appears to have no outbound IPv6, so IPv6 addresses are shown as unreachable and left out of the comparison. A nameserver with only IPv6 addresses can't be checked from this host.
- **Behind a proxy.** **Confirmed 2026-10-21 from `/selftest.html`:** the socket address is empty (Unix socket), `X-Forwarded-For` arrives with two entries (both the client's IP, which suggests two proxy layers) and `X-Real-IP` matches. The limiter uses the last `X-Forwarded-For` entry, so per-client limits and the sign-in lockout identify clients correctly. Not yet checked: whether a client-supplied `X-Forwarded-For` is overwritten or appended to. The last-entry rule is correct as long as the nearest proxy appends.

### Phase 0 self-test results (2026-10-20)

| Resolver | UDP | TCP | TCP answers | TTL | TCP ms |
|---|---|---|---|---|---|
| Google 8.8.8.8 | timeout | ok | 172.66.147.243, 104.20.23.154 | 300 | 12.8 |
| Cloudflare 1.1.1.1 | timeout | ok | 104.20.23.154, 172.66.147.243 | 245 | 7.8 |
| Quad9 9.9.9.9 | timeout | ok | 104.20.23.154, 172.66.147.243 | 83 | 5.9 |
| OpenDNS 208.67.222.222 | timeout | ok | 104.20.23.154, 172.66.147.243 | 249 | 5.2 |

Summary: UDP 0 of 4 reachable, TCP 4 of 4 reachable, no interception warnings.
