# DNS Checker

A private, self-hosted DNS lookup tool, a personal replacement for dnschecker.org. It compares answers from several public resolvers, queries a domain's authoritative nameservers directly, and checks email DNS (SPF, DKIM, DMARC, MX).

It runs as a Node.js Project on SiteGround Cloud and deploys from GitHub. It has zero npm dependencies and uses only Node built-ins.

The original brief is in [docs/PLAN.md](docs/PLAN.md). Project rules, and the decisions that changed the plan, are in [CLAUDE.md](CLAUDE.md).

## Using it

Sign in at the site's address with username `admin` and the `AUTH_PASSWORD` password. The form works with password managers.

Pick what to check against:

- **Public resolvers.** Asks Google, Cloudflare, Quad9 and OpenDNS for one record type, or "All common" types at once. Rows that differ from the majority answer are highlighted. TTLs are shown but ignored when comparing, because caches naturally differ. For PTR, enter an IP address.
- **Authoritative nameservers.** Finds the zone (walking up from subdomains), then asks each of its nameservers directly. Each row shows that nameserver's answer and its SOA serial. Differing serials mean the zone hasn't synchronised. This is the real propagation check: public resolvers can serve cached answers until the TTL expires, but the nameservers show what is published right now.
- **Email (SPF, DMARC, DKIM, MX).** One card per check with a Pass, Warning or Fail badge. SPF shows its DNS lookup count against the limit of 10 and a collapsible include tree. DKIM needs a selector: type one, or click a common one.

Under each result, **Copy as text** copies a plain-text version for pasting into a ticket. **Recent** lists your last 10 lookups. They are stored only in your browser, and **Clear** removes them.

**What this tool can't tell you:** the public resolvers are anycast, so every query is answered by the node nearest the SiteGround server. This gives resolver diversity, not the location diversity of dnschecker.org. For "has my change reached everywhere?", use authoritative mode. If every nameserver has the new serial and answer, the rest is caches expiring by TTL.

## API

All routes need sign-in, by session cookie or HTTP Basic auth, except `/healthz` and the sign-in page. Responses are JSON.

| Route | Purpose |
|---|---|
| `GET /healthz` | Returns `ok`. No sign-in. For uptime monitoring. |
| `GET /api/lookup?domain=&type=` | Every public resolver for one record type, with the majority answer and which rows differ. |
| `GET /api/authoritative?domain=&type=` | The zone's nameservers queried directly: answers, SOA serials and warnings. 422 if no zone is found, 502 if the public resolvers can't be reached. |
| `GET /api/email?domain=&selector=` | SPF, DMARC, MX, and DKIM if a selector is given (selectors may contain dots). |
| `GET /api/selftest` | Checks UDP and TCP reachability of each resolver, plus runtime details (Node version, listener, client address seen). The page is `/selftest.html`. |

Record types are A, AAAA, CNAME, MX, NS, TXT, SOA, CAA and PTR. Invalid input returns 400 with a message.

For scripts:

```sh
curl -s -u admin:YOUR_PASSWORD 'https://dnschecker.immersemarketing.com.au/api/lookup?domain=example.com&type=MX'
```

## Authentication

- **`AUTH_PASSWORD` is required.** The server refuses to start if it is unset or shorter than 12 characters. Use a long random password.
- **Sign-in form:** a successful sign-in sets the `dnschecker_session` cookie, which lasts 30 days.
  - **Cookie attributes:** `HttpOnly`, `Secure` and `SameSite=Strict`.
  - **Signing:** it is signed with a key derived from `AUTH_PASSWORD`, and nothing is stored on the server, so sessions survive redeploys.
  - **Signing out:** "Sign out" clears your browser's copy. **Changing `AUTH_PASSWORD` signs everyone out**, and is the only way to revoke a session early.
- **Basic auth** still works for scripts. The server never sends `WWW-Authenticate`, so browsers show the form, not the native prompt.
  - Unauthenticated API calls get 401 JSON.
  - Unauthenticated page requests are redirected to `/login.html`.
- **Sign-in form checks:**
  - Only small `application/x-www-form-urlencoded` bodies are accepted.
  - Cross-site posts are refused. `Sec-Fetch-Site` must be `same-origin`, falling back to an `Origin` check for clients that don't send it.
  - After sign-in, the redirect only goes to a path on this site.

## Limits and hardening

| Limit | Default |
|---|---|
| Failed sign-ins (a wrong password on the form or in a Basic header) | 20 per 15 minutes per client, then 429 |
| API requests | 60 per minute per client (page files are not counted) |
| Lookups in progress | 10 per client, 20 in total, then 429 |
| Outbound DNS connections | 64 at once (extra queries wait) |
| Authoritative checks | At most 8 nameservers and 16 addresses per request; private and reserved addresses are never queried |

- **Client address:** a client is identified by the last `X-Forwarded-For` entry, then `X-Real-IP`, then the socket address. The last `X-Forwarded-For` entry is the one the nearest proxy added; earlier entries come from the client and can be faked.
- **Unknown clients:** if none of these is available, all requests share one key. The sign-in lockout is then switched off, so that bots can't lock out the real user.
- **Response headers:** every response sends a strict Content Security Policy, HSTS, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` and a Permissions Policy. API, sign-in, 401 and 429 responses are `no-store`.
- **Request log:** one line per request (method, path, status, duration and a salted 8-character client tag in place of the IP). Query strings, headers, cookies and passwords are never logged.

## Configuration

| Environment variable | Required | Purpose |
|---|---|---|
| `AUTH_PASSWORD` | yes | Password for user `admin`. At least 12 characters. Changing it signs everyone out. |
| `LOOKUP_TIMEOUT_MS` | no | Per-query timeout in milliseconds. Default 3000. |
| `PORT` | no | Listening port. SiteGround sets this itself, so don't set it there. |

The public resolvers are listed in `resolvers.json` as `{ "name", "address" }` pairs. Edit that file to add or remove resolvers; no code change is needed. Addresses must be IPv4, because SiteGround has no outbound IPv6.

## Running locally

Requires Node 22 or later. There is no install step and no build step.

```sh
AUTH_PASSWORD='at-least-12-chars' npm start   # node server.js, listens on $PORT (default 3000)
npm test                                      # node --test, runs offline with fake DNS
```

Open `http://localhost:3000`. The `Secure` cookie works there because browsers treat `localhost` as secure.

Real DNS lookups need outbound TCP port 53. Some networks block or intercept it. The Claude Code cloud sandbox, for example, times out on TCP 53 and fakes NXDOMAIN answers on UDP 53, so check real behaviour on the deployed site.

## Deployment (SiteGround)

1. **Repository:** `main` on GitHub is the deploy branch. **Every merge to `main` is a production deploy**, with no staging step. Merge only what has passed `npm test`.
2. **Project:** in the SiteGround Client Area, create a Node.js Project connected to this repository and `main`.
3. **Settings:** in Site Tools > Node.js, set:
   - Node version 22;
   - package manager npm;
   - no build command;
   - start command `npm start` or `node server.js`.
4. **Variables:** add `AUTH_PASSWORD` as an environment variable before the first deploy, or the app won't start.
5. **Domain:** use a dedicated subdomain with HTTPS active. Don't host it inside a client website.
6. **Check:** load `/healthz`, sign in, and run `/selftest.html`. TCP should show 4 of 4 reachable.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Site down right after a deploy | `AUTH_PASSWORD` is missing or shorter than 12 characters, so the server refused to start. Set it in Site Tools > Node.js and redeploy. |
| Build failed | See Site Tools > Node.js > Logs. The build deletes `package-lock.json` and runs `npm install`, which does nothing here, so a failure usually means a syntax error in the pushed code. |
| Runtime errors | Statistics > Error Log shows nginx entries only, not the app's console output. Use `/selftest.html` for runtime details (Node version, listener, client address). |
| Every lookup times out | Run `/selftest.html`. If TCP is no longer reachable, SiteGround's outbound port 53 policy has changed. |
| A result says "queries are probably being intercepted" | Something on the network path answered instead of the resolver (for example, NXDOMAIN for `example.com`). Check where the app is running. |
| IPv6 nameserver addresses show "unreachable" | Expected. SiteGround has no outbound IPv6, and these rows are left out of the comparison. |
| An authoritative row says "(not authoritative)" | Lame delegation: that nameserver is listed for the zone but doesn't serve it. Fix it at the domain's registrar or DNS host. |
| SOA serials differ | A secondary nameserver hasn't picked up the latest zone. It is usually brief after a change; if it persists, check zone transfers at the DNS host. |
| "Too many failed sign-in attempts" | 20 wrong passwords from your address in 15 minutes. Wait for the time shown, or sign in from a different network. |
| Sign-in keeps returning to the form | The session cookie is `Secure`, so the site must be on HTTPS. Also check that the browser accepts cookies for the subdomain. |
| Everyone needs to be signed out | Change `AUTH_PASSWORD` and redeploy. |

## Platform findings

These were checked against the deployed instance. Items marked unverified are still open.

- **Outbound DNS.** **Confirmed 2026-10-20:** TCP 53 works and UDP 53 does not. Every resolver timed out over UDP and answered over TCP in 5 to 13 ms. All queries therefore use TCP, via `lib/wire.js` (Node's `node:dns` tries UDP first, so it can't be used).
- **Outbound IPv6.** **Observed 2026-10-21:** every IPv6 nameserver address was unreachable while IPv4 worked. A nameserver with only IPv6 addresses can't be checked from this host.
- **Node version.** **Confirmed from the build log:** Node 22.23.2. `engines` is `>=22`.
- **Build.** **Confirmed from the build log:** the build deletes `package-lock.json`, then runs `npm install` (which does nothing, since there are no dependencies).
- **Deploy branch.** **Confirmed:** `main`, deployed straight to production.
- **Port and listener.** **Confirmed 2026-10-20:** SiteGround sets `PORT` (seen as `64321`). The connection has no local port, which in Node only happens on a Unix socket, so SiteGround probably wraps the app and redirects its listener. `/selftest.html` shows the listener address.
- **Proxy headers.** **Confirmed 2026-10-21:** the socket address is empty, `X-Forwarded-For` arrives with two entries (both the client's IP) and `X-Real-IP` matches. Per-client limits therefore identify clients correctly.
  - Unverified: whether a client-supplied `X-Forwarded-For` is overwritten or appended to. The last-entry rule is correct as long as the nearest proxy appends.
  - To test, run `curl -u admin:… -H 'X-Forwarded-For: 1.2.3.4' https://…/api/selftest`. `clientKey` should still be your real IP.
- **Logs.** Statistics > Error Log shows nginx entries, not the app's output.
- **Start command.** Unverified. The app runs, but which of `npm start` or `node server.js` SiteGround uses isn't confirmed. Both work.
- **Where environment variables are set.** Unverified. Record the exact Site Tools menu path here.

### Phase 0 self-test results (2026-10-20)

| Resolver | UDP | TCP | TCP answers | TTL | TCP ms |
|---|---|---|---|---|---|
| Google 8.8.8.8 | timeout | ok | 172.66.147.243, 104.20.23.154 | 300 | 12.8 |
| Cloudflare 1.1.1.1 | timeout | ok | 104.20.23.154, 172.66.147.243 | 245 | 7.8 |
| Quad9 9.9.9.9 | timeout | ok | 104.20.23.154, 172.66.147.243 | 83 | 5.9 |
| OpenDNS 208.67.222.222 | timeout | ok | 104.20.23.154, 172.66.147.243 | 249 | 5.2 |

Summary: UDP 0 of 4 reachable, TCP 4 of 4 reachable, no interception warnings.
