# DNS Checker

A private, self-hosted DNS lookup tool, a personal replacement for dnschecker.org. It compares answers from several public resolvers, queries a domain's authoritative nameservers directly, and checks email DNS (SPF, DKIM, DMARC, MX).

It runs as a Node.js Project on SiteGround Cloud and deploys from GitHub. It has zero npm dependencies and uses only Node built-ins.

The full brief is in [docs/PLAN.md](docs/PLAN.md). Project rules are in [CLAUDE.md](CLAUDE.md).

**Status:** Phase 0 (reachability spike). The only working endpoints are `/healthz` and `/api/selftest`.

## Running locally

Requires Node 22 for development. `engines` asks for Node 20 or later.

```sh
npm start    # node server.js, listens on $PORT (default 3000)
npm test     # node --test, runs offline
```

There is no install step and no build step.

## Phase 0 deployment

Condensed from [docs/PLAN.md](docs/PLAN.md) section 6.

1. Create the GitHub repository `dnschecker` and make sure `main` exists. `main` is the deploy branch.
2. In the SiteGround Client Area, create a Node.js Project and connect the repository and the `main` branch. Confirm the menu path in the SiteGround KB article "What is a Node.js Project?".
3. In Site Tools > Node.js, set the Node version (pick one that is actually selectable and matches `engines`), package manager to npm, no build command, and start command `npm start` (or `node server.js`).
4. Point a dedicated subdomain at the project. Do not host it inside a client website.
5. Confirm HTTPS is active.
6. Load `/healthz`, then `/api/selftest`, and record the output here.
7. If something fails, check Site Tools > Node.js > Logs (build) and Statistics > Error Log (runtime).

Environment variables: `AUTH_PASSWORD` is required from Phase 1. Set `PORT` only if the platform does not inject it. See `.env.example`.

## Platform findings

Every item below is **unverified – to confirm on deploy**. Record the answer here once checked against SiteGround's documentation or a deployed instance.

- **Outbound UDP and TCP port 53.** Can a SiteGround Node project query arbitrary resolvers on both transports? Status: unverified – to confirm on deploy. In the Claude Code sandbox, TCP 53 times out and UDP 53 is intercepted: every resolver "answers" NXDOMAIN for `example.com` within about 5 ms. The self-test reports that pattern as a warning, so watch for it on SiteGround too. Only the deployed `/api/selftest` can answer this. Only rows with status `ok` count as reachable.
- **Listening port.** How does the platform pass the port to the app? Status: unverified – to confirm on deploy. The server uses `process.env.PORT`, falls back to 3000, and logs which source it used at startup.
- **Node versions.** Which versions can be selected in Site Tools? Status: unverified – to confirm on deploy. `engines` is `>=20`.
- **Start command.** Does the platform expect `npm start` or `node server.js`? Status: unverified – to confirm on deploy. A `start` script runs `node server.js`, so either works if the platform accepts it.
- **Deploy branch.** Which branch deploys? The plan says `main`. Status: unverified – to confirm on deploy.

Phase 0 self-test results: not yet recorded.
