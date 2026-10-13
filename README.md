# EDF Agent

A hosted Next.js app that will prepare RBI Export Declaration Form filings for Indian service exporters. It is an OAuth-protected remote MCP server (`/api/mcp`) plus a web dashboard. The current slice (S1) covers signing in and a `whoami` tool.

## Connect from Claude Code

```sh
claude mcp add --transport http edf https://<env>/api/mcp
```

Then run `/mcp` → Authenticate (or `claude mcp login edf`), sign in in the browser, and ask Claude to call `whoami`.

## Supported clients

| Client | Status |
| --- | --- |
| Claude Code | Supported. It registers through a Client ID Metadata Document (CIMD) or Dynamic Client Registration (DCR) with a loopback redirect (`http://localhost:<port>/callback`). |
| claude.ai / Claude web connectors | Allowed: `https://claude.ai` and `https://claude.com` callbacks are trusted. |
| Other CIMD or DCR clients | Supported when every redirect is loopback http, a reverse-domain private-use scheme (`com.example.app:/cb`), or one of the trusted https hosts above. Registration is open, so no other https redirect is trusted: DCR returns 400 `invalid_redirect_uri`, and a CIMD client's authorize request goes to `/api/auth/error` instead. |
| Cursor | Not supported yet. Its `cursor://anysphere.cursor-*` redirect URIs fail Better Auth's RFC 8252 §7.1 reverse-domain private-use scheme check, and `@better-auth/oauth-provider` 1.7.7 has no option to relax it. Tracked for a later slice. |
| Browser-based clients (e.g. MCP Inspector) | Cannot finish sign-in: the token and registration endpoints send no CORS headers. |

Clients that do not send the RFC 8707 `resource` parameter get it defaulted to `https://<env>/api/mcp`. DPoP-bound tokens (RFC 9449) are supported.

## Environment

| Variable | Notes |
| --- | --- |
| `BETTER_AUTH_URL` | The environment's public https origin: no path, no trailing slash. It must be the exact host users pass to `claude mcp add`. The issuer is `<origin>/api/auth` and the MCP resource is `<origin>/api/mcp`. Optional for `next dev` (defaults to `http://localhost:3000`). |
| `BETTER_AUTH_SECRET` | 32+ random characters (`openssl rand -base64 32`), different in every environment. Keep it stable: it encrypts the token-signing keys stored in the database. |
| `REQUIRE_DB` | `true` in deployed environments. It requires `DATABASE_URL`, an https `BETTER_AUTH_URL` and a 32+ character secret. Misconfiguration makes `/api/health` return 503 with reason codes. |
| `DATABASE_URL` | Postgres 16, a separate database per environment. |
| `PORT` | Injected by Railway. When set, tokens are verified against `http://127.0.0.1:$PORT/api/auth/jwks`. |

Dev and production must differ in origin, secret and database; their tokens then fail each other's issuer, audience and signature checks.

## Commands

| Command | What it does |
| --- | --- |
| `npm run dev` | Next dev server; no env needed. |
| `npm run build` | Production build. |
| `npm start` | Runs the idempotent migrations (`scripts/migrate.ts`, under an advisory lock), then `next start`. |
| `npm test` | Unit tests. The integration suite is skipped when `TEST_DATABASE_URL` is unset. |
| `npm run test:integration` | The end-to-end OAuth suite against a Postgres role that may `CREATE DATABASE` (see the recipe at the top of `tests/integration/auth-flow.test.ts`). |
| `npm run smoke -- https://<env>` | Post-deploy check: health, protected-resource metadata and the anonymous 401 challenge. |
