# Design: cf-access-basic-auth-proxy

**Date:** 2026-07-22
**Status:** Approved (pending spec review)

## Summary

A stateless Cloudflare Worker that lets an **HTTP Basic Auth-only client** reach an
**origin protected by Cloudflare Access service tokens**. The caller supplies its
Cloudflare Access service token as Basic Auth credentials
(`username = Client ID`, `password = Client Secret`); the worker format-validates
them and re-issues them as the `CF-Access-Client-Id` / `CF-Access-Client-Secret`
headers that Cloudflare Access expects, then forwards the request to a configured
origin.

The repository is shipped as a **public "Deploy to Cloudflare" button template** so
that anyone can install their own copy of the worker into their own Cloudflare
account with one click, supplying only the origin URL.

### Security model (important)

The proxy **authenticates no one itself and stores no secrets**. It is a credential
*format adapter*, not an auth gate. Real authorization happens entirely at the
origin: Cloudflare Access validates the forwarded service token. The worker only
performs input hygiene (strip control characters, enforce a conservative charset and
length) so it cannot be used for header injection, and delegates the actual
allow/deny decision to Cloudflare Access.

This is the deliberate design: each client brings its own service token; the worker
holds nothing sensitive.

## Goals

- A production-quality Cloudflare Worker implementing the Basic-Auth → service-token
  adapter.
- The repo installs to **any** Cloudflare account via a one-click Deploy to
  Cloudflare button, prompting the installer for the single required config value.
- Trustworthy for a public auth-adjacent template: TypeScript, tests over the
  security-relevant paths, CI, clear docs, MIT license.

## Non-goals

- The worker does **not** validate credential *values* or maintain an allowlist —
  Cloudflare Access at the origin does that.
- No multi-tenant routing, no KV/D1/R2, no per-request origin selection. One worker
  instance → one origin.
- No deploy-tooling/CLI for pushing to accounts we control (that was an alternative
  approach; the chosen approach is the self-service Deploy button).

## Configuration surface

Exactly **one** value, and it is **not** a secret:

| Name         | Kind | Required | Notes |
|--------------|------|----------|-------|
| `ORIGIN_URL` | var  | yes      | Scheme + host (+ optional port) of the Access-protected origin, e.g. `https://internal.example.com`. Any path in this value is ignored (host-swap). |

`ORIGIN_URL` is declared in `wrangler.jsonc` under `vars` (default `""`) and
described in `package.json` under `cloudflare.bindings`. Because the Deploy to
Cloudflare flow reads declared `vars` and prompts the installer for each, the
installer is asked for `ORIGIN_URL` in the Cloudflare dashboard during deploy.

There are **no secrets**, so there is intentionally **no** `.dev.vars.example` /
`.env.example` file (an entry there would make the Deploy flow prompt for
`ORIGIN_URL` a second time as a secret). For local development the origin is set via
`wrangler.jsonc` or a gitignored local `.dev.vars`.

## Worker behavior

Single `fetch` handler in `src/index.ts` (default export), plus the two helper
functions from the provided source. Typed environment: `interface Env { ORIGIN_URL: string }`.

### Request flow

1. Read `Authorization`. If absent or not starting with `Basic ` →
   **401** with `WWW-Authenticate: Basic realm="Cloudflare Access Proxy", charset="UTF-8"`.
2. Base64-decode the credential segment with `atob`. On throw → **400**
   `Invalid Basic Auth encoding`.
3. Split on the **first** colon (standard Basic Auth: password is everything after
   the first `:`). Use `indexOf(':')` + `slice`, **not** `split(':', 2)` (which would
   silently truncate a value containing a colon). No colon, or either part empty →
   **401** `Invalid credentials format`.
4. For each part: sanitize (`sanitizeHeaderValue` — strip CR/LF/TAB and C0/C1 control
   chars, trim) then validate (`^[A-Za-z0-9_-]+$`, length 20–300). Either invalid →
   **401** `Invalid Cloudflare Access credentials format`.
5. Validate `ORIGIN_URL`: if missing/empty or not a parseable URL → **500**
   `Proxy misconfigured: ORIGIN_URL is not set` (logged via `console.error`). No
   outbound request is made. (Checked after credential validation so unauthenticated
   probes still get a 401.)
6. Build the target URL by **host-swap, preserving path + query**:
   ```ts
   const target = new URL(request.url);      // proxy host + incoming path + query
   const origin = new URL(env.ORIGIN_URL);
   target.protocol = origin.protocol;
   target.host = origin.host;                // host + port; path/query preserved
   ```
7. Clone the request (`new Request(request)`) and set headers on the clone:
   - `CF-Access-Client-Id` = validated client id
   - `CF-Access-Client-Secret` = validated client secret
   - From `CF-Connecting-IP` (sanitized, if present): set `X-Original-IP`,
     `X-Forwarded-For`, `X-Real-IP`
   - From incoming `User-Agent` (sanitized, if present): set `X-Original-User-Agent`
   - `User-Agent` = `CF-Access-Basic-Auth-Proxy`
   - Delete `Authorization` (do not leak Basic Auth to origin)
8. `await fetch(target, clonedRequest)`. Return the response passed through
   (`status`, `statusText`, `headers`, `body`). On throw → **502**
   `Internal proxy error` (logged via `console.error`).

### Changes from the provided source

- **Fix path forwarding.** The provided code forwards to `ORIGIN_URL` verbatim,
  dropping the request path/query. Replace with the host-swap construction in step 6
  so the incoming path + query are preserved.
- **Require `ORIGIN_URL`.** Remove the `|| https://your-protected-origin.example.com…`
  fallback; fail fast with a 500 when unset/invalid (step 5).
- **First-colon split** (step 3) instead of `split(':', 2)`.
- Drop the unused `${url.hash}` (fragments are never sent to servers).

Everything else (helpers, sanitization rules, forwarded headers, error codes)
matches the provided source.

## Repository structure (TypeScript)

```
src/index.ts                worker: default fetch handler + sanitizeHeaderValue +
                            sanitizeAndValidateAccessHeader; Env interface
test/index.spec.ts          Vitest suite (@cloudflare/vitest-pool-workers)
wrangler.jsonc              name, main, compatibility_date, observability, vars.ORIGIN_URL
package.json                scripts + cloudflare.bindings description + devDeps
tsconfig.json               Workers + vitest-pool-workers types
vitest.config.ts            cloudflareTest plugin pointing at wrangler.jsonc
.github/workflows/ci.yml    typecheck + test on push/PR
.gitignore                  node_modules, .wrangler, dist, .dev.vars, coverage, .DS_Store
README.md                   deploy button, how it works, security model, setup, usage, local dev
LICENSE                     MIT, Tom Schlick, 2026
```

### Key file contents

**wrangler.jsonc**
```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "cf-access-basic-auth-proxy",
  "main": "src/index.ts",
  "compatibility_date": "2026-07-01",
  "observability": { "enabled": true },
  "vars": { "ORIGIN_URL": "" }
}
```

**package.json** (versions pinned to current latest at implementation time;
`@cloudflare/vitest-pool-workers` and `vitest` must be a compatible pair)
```jsonc
{
  "name": "cf-access-basic-auth-proxy",
  "private": true,
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run",
    "typecheck": "tsc --noEmit"
  },
  "cloudflare": {
    "bindings": {
      "ORIGIN_URL": {
        "description": "Base URL (scheme + host) of your Cloudflare Access-protected origin, e.g. `https://internal.example.com`. Incoming request paths and query strings are preserved."
      }
    }
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "*",
    "@cloudflare/workers-types": "*",
    "typescript": "*",
    "vitest": "*",
    "wrangler": "*"
  }
}
```

**vitest.config.ts** (vitest 4 / `@cloudflare/vitest-pool-workers` 0.18+ uses the `cloudflareTest` plugin, not the old `defineWorkersConfig`; the package is ESM-only, so `package.json` must set `"type": "module"`)
```ts
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
});
```

## Testing

Vitest with `@cloudflare/vitest-pool-workers` (runs in workerd). Tests import the
default worker and call `worker.fetch(request, env, ctx)` with a per-test `env` so
`ORIGIN_URL` can be set/unset, using `createExecutionContext` from `cloudflare:test`.
Outbound `fetch` is intercepted (primary approach: `vi.stubGlobal("fetch", …)` to
capture the outbound `Request` and return a canned `Response`, so header/URL
assertions are exact; fall back to `cloudflare:test`'s `fetchMock` if stubbing the
global proves unreliable in the pool).

Cases:

1. Missing `Authorization` → 401 + correct `WWW-Authenticate` header; no outbound fetch.
2. Non-Basic scheme (`Bearer …`) → 401.
3. Un-decodable base64 (e.g. `Basic @@@@`) → 400.
4. Empty id (`:secret…`) or empty secret (`id…:`) → 401 `Invalid credentials format`.
5. Bad charset (contains e.g. `!`) → 401 invalid format.
6. Too short (< 20) / too long (> 300) → 401 invalid format.
7. **Valid credentials** → exactly one outbound fetch; target URL is host-swapped
   (`ORIGIN_URL` host + original path + query preserved); outbound headers include
   `CF-Access-Client-Id`/`CF-Access-Client-Secret` set to the provided values,
   `Authorization` removed, `X-Forwarded-For`/`X-Real-IP`/`X-Original-IP` from
   `CF-Connecting-IP`, `User-Agent` overridden; response status/body passed through.
8. Valid credentials but `ORIGIN_URL` unset/empty → 500; no outbound fetch. (Sends
   valid-format credentials so the request reaches the step-5 config check rather
   than a 401.)
9. Outbound fetch throws → 502.

## CI

`.github/workflows/ci.yml`: on push to `master` and on PRs — checkout,
`actions/setup-node@v4` (Node 20, npm cache), `npm ci`, `npm run typecheck`,
`npm test`. No deploy step (end-user deploys happen via the button / their own
Cloudflare Workers Builds).

## Deploy to Cloudflare button

README includes:
```md
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/tomschlick/cf-access-basic-auth-proxy)
```
Requirements satisfied by this design: repo is public on GitHub.com, has a Wrangler
config with `compatibility_date`, and a `package.json`. Default deploy command is
`npx wrangler deploy`. Installer is prompted for `ORIGIN_URL`.

## README outline

- Title + one-line description
- Deploy to Cloudflare button
- How it works (flow: Basic Auth in → service-token headers out → origin)
- Security model (delegates all authz to Cloudflare Access; stores no secrets)
- Prerequisites (an Access-protected origin; a Cloudflare Access service token)
- Setup (create a service token in Zero Trust; click Deploy; set `ORIGIN_URL`)
- Usage (`curl -u "$CLIENT_ID:$CLIENT_SECRET" https://<worker>/path`)
- Configuration (`ORIGIN_URL`, host-swap behavior)
- Local development (`npm install`, set origin, `npm run dev`, `npm test`)
- License

## Open implementation notes

- Pick a compatible `vitest` / `@cloudflare/vitest-pool-workers` version pair at
  install time (they track each other closely).
- Consider `wrangler types` to generate env types instead of the hand-written
  `Env` interface; either is acceptable for a single var.
