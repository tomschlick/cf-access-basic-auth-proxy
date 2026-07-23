# cf-access-basic-auth-proxy Implementation Plan

> **Status:** Implemented and verified (typecheck clean, 10/10 tests passing, `wrangler deploy --dry-run` succeeds). This document was updated to match the shipped code — notably the vitest 4 config API and the control-character-safe `sanitizeHeaderValue`.

**Goal:** Build a stateless Cloudflare Worker that translates HTTP Basic Auth credentials into Cloudflare Access service-token headers, packaged as a public one-click "Deploy to Cloudflare" template.

**Architecture:** A single `fetch` handler validates the *format* of Basic Auth credentials (username = Client ID, password = Client Secret), then forwards the request to a configured origin with `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers set. It stores no secrets and authenticates no one itself — Cloudflare Access at the origin performs the real authorization. The only configuration is `ORIGIN_URL`, a Wrangler `var` so the Deploy-to-Cloudflare flow prompts the installer for it.

**Tech Stack:** TypeScript, Cloudflare Workers, Wrangler 4, Vitest 4 with `@cloudflare/vitest-pool-workers` 0.18, GitHub Actions.

## Global Constraints

- Language: **TypeScript**, `"strict": true`. Package is **ESM** (`"type": "module"` in `package.json`) — `@cloudflare/vitest-pool-workers` is ESM-only and the vitest config fails to load otherwise.
- Wrangler `compatibility_date`: **`2026-07-01`**.
- Worker/repo name: **`cf-access-basic-auth-proxy`**.
- Only configuration value: **`ORIGIN_URL`** — a Wrangler `var`, default `""`. **No secrets. No `.dev.vars.example` / `.env.example` file.**
- `WWW-Authenticate` header value, exactly: `Basic realm="Cloudflare Access Proxy", charset="UTF-8"`.
- Forwarded `User-Agent` value, exactly: `CF-Access-Basic-Auth-Proxy`.
- Credential format validation: `^[A-Za-z0-9_-]+$`, length **20–300** inclusive; strip C0 (`0x00-0x1F`) and C1 (`0x7F-0x9F`) control characters first.
- URL rule: **host-swap** — target uses `ORIGIN_URL`'s scheme + host (+ port); the incoming request's path + query are preserved; any path in `ORIGIN_URL` is ignored.
- Error codes: **401** auth missing / non-Basic / empty part / invalid format; **400** un-decodable base64; **500** `ORIGIN_URL` unset or unparseable; **502** origin fetch throws.
- Deploy button target URL: `https://deploy.workers.cloudflare.com/?url=https://github.com/tomschlick/cf-access-basic-auth-proxy`.
- License: **MIT**, "Tom Schlick", 2026.
- CI: Node 20, `npm ci`, `npm run typecheck`, `npm test`.

## File Structure

| File | Responsibility |
|------|----------------|
| `src/index.ts` | Worker: default `fetch` handler + `sanitizeHeaderValue` + `sanitizeAndValidateAccessHeader`; exported `Env` interface. |
| `test/index.spec.ts` | Vitest suite covering every request-flow branch. |
| `test/env.d.ts` | Triple-slash reference bringing in `cloudflare:test` types (`/types` subpath). |
| `wrangler.jsonc` | Worker name, entrypoint, `compatibility_date`, observability, `vars.ORIGIN_URL`. |
| `package.json` | `"type": "module"`, scripts, `cloudflare.bindings` description, devDependencies. |
| `tsconfig.json` | TypeScript config with Workers types. |
| `vitest.config.ts` | `cloudflareTest` plugin pointing at `wrangler.jsonc`. |
| `.gitignore` | Ignore `node_modules`, `.wrangler`, `.dev.vars`, `dist`, `coverage`. |
| `.github/workflows/ci.yml` | Typecheck + test on push/PR. |
| `README.md` | Deploy button, how-it-works, security model, setup, usage. |
| `LICENSE` | MIT. |

Tasks: **Task 1** = scaffold + input validation. **Task 2** = origin resolution + forwarding. **Task 3** = template polish (README, button, CI, LICENSE).

---

### Task 1: Scaffold project and implement input validation

**Files:** `package.json`, `wrangler.jsonc`, `tsconfig.json`, `vitest.config.ts`, `.gitignore`, `test/env.d.ts`, `src/index.ts`, `test/index.spec.ts`.

**Interfaces produced:** `export interface Env { ORIGIN_URL: string }`; default export `{ fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> }`; module-private `sanitizeHeaderValue(value: string | null): string` and `sanitizeAndValidateAccessHeader(value: string, fieldName: string): string | null`.

- [x] **Step 1: `package.json`** — note `"type": "module"` (required: the vitest pool package is ESM-only).

```json
{
  "name": "cf-access-basic-auth-proxy",
  "private": true,
  "type": "module",
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
  }
}
```

- [x] **Step 2: Install dev dependencies**

```bash
npm install --save-dev wrangler @cloudflare/workers-types @cloudflare/vitest-pool-workers vitest typescript
```
`@cloudflare/vitest-pool-workers` peers `vitest ^4.1`. Resolved versions used: wrangler 4.113, vitest 4.1, vitest-pool-workers 0.18.7, typescript 7.0.

- [x] **Step 3: `wrangler.jsonc`**

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

- [x] **Step 4: `tsconfig.json`**

```jsonc
{
  "compilerOptions": {
    "target": "es2022",
    "lib": ["es2022"],
    "module": "es2022",
    "moduleResolution": "bundler",
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "resolveJsonModule": true
  },
  "include": ["src", "test", "vitest.config.ts"]
}
```

- [x] **Step 5: `vitest.config.ts`** — vitest 4 / pool-workers 0.18 use the `cloudflareTest` plugin (the old `defineWorkersConfig` from `/config` was removed).

```ts
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
});
```

- [x] **Step 6: `test/env.d.ts`** — the `cloudflare:test` module is declared in the package's `./types` subpath, not its main entry.

```ts
/// <reference types="@cloudflare/vitest-pool-workers/types" />
```

- [x] **Step 7: `.gitignore`**

```gitignore
node_modules/
.wrangler/
dist/
.dev.vars
coverage/
.DS_Store
```

- [x] **Step 8: `test/index.spec.ts`** (input-validation cases; forwarding cases added in Task 2) — see final file in the repo. The suite imports the default worker, calls `worker.fetch(request, env, createExecutionContext())` with a per-test `env`, and stubs outbound `fetch` with `vi.stubGlobal("fetch", …)` to capture the forwarded `Request`.

- [x] **Step 9–11: `src/index.ts`, run tests + typecheck.** `sanitizeHeaderValue` uses a **code-point scan** (not a control-character regex literal) so the source contains no raw control bytes:

```ts
function sanitizeHeaderValue(value: string | null): string {
  if (typeof value !== "string") return "";
  let sanitized = "";
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) {
      continue;
    }
    sanitized += char;
  }
  return sanitized.trim();
}
```

The handler implements request-flow steps 1–3 (Basic Auth presence → 401 + `WWW-Authenticate`; base64 decode → 400; first-colon split via `indexOf`/`slice` → 401 on empty; format validation → 401).

- [x] **Step 12: Commit** the scaffold + validation.

---

### Task 2: Origin resolution and request forwarding

**Files:** `src/index.ts` (request-flow steps 4–6), `test/index.spec.ts` (forwarding cases).

- [x] **Step 1: Host-swap + forwarding.** Resolve `ORIGIN_URL` (fail-fast 500 if unset/unparseable), host-swap the target, set Access + forwarded headers, strip `Authorization`, fetch, pass the response through, 502 on throw:

```ts
// === 4. Resolve origin (host-swap; fail fast if misconfigured) ===
let target: URL;
try {
  const origin = new URL(env.ORIGIN_URL);
  target = new URL(request.url);
  target.protocol = origin.protocol;
  target.host = origin.host; // host + port; incoming path + query preserved
} catch {
  console.error("Proxy misconfigured: ORIGIN_URL is not a valid URL:", env.ORIGIN_URL);
  return new Response("Proxy misconfigured: ORIGIN_URL is not set", { status: 500 });
}

// === 5. Build the forwarded request ===
const forwarded = new Request(target, request);
forwarded.headers.set("CF-Access-Client-Id", clientId);
forwarded.headers.set("CF-Access-Client-Secret", clientSecret);

const clientIP = sanitizeHeaderValue(request.headers.get("CF-Connecting-IP"));
if (clientIP) {
  forwarded.headers.set("X-Original-IP", clientIP);
  forwarded.headers.set("X-Forwarded-For", clientIP);
  forwarded.headers.set("X-Real-IP", clientIP);
}

const originalUserAgent = sanitizeHeaderValue(request.headers.get("User-Agent"));
if (originalUserAgent) {
  forwarded.headers.set("X-Original-User-Agent", originalUserAgent);
}
forwarded.headers.set("User-Agent", "CF-Access-Basic-Auth-Proxy");
forwarded.headers.delete("Authorization");

// === 6. Forward to origin ===
try {
  const response = await fetch(forwarded);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
} catch (err) {
  console.error("Proxy error:", err);
  return new Response("Internal proxy error", { status: 502 });
}
```

- [x] **Step 2–5: Tests, typecheck, commit.** Forwarding tests assert the outbound URL is `https://origin.test/api/x?y=1` (host-swap + path/query preserved), the Access headers are set, `Authorization` is stripped, the `X-*` forwarded headers come from `CF-Connecting-IP`, `User-Agent` is overridden, the response is passed through; plus `ORIGIN_URL` unset → 500 (no outbound call) and origin throw → 502.

---

### Task 3: Template polish — README, Deploy button, CI, LICENSE

- [x] **Step 1: `.github/workflows/ci.yml`** — Node 20, `npm ci`, `npm run typecheck`, `npm test` on push to `master` and PRs. No `${{ github.event.* }}` interpolation in `run:` steps (avoids workflow injection).
- [x] **Step 2: `README.md`** — Deploy-to-Cloudflare button, how-it-works diagram, security model, service-token setup, `curl -u CLIENT_ID:CLIENT_SECRET` usage, configuration table, local dev.
- [x] **Step 3: `LICENSE`** — MIT, Copyright (c) 2026 Tom Schlick.
- [x] **Step 4: Remove the placeholder `.gitkeep`.**
- [x] **Step 5–6: Final verification + commit.** `npm run typecheck && npm test` green; `wrangler deploy --dry-run` compiles the worker and recognizes the `ORIGIN_URL` binding.

## Self-Review

- Spec coverage: stateless adapter (no secrets) ✓; request flow 1–8 ✓; first-colon split ✓; `ORIGIN_URL` required/500 ✓; host-swap keep path ✓; forwarded headers ✓; one-var config surface with Deploy prompt ✓; every-branch tests ✓; TS + Vitest + CI + README/button + MIT ✓.
- The vitest config, `test/env.d.ts` subpath, ESM `"type": "module"`, and control-character-safe `sanitizeHeaderValue` were corrected during implementation to match the installed vitest 4 / pool-workers 0.18 toolchain and to avoid raw control bytes in source.
