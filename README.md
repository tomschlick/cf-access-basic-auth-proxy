# cf-access-basic-auth-proxy

A stateless Cloudflare Worker that lets HTTP **Basic Auth** clients reach an origin protected by **Cloudflare Access service tokens**.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/tomschlick/cf-access-basic-auth-proxy)

## Why

Some clients (legacy apps, webhooks, monitoring tools, RSS readers, HTTP libraries) can only send HTTP Basic Auth. They cannot set the custom `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers that a [Cloudflare Access service token](https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/) requires.

This worker bridges the gap: the client sends its service token as Basic Auth credentials, and the worker rewrites them into the headers Cloudflare Access expects.

## How it works

```
client ──Basic base64(CLIENT_ID:CLIENT_SECRET)──▶ worker ──CF-Access-Client-Id/Secret──▶ Access-protected origin
```

1. The client sends `Authorization: Basic base64(CLIENT_ID:CLIENT_SECRET)`, where `CLIENT_ID` / `CLIENT_SECRET` are a Cloudflare Access service token.
2. The worker format-validates the credentials (charset, length), then forwards the request to `ORIGIN_URL`, preserving the request path and query.
3. It sets `CF-Access-Client-Id` and `CF-Access-Client-Secret`, strips the original `Authorization` header, and adds `X-Forwarded-For` / `X-Real-IP` / `X-Original-IP` / `X-Original-User-Agent`.
4. Cloudflare Access at the origin validates the service token and allows or denies the request.

## Security model

The proxy **authenticates no one and stores no secrets.** It does not check credentials against an allowlist — it only sanitizes their format to prevent header injection. **All authorization is delegated to Cloudflare Access at the origin.** Anyone can reach the proxy; only requests carrying a service token that Access accepts get through.

## Deploy

### 1. Create a Cloudflare Access service token

In the Cloudflare Zero Trust dashboard: **Access → Service Auth → Service Tokens → Create Service Token**. Save the Client ID and Client Secret, and make sure your origin's Access application has a policy that allows this service token.

### 2. Click Deploy

Use the button above. Cloudflare forks this repo into your account, wires up builds, and prompts you for:

- **`ORIGIN_URL`** — the base URL (scheme + host) of your Access-protected origin, e.g. `https://internal.example.com`. Request paths and query strings are preserved.

## Usage

```sh
curl -u "$CF_ACCESS_CLIENT_ID:$CF_ACCESS_CLIENT_SECRET" https://<your-worker-url>/some/path?q=1
```

The proxy forwards `GET /some/path?q=1` to `https://internal.example.com/some/path?q=1` with the Access headers attached.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `ORIGIN_URL` | yes | Base URL (scheme + host) of the Access-protected origin. Path/query from the incoming request are preserved; any path in this value is ignored. |

If `ORIGIN_URL` is unset, the worker returns `500`.

## Local development

```sh
npm install
# set ORIGIN_URL for local runs (edit wrangler.jsonc vars, or create a gitignored .dev.vars)
npm run dev
npm test
npm run typecheck
```

## License

MIT — see [LICENSE](./LICENSE).
