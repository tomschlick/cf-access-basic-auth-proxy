export interface Env {
  ORIGIN_URL: string;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // === 1. Require Basic Auth ===
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return new Response("Unauthorized - Basic Auth required", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Cloudflare Access Proxy", charset="UTF-8"',
        },
      });
    }

    // === 2. Decode + parse credentials (password = everything after the first colon) ===
    let credentials: string;
    try {
      credentials = atob(authHeader.slice("Basic ".length));
    } catch {
      return new Response("Invalid Basic Auth encoding", { status: 400 });
    }

    const separator = credentials.indexOf(":");
    if (separator === -1) {
      return new Response("Invalid credentials format", { status: 401 });
    }
    const rawClientId = credentials.slice(0, separator);
    const rawClientSecret = credentials.slice(separator + 1);
    if (!rawClientId || !rawClientSecret) {
      return new Response("Invalid credentials format", { status: 401 });
    }

    // === 3. Sanitize + enforce Cloudflare Access service token format ===
    const clientId = sanitizeAndValidateAccessHeader(rawClientId, "Client ID");
    const clientSecret = sanitizeAndValidateAccessHeader(rawClientSecret, "Client Secret");
    if (!clientId || !clientSecret) {
      return new Response("Invalid Cloudflare Access credentials format", { status: 401 });
    }

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

    // Never leak the client's Basic Auth to the origin.
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
  },
};

/**
 * Remove control characters that could enable header injection: C0 (0x00-0x1F)
 * and C1 (0x7F-0x9F). Uses a code-point scan rather than a control-character
 * regex literal so the source stays free of raw control bytes.
 */
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

/** Sanitize + enforce Cloudflare Access service token format. */
function sanitizeAndValidateAccessHeader(value: string, fieldName: string): string | null {
  const sanitized = sanitizeHeaderValue(value);

  // Cloudflare service tokens are long alphanumeric strings (with - and _).
  if (sanitized.length < 20 || sanitized.length > 300) {
    console.warn(`Invalid ${fieldName} length`);
    return null;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(sanitized)) {
    console.warn(`Invalid characters in ${fieldName}`);
    return null;
  }
  return sanitized;
}
