import { describe, it, expect, vi, afterEach } from "vitest";
import { createExecutionContext } from "cloudflare:test";
import worker, { type Env } from "../src/index";

const CLIENT_ID = "a".repeat(40); // valid: 40 chars in [A-Za-z0-9_-]
const CLIENT_SECRET = "b".repeat(64); // valid: 64 chars in [A-Za-z0-9_-]

function basic(id: string, secret: string): string {
  return "Basic " + btoa(`${id}:${secret}`);
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return { ORIGIN_URL: "https://origin.test", ...overrides };
}

/** Replace global fetch with a capturing stub returning a canned origin response. */
function stubOrigin(
  response = new Response("origin-body", { status: 200, statusText: "OK" }),
) {
  const stub = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response);
  vi.stubGlobal("fetch", stub);
  return stub;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("cf-access-basic-auth-proxy", () => {
  it("returns 401 with WWW-Authenticate when Authorization is missing", async () => {
    const stub = stubOrigin();
    const res = await worker.fetch(
      new Request("https://proxy.test/x"),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(
      'Basic realm="Cloudflare Access Proxy", charset="UTF-8"',
    );
    expect(stub).not.toHaveBeenCalled();
  });

  it("returns 401 for a non-Basic Authorization scheme", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", { headers: { Authorization: "Bearer token" } }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
  });

  it("returns 400 for undecodable base64", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", { headers: { Authorization: "Basic @@@@" } }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(400);
  });

  it("returns 401 when the id is empty", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: basic("", CLIENT_SECRET) },
      }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when there is no colon separator", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: "Basic " + btoa("no-colon-here") },
      }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 for invalid token characters", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: basic("bad!!!!!!!!!!!!!!!!!!!!", CLIENT_SECRET) },
      }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 for a too-short token", async () => {
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: basic("short", CLIENT_SECRET) },
      }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(401);
  });

  it("returns 500 with valid credentials when ORIGIN_URL is unset", async () => {
    const stub = stubOrigin();
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: basic(CLIENT_ID, CLIENT_SECRET) },
      }),
      makeEnv({ ORIGIN_URL: "" }),
      createExecutionContext(),
    );
    expect(res.status).toBe(500);
    expect(stub).not.toHaveBeenCalled();
  });

  it("forwards valid requests to the host-swapped origin with Access headers", async () => {
    const stub = stubOrigin();
    const res = await worker.fetch(
      new Request("https://proxy.test/api/x?y=1", {
        method: "POST",
        headers: {
          Authorization: basic(CLIENT_ID, CLIENT_SECRET),
          "CF-Connecting-IP": "203.0.113.5",
          "User-Agent": "curl/8.0",
        },
        body: "payload",
      }),
      makeEnv(),
      createExecutionContext(),
    );

    expect(stub).toHaveBeenCalledTimes(1);
    const forwarded = stub.mock.calls[0][0] as Request;
    expect(forwarded.url).toBe("https://origin.test/api/x?y=1");
    expect(forwarded.headers.get("CF-Access-Client-Id")).toBe(CLIENT_ID);
    expect(forwarded.headers.get("CF-Access-Client-Secret")).toBe(CLIENT_SECRET);
    expect(forwarded.headers.get("Authorization")).toBeNull();
    expect(forwarded.headers.get("X-Forwarded-For")).toBe("203.0.113.5");
    expect(forwarded.headers.get("X-Real-IP")).toBe("203.0.113.5");
    expect(forwarded.headers.get("X-Original-IP")).toBe("203.0.113.5");
    expect(forwarded.headers.get("X-Original-User-Agent")).toBe("curl/8.0");
    expect(forwarded.headers.get("User-Agent")).toBe("CF-Access-Basic-Auth-Proxy");

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });

  it("returns 502 when the origin fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network");
      }),
    );
    const res = await worker.fetch(
      new Request("https://proxy.test/x", {
        headers: { Authorization: basic(CLIENT_ID, CLIENT_SECRET) },
      }),
      makeEnv(),
      createExecutionContext(),
    );
    expect(res.status).toBe(502);
  });
});
