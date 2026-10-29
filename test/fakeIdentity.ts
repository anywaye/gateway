import type { FetchFn } from "../src/bff/auth";

export type RecordedCall = {
  method: string;
  path: string;
  token: string | null;
  body: string | null;
  url: string;
};

export type Reply = {
  status: number;
  json?: unknown;
  text?: string;
  headers?: Record<string, string>;
  fail?: Error;
  hang?: boolean;
};

export type FakeIdentity = {
  readonly fetch: FetchFn;
  readonly calls: RecordedCall[];
  route(method: string, path: string, reply: Reply): void;
  callsTo(method: string, path: string): RecordedCall[];
  clear(): void;
};

export function fakeIdentity(): FakeIdentity {
  const routes = new Map<string, Reply>();
  const calls: RecordedCall[] = [];

  const fetch: FetchFn = async (input, init) => {
    const request = toRequest(input, init);
    const { pathname } = new URL(request.url);

    calls.push({
      method: request.method,
      path: pathname,
      token: bearerOf(request.headers.get("authorization")),
      body: request.body ? await readBody(request) : null,
      url: request.url,
    });

    const reply = routes.get(`${request.method} ${pathname}`);
    if (reply === undefined) {
      return Response.json({ code: "not_found", detail: `no fake route for ${request.method} ${pathname}` }, 404);
    }
    if (reply.fail) throw reply.fail;
    if (reply.hang) return new Promise<Response>(() => {});

    if (reply.text !== undefined) {
      return new Response(reply.text, {
        status: reply.status,
        headers: { "content-type": "text/html", ...reply.headers },
      });
    }

    return new Response(reply.json === undefined ? "" : JSON.stringify(reply.json), {
      status: reply.status,
      headers: { "content-type": "application/json", ...reply.headers },
    });
  };

  return {
    fetch,
    calls,
    route(method, path, reply) {
      routes.set(`${method} ${path}`, reply);
    },
    callsTo(method, path) {
      return calls.filter((call) => call.method === method && call.path === path);
    },
    clear() {
      calls.length = 0;
    },
  };
}

export const IDENTITY_PATHS = {
  register: "/v1/users",
  session: "/v1/session",
  me: "/v1/me",
  healthz: "/healthz",
} as const;

function toRequest(input: string | URL | Request, init?: RequestInit): Request {
  if (input instanceof Request) return init === undefined ? input : new Request(input, init);
  return new Request(typeof input === "string" ? input : input.href, init);
}

async function readBody(request: Request): Promise<string | null> {
  try {
    return await request.clone().text();
  } catch {
    return null;
  }
}

function bearerOf(authorization: string | null): string | null {
  if (authorization === null) return null;
  return /^bearer +(\S+)$/i.exec(authorization.trim())?.[1] ?? null;
}
