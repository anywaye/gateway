import { SignJWT, exportJWK, generateKeyPair, type JWK, type JWTPayload } from "jose";

export type TestKey = {
  kid: string;
  privateKey: CryptoKey;
  jwk: JWK;
};

export async function testKey(kid: string): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);

  return { kid, privateKey, jwk: { ...jwk, kid, alg: "RS256", use: "sig" } };
}

export function signToken(key: TestKey, claims: JWTPayload, header: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: key.kid, ...header })
    .sign(key.privateKey);
}

export function tamperPayload(token: string, claims: JWTPayload): string {
  const [header, _payload, signature] = token.split(".");
  if (!header || !signature) throw new Error("tamperPayload: not a compact JWS");
  return `${header}.${base64url(claims)}.${signature}`;
}

export function unsignedToken(claims: JWTPayload, header: Record<string, unknown>): string {
  return `${base64url(header)}.${base64url(claims)}.`;
}

export type JwksServer = {
  readonly issuer: string;
  readonly jwksUrl: string;
  readonly requests: string[];
  publish(...keys: TestKey[]): void;
  failWith(status: number): void;
  serveGarbage(): void;
  hang(): void;
  serveKeys(): void;
  stop(): void;
};

export async function startJwksServer(...keys: TestKey[]): Promise<JwksServer> {
  const requests: string[] = [];
  let published: JWK[] = keys.map((key) => key.jwk);
  let mode: "keys" | "status" | "garbage" | "hang" = "keys";
  let status = 500;

  const server = Bun.serve<unknown>({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const { pathname } = new URL(request.url);
      requests.push(pathname);

      if (mode === "hang") return new Promise<Response>(() => {});
      if (mode === "status") return new Response("upstream is unwell", { status });
      if (mode === "garbage") {
        return new Response("<html>login required</html>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }
      if (pathname !== "/.well-known/jwks.json") {
        return new Response("not found", { status: 404 });
      }
      return Response.json({ keys: published });
    },
  });

  const issuer = `http://127.0.0.1:${server.port}`;

  return {
    issuer,
    jwksUrl: `${issuer}/.well-known/jwks.json`,
    requests,
    publish(...next: TestKey[]) {
      published = next.map((key) => key.jwk);
    },
    failWith(next: number) {
      mode = "status";
      status = next;
    },
    serveGarbage() {
      mode = "garbage";
    },
    hang() {
      mode = "hang";
    },
    serveKeys() {
      mode = "keys";
    },
    stop() {
      server.stop(true);
    },
  };
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
