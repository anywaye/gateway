// The principal assertion: guard's own signature over who the caller is, sent to
// one upstream and to nothing else.
//
// ## THE GAP THIS EXISTS TO CLOSE, AND WHY IT IS A FACT RATHER THAN A BUG
//
// `proxy.ts` sends the per-upstream `token` as `authorization` and copies
// nothing else. Its own header says the cost out loud: *"an upstream cannot tell
// which caller sent a request. The per-upstream `token` is a service credential,
// not a delegation, and no header here asserts who the caller was."*
//
// That rule is correct and load-bearing — forwarding the caller's `Authorization`
// would make guard a confused deputy — and it is exactly why a publisher write
// cannot work: pantry's RLS predicates compare against
// `pantry.current_publisher_id()`, and the request arrives with nothing to
// compare. The caller is not missing. `src/index.ts` resolved it to a principal
// before the proxy runs. It was discarded at the boundary, and this file is the
// boundary.
//
// ## THE ONE THING, STATED
//
// **A request to a non-public `ROUTE_TABLE` upstream carries a short-lived signed
// assertion of who the caller is. A request to a public one carries nothing,
// ever.**
//
// ## WHY IT IS A JWT AND NOT A HEADER
//
// Because the upstream has to be able to *verify* it without trusting the
// network, and "the header said so" is not a fact a service can check. A compact
// JWS over a minimal claim set is the smallest object that carries a signature an
// independent service can check with an off-the-shelf verifier.
//
// ## WHY IT IS NOT THE CALLER'S TOKEN, AND CANNOT BECOME ONE
//
// Two reasons, and the second is the one that would survive a well-meaning
// refactor.
//
//   1. The caller's token was minted for a *different audience*. Forwarding it
//      makes guard a credential relay for a token issued to something else, and
//      the upstream has no way to narrow what it accepts.
//   2. The claim set would be the caller's whole JWT. MD19's fourth property is
//      *minimal claims* — what the upstream is declared to need, not the JWT —
//      and a forwarded token is the opposite of minimal by construction: the
//      caller decides what is in it.
//
// ## THE SIGNING KEY, AND WHY IT IS NOT THE JWKS ONE
//
// guard already validates RS256 against identity's published JWKS, and the reuse
// actually available is the *library and the shape*, not the key: a JWKS is
// public keys by definition and cannot sign. Inventing a second key store would
// have been the easy mistake; reusing identity's would have been the dangerous
// one, because a key that can sign is a key that can mint anything identity can
// mint.
//
// So guard holds **its own** RS256 key, configured as a file path rather than an
// environment value — a private key in an environment variable turns up in
// `docker inspect`, in `/proc/<pid>/environ` and in any crash dump, and this
// repository already refuses a base URL carrying a password for exactly the
// reason it refuses a credential that reaches a log.
//
// The public half is exposed as a JWK (`publicJwk`) rather than over an HTTP
// endpoint, and that is a decision rather than an omission. Publishing it at
// `/.well-known/jwks.json` would add a route to the public edge of the gateway:
// a new operation in `openapi/v1.yaml`, six `registeredAt` anchors to move in
// `account_scope.yml`, and a `surface.minimum` this packet has no standing to
// move — all of it for something no *caller* needs. The upstream is already
// configured out of band (it needs guard's `token` the same way), so the key
// travels the same road the `token` already travels. MD19 asks for both halves to
// be written; the verifying half is the next packet's job in pantry, and this is
// the half guard owes it.
//
// ## BOUND TO THE UPSTREAM, AND WHY THE AUDIENCE IS AN ORIGIN
//
// `aud` is the upstream's `baseUrl` origin, which `table.ts` has already reduced
// to `url.origin`. A leaked assertion is therefore worth nothing on any other
// upstream, which is MD19's third property, and it is checkable by any JWT
// verifier that has never heard of cafaye — no cafaye-specific claim to
// understand before the check works.
//
// The alternative was a second, tighter binding on the route *prefix*. It is
// deliberately absent: an upstream that verified the prefix would need a
// cafaye-aware verifier, so the binding would bind only in deployments that
// opted into it and be silently unenforced everywhere else. A binding that is
// available rather than enforced is documentation wearing a control's clothes.
//
// ## MINIMAL CLAIMS, AND WHY THE TABLE DECLARES THEM
//
// A route entry names the claims its upstream is declared to need, and guard
// asserts those and nothing else:
//
//     ROUTE_TABLE='{"/v1/pantry/services":{"baseUrl":"http://pantry:8080",
//                                      "principal":["sub","github_id"]}}'
//
// Two properties follow from the table saying it rather than guard guessing it.
//
//   * An upstream that declares nothing gets **no assertion at all**. That is the
//     honest reading of "declared": a service that has not said what it needs has
//     not asked, and minting one anyway would hand every service in a deployment
//     a credential it never agreed to hold. It also keeps the whole feature off
//     by default, which is what makes it additive to a deployed gateway.
//   * A claim the caller's token does not carry is **omitted**, not invented and
//     not refused. MD19 wants a publisher with no row to get a "no publisher
//     record" refusal rather than a silently minted one, and a missing `github_id`
//     has to reach pantry as a missing `github_id` for that to happen.
//
// The claims are copied **as the verified token carried them**, read from
// `principal.claims` rather than from guard's typed `Principal`. So `scope` stays
// the space-separated string identity signed rather than becoming the array guard
// parsed it into, and `github_id` — which is not a field on `Principal` at all —
// crosses without guard having to be taught its name. guard is a signer here, not
// a translator: reshaping a claim would make the assertion a *different* claim
// from the one identity verified, which is a second thing to get right for no
// gain.
import { calculateJwkThumbprint, exportJWK, SignJWT, type JWK } from "jose";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import type { Principal } from "../middleware/jwt";

/**
 * The header the assertion crosses in.
 *
 * A header of its own rather than a second `Authorization`, and the reason is the
 * same one `proxy.ts` gives for dropping the caller's: the table entry's `token`
 * is already in `authorization`, it is a *different* credential, and asking one
 * header to carry two answers to two questions is how a service ends up reading
 * the wrong one. The name is namespaced because it is not a standard header and
 * no proxy in the fleet should have an opinion about it.
 */
export const ASSERTION_HEADER = "x-cafaye-principal";

/** The issuer guard asserts when nothing is configured: an origin, like identity's. */
export const DEFAULT_ASSERTION_ISSUER = "https://guard.localhost";

/**
 * How long an assertion is good for, and how long it may be configured to be.
 *
 * Two minutes by default because the assertion is minted at the proxy and
 * verified by the service on the other end of the same request: the window only
 * has to cover one hop plus a clock skew, and MD19 asked for "minutes". The
 * ceiling is the half that matters, because a lifetime nobody may exceed cannot
 * be configured into something that is no longer short-lived — `30d` is a
 * refusal to boot naming the maximum, not a value that gets used.
 */
export const DEFAULT_ASSERTION_TTL_MS = 120_000;
export const MAX_ASSERTION_TTL_MS = 600_000;

/**
 * Claims guard owns, and which an entry naming one is refused for.
 *
 * These are the envelope: the audience that binds the assertion to an upstream,
 * the lifetime that keeps it short-lived, and the issuer that says which gateway
 * minted it. An operator who wrote one of these names into a route entry has not
 * decided what they meant — the same reasoning `routeTable` applies to an entry
 * that is `public` *and* carries a `token`, and refused for the same reason:
 * guessing would produce a token that verifies for a route it was not minted for,
 * which is the one outcome an assertion must never have.
 *
 * `sub` is deliberately NOT here. It is the caller, it is verified, and half the
 * upstreams in a gateway exist to answer questions about it.
 */
export const RESERVED_CLAIMS: readonly string[] = ["iss", "aud", "exp", "nbf", "iat", "jti"];

/** A guard signing key: the pair, and the id upstreams select it by. */
export type AssertionKey = {
  /**
   * The `kid`, or empty for "derive it from the key" — see `readAssertionKey`.
   * Empty rather than absent because it is not optional in a way that changes the
   * shape: `createApp` builds this object and never reads the distinction.
   */
  keyId: string;
  /** Signs. Never leaves the process, and is never published. */
  privateKey: KeyObject;
  /** What `publicJwk` exports. Held separately, and that is load-bearing. */
  publicKey: KeyObject;
};

export type AssertionOptions = {
  /** Who minted it. Defaults to `DEFAULT_ASSERTION_ISSUER`. */
  issuer?: string;
  key: AssertionKey;
  /** Defaults to `DEFAULT_ASSERTION_TTL_MS`; above `MAX_ASSERTION_TTL_MS` is refused. */
  ttlMs?: number;
  /** Clock, injected so a test can cross `exp` without sleeping. */
  now?: () => number;
};

/** What one mint is about: the upstream it is for, and the claims it may carry. */
export type AssertionSubject = {
  /**
   * The audience, which is the upstream's origin. `table.ts` has already reduced
   * `baseUrl` to `url.origin`, so this needs no parsing here — and parsing it
   * again would be a second spelling of "which upstream is this".
   */
  audience: string;
  /** The claims the route entry declared, in the order the operator wrote them. */
  claims: readonly string[];
};

/**
 * Mints assertions, and knows nothing about routing or about HTTP.
 *
 * The facts it is given per call are the verified principal and what the route
 * declared; what it does with them is the whole of its responsibility, which is
 * why it can be tested without a gateway and why the gateway's only decision is
 * *whether* to call it.
 */
export type AssertionMinter = {
  /** A compact JWS asserting `subject.claims` for `subject.audience`. */
  mint(principal: Principal, subject: AssertionSubject): Promise<string>;
  /** The public half, for an upstream's key set. Memoised on first call. */
  publicJwk(): Promise<JWK>;
  /** The key id the assertion's protected header names. Derived if not configured. */
  readonly keyId: string;
};

/**
 * Builds the minter, validating everything configuration can get wrong here.
 *
 * The issuer and the lifetime are refusals at construction rather than at request
 * time, for the reason `createJwtVerifier` gives: a typo in an environment
 * variable should be a startup failure and not a 503 on every request. The clock
 * is injected rather than read so a test can assert expiry without sleeping — an
 * expiry test that sleeps is an expiry test that is slow, and then skipped.
 */
export function createAssertionMinter(options: AssertionOptions): AssertionMinter {
  const issuer = parseIssuer(options.issuer ?? DEFAULT_ASSERTION_ISSUER);
  const ttlMs = options.ttlMs ?? DEFAULT_ASSERTION_TTL_MS;
  const now = options.now ?? Date.now;

  assertTtl(ttlMs);

  const { privateKey } = options.key;
  // The resolved key id, which is the thumbprint when none was configured. The
  // export is async (jose's `exportJWK`), so this is resolved on first use and
  // memoised: a key id that changed between two requests would be a key set no
  // upstream could select from, and the failure would be entirely on their side.
  let published: Promise<JWK> | undefined;
  const resolve = (): Promise<JWK> => {
    published ??= publish(options.key);
    return published;
  };

  return {
    keyId: options.key.keyId,

    publicJwk: resolve,

    async mint(principal: Principal, subject: AssertionSubject): Promise<string> {
      const seconds = Math.floor(now() / 1000);
      const { kid } = await resolve();

      return new SignJWT(envelope(issuer, subject, seconds, ttlMs, principal))
        .setProtectedHeader({ alg: "RS256", kid })
        // Computed from the same `seconds` as `iat`, so the window is exactly
        // `ttlMs` and cannot drift by a rounding of `now()` — which is the kind
        // of thing that is only visible in production.
        .setIssuedAt(seconds)
        .setExpirationTime(seconds + Math.floor(ttlMs / 1000))
        .sign(privateKey);
    },
  };
}

/**
 * The claim set: guard's envelope, then the declared claims that exist.
 *
 * `nbf` is deliberately absent. guard is the signer and the audience is one hop
 * away, so a `not-before` on a token minted microseconds ago buys a skew window
 * nobody configured and refuses nothing — an upstream that enforces it rejects a
 * token it should have accepted.
 *
 * `jti` is here and is not decoration. It makes two assertions for the same caller
 * on the same route differ byte for byte, which is what lets an upstream log and
 * correlate one without being able to replay either — and it is asserted in the
 * tests rather than merely claimed, because a `jti` that is accidentally constant
 * is a field nobody reads and nobody notices.
 *
 * The envelope is spread **first**, so a declared claim could not overwrite it
 * even if the reserved-name check in `routeTable` were removed. That ordering is
 * the second of the two gates on MD19's "bound to the upstream", and like the
 * other one it is redundant on purpose: a security property that depends on a
 * validation three files away is a property that is one refactor away from gone.
 */
function envelope(
  issuer: string,
  subject: AssertionSubject,
  seconds: number,
  ttlMs: number,
  principal: Principal,
): Record<string, unknown> {
  return {
    iss: issuer,
    aud: subject.audience,
    iat: seconds,
    exp: seconds + Math.floor(ttlMs / 1000),
    jti: jti(),
    ...declared(principal, subject.claims),
  };
}

/**
 * The declared claims, as the verified token carried them.
 *
 * A name the caller's token does not hold is skipped rather than refused, and the
 * comment above says why. `sub` is included from `principal.sub` when the claim
 * set happens not to name it, because every verified principal in this repository
 * has one and an assertion that dropped the subject would be useless — but the
 * *declared* set still governs, so an entry that asked for nothing does not get it.
 */
function declared(principal: Principal, names: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of names) {
    // `Object.hasOwn` rather than `in`: a claim named `constructor` or `toString`
    // is a claim an operator can write in JSON, and reading it off the prototype
    // would put a *function* in a signed token for an upstream to decode.
    if (Object.hasOwn(principal.claims, name)) out[name] = principal.claims[name];
  }

  if (Object.hasOwn(principal, "sub") && !Object.hasOwn(out, "sub")) {
    out.sub = principal.sub;
  }

  return out;
}

/** A correlation id that is not a constant, and is never a secret. */
function jti(): string {
  return crypto.randomUUID();
}

/**
 * Reads a PKCS#8 PEM into a signing key.
 *
 * Synchronous on purpose. `jose`'s `importPKCS8` is async, and awaiting it would
 * mean a malformed key is discovered on the first proxied request rather than at
 * startup — which is the same defect `REDIS_URL=redis//redis` refusing to boot is
 * not. Node's `createPrivateKey` parses a PKCS#8 PEM synchronously and throws on
 * anything else, so both a missing file (the caller reads it) and a malformed one
 * (this) are startup errors.
 *
 * `keyId` is optional and the default is the RFC 7638 thumbprint of the public
 * key. That is not cosmetic: an operator-invented `kid` that two deployments both
 * call `guard-1` is a key set in which an upstream silently verifies against the
 * wrong deployment's key, and a thumbprint cannot collide across keys. An
 * explicit id is still accepted, for an operator who wants a short stable name in
 * a key set they publish by hand — and the trade is that a hand-published id is
 * one guard cannot check, which is the whole reason it is not the default.
 */
export function readAssertionKey(pem: string, keyId?: string): AssertionKey {
  const privateKey = createPrivateKey(pem);

  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new RangeError(
      `createAssertionMinter: the assertion signing key must be RSA, got ${String(privateKey.asymmetricKeyType)}. ` +
        `The algorithm is a property of this process's key, not a hint a token carries — the same rule ` +
        `src/middleware/jwt.ts pins for the keys it verifies — so an EC key is refused rather than signed with ` +
        `under an RS256 header.`,
    );
  }

  // Both halves, deliberately. Node derives the public key from the private one,
  // and `publish` is handed THIS rather than re-deriving it from `privateKey` —
  // because `exportJWK` on a private `KeyObject` returns the private key, primes
  // and all. See `publish`.
  return { keyId: keyId ?? "", privateKey, publicKey: createPublicKey(privateKey) };
}

/**
 * The public half, with the id in it. Memoised by the caller.
 *
 * ## THE PUBLIC HALF IS TAKEN FROM `publicKey`, NOT FROM `privateKey`
 *
 * Measured in this repository, not assumed: `exportJWK` given a Node **private**
 * `KeyObject` returns `kty, n, e, d, p, q, dp, dq, qi` — the whole private key,
 * RSA primes included. The first draft of this function exported the private key
 * it had been handed, which would have handed every upstream guard's signing key
 * along with the public half, and the key id would still have been correct
 * because RFC 7638 hashes only `e`, `kty` and `n`. So nothing about the token set
 * would have looked wrong.
 *
 * That is why `AssertionKey` carries both halves rather than just the private
 * one, and why `assertion.test.ts` asserts the published JWK's field names
 * exactly rather than merely that it verifies. The tempting shortcut —
 * `exportJWK(key.privateKey)` — produces something that works and that is a
 * private key.
 */
async function publish(key: AssertionKey): Promise<JWK> {
  const bare = await exportJWK(key.publicKey as never);
  const kid = key.keyId === "" ? await calculateJwkThumbprint(bare as never, "sha256") : key.keyId;

  // `alg` and `use` are what a real key set carries and this one will be verified
  // by; a set that omits them is legal and says less. Publishing them also stops
  // an upstream accepting this key for anything but a signature, which is the only
  // use this process has for it.
  return { ...bare, kid, alg: "RS256", use: "sig" };
}

/** An absolute http(s) origin with no path, mirroring `parseIssuer` in `jwt.ts`. */
function parseIssuer(value: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new RangeError("createAssertionMinter: issuer must be a non-empty string");
  }

  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new RangeError(`createAssertionMinter: issuer must be an absolute URL, got ${JSON.stringify(value)}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RangeError(`createAssertionMinter: issuer must be http(s), got ${JSON.stringify(value)}`);
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RangeError(
      `createAssertionMinter: issuer must be a base URL with no path, got ${JSON.stringify(value)}. An upstream ` +
        `verifies it to learn which gateway minted the assertion, so it names the gateway rather than a route on it.`,
    );
  }

  return url.origin;
}

/** An integer of milliseconds, and no more than the ceiling. */
function assertTtl(ttlMs: number): void {
  if (!Number.isInteger(ttlMs) || ttlMs < 1) {
    throw new RangeError(`createAssertionMinter: ttlMs must be an integer >= 1, got ${String(ttlMs)}`);
  }
  if (ttlMs > MAX_ASSERTION_TTL_MS) {
    throw new RangeError(
      `createAssertionMinter: ttlMs must be at most ${MAX_ASSERTION_TTL_MS}, got ${ttlMs}. An assertion is minted ` +
        `for one hop and verified by the service on the other end of it; a window of minutes is the whole of what ` +
        `it is for, and a lifetime nobody may exceed cannot be configured into something that is no longer ` +
        `short-lived.`,
    );
  }
}