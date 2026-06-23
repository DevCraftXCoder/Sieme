// Hono middleware for Bearer token authentication.
// Uses Web Crypto SHA-256 digest + manual timing-safe XOR comparison.
// crypto.subtle.timingSafeEqual does NOT exist on the Web Crypto API — it is a
// Node.js crypto module method. Even with nodejs_compat, crypto.subtle remains the
// Web Crypto interface. The XOR loop below is the correct CF Workers pattern.
// Reference: packages/llm-gateway/src/auth.ts (same approach, key name changed).

import type { Context, Next } from "hono";
import type { Env, Variables } from "./types.js";

type AppContext = { Bindings: Env; Variables: Variables };

/**
 * Verify that the request carries `Authorization: Bearer <SIEMEN_API_KEY>`.
 *
 * Both the incoming token and the stored key are hashed to 32-byte SHA-256
 * digests before comparison. This eliminates any length pre-check that could
 * leak key length information via timing differences (CWE-208).
 *
 * Returns 401 when the header is absent, malformed, or the key does not match.
 */
export async function verifyAuth(c: Context<AppContext>, next: Next): Promise<Response | void> {
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "unauthorized" }, 401);
  }

  const token = authHeader.slice(7);
  const storedKey = c.env.SIEMEN_API_KEY;

  if (!storedKey) {
    // API key is not configured — fail closed.
    return c.json({ error: "unauthorized" }, 401);
  }

  const enc = new TextEncoder();
  const [tokenHash, keyHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(token)),
    crypto.subtle.digest("SHA-256", enc.encode(storedKey)),
  ]);

  // Timing-safe comparison via manual XOR loop over 32-byte SHA-256 digests.
  // crypto.subtle has no timingSafeEqual — that method lives on Node.js crypto only.
  const a = new Uint8Array(tokenHash);
  const b = new Uint8Array(keyHash);
  let diff = 0;
  for (let i = 0; i < 32; i += 1) {
    diff |= a[i] ^ b[i];
  }
  if (diff !== 0) {
    return c.json({ error: "unauthorized" }, 401);
  }

  // Store the token hash as the caller identity so the rate limiter can key on
  // a server-derived value — callers cannot bypass their budget by rotating headers.
  const hashHex = Array.from(new Uint8Array(tokenHash))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  c.set("callerHash", hashHex);

  return next();
}
