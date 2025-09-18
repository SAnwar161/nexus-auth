// src/lib/jwt.js
// JWT utilities for Cloudflare Workers using @tsndr/cloudflare-worker-jwt

import * as jwt from '@tsndr/cloudflare-worker-jwt';

// In Workers, env vars are passed at runtime. For local dev, fallback to process.env or a default.
const JWT_SECRET =
  (typeof process !== 'undefined' && process.env && process.env.JWT_SECRET) ||
  globalThis.JWT_SECRET ||
  'fallback-secret';

// Warn in local dev if using fallback
if (JWT_SECRET === 'fallback-secret') {
  console.warn(
    '⚠️ JWT_SECRET not set — using fallback-secret. Set it in wrangler.toml [vars] for production.'
  );
}

/**
 * Sign a JWT with the given payload
 * @param {Object} payload - e.g. { id, email, plan }
 * @returns {Promise<string>} Signed token
 */
export async function signJWT(payload) {
  return await jwt.sign(payload, JWT_SECRET);
}

/**
 * Verify a JWT and return the decoded payload if valid
 * @param {string} token
 * @returns {Promise<Object|false>} Decoded payload or false if invalid
 */
export async function verifyJWT(token) {
  const valid = await jwt.verify(token, JWT_SECRET);
  if (!valid) return false;
  return jwt.decode(token).payload;
}