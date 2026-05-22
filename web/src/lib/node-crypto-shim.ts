/**
 * Browser shim for `node:crypto`'s `randomBytes`.
 * @tardus/sdk imports `randomBytes` from `node:crypto`; this file
 * provides the same function backed by the Web Crypto API so it
 * works under Vite without bundling Node internals.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

export function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len)
  crypto.getRandomValues(out)
  return out
}
