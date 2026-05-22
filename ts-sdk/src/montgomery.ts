/**
 * Curve25519 Montgomery ladder — UNCLAMPED scalar multiplication.
 *
 * `@noble/curves`'s built-in `x25519.scalarMult` follows RFC 7748
 * §5 strictly and CLAMPS the scalar (clears bits 0,1,2 of byte 0;
 * clears bit 7 of byte 31; sets bit 6 of byte 31). TARDUS's Rust
 * reference at `crates/tardus-wallet/src/sealed_box.rs` uses
 * `curve25519_dalek::Scalar * MontgomeryPoint`, which performs
 * unclamped scalar multiplication with a canonical Ed25519 scalar
 * (mod ℓ).
 *
 * For Rust↔TS cross-decryption compatibility, the TS sealed-box
 * MUST use the same unclamped semantics. This module ships a
 * standalone Montgomery ladder (RFC 7748 Algorithm 1, but without
 * the scalar adjustment step) and is wired into
 * `sealed-box.ts`'s Rust-compat path.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

const P = 2n ** 255n - 19n;
const A24 = 121665n; // (486662 - 2) / 4 for Curve25519

function modP(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function modInvP(a: bigint): bigint {
  // Extended Euclidean modular inverse (Curve25519 prime is prime,
  // so this works for any non-zero a).
  let oldR = a;
  let r = P;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return modP(oldS);
}

function bytesToLeBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes[i] ?? 0);
  }
  return acc;
}

function leBigIntToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let acc = n;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(acc & 0xffn);
    acc >>= 8n;
  }
  return out;
}

/**
 * Unclamped Curve25519 Montgomery ladder. `scalarBytes` and
 * `uBytes` are 32-byte little-endian. Returns the 32-byte
 * little-endian Montgomery x-coordinate of `scalar * u`.
 *
 * Implements RFC 7748 Algorithm 1 WITHOUT the
 * `decodeScalar25519` clamping step. The Rust reference takes a
 * 32-byte canonical Ed25519 scalar (mod ℓ ≈ 2^252) and feeds it
 * directly to the ladder; we mirror that exactly.
 *
 * The upper bit of the Montgomery u-coordinate IS still masked
 * per RFC 7748 §5 ("decodeUCoordinate"): the high bit of
 * `uBytes[31]` is ignored, since Curve25519 points are defined
 * on Fp with p = 2^255 - 19. Without this, an attacker could
 * encode garbage in bit 255 and observe whether the receiver
 * caught it (a small but real distinguisher).
 */
export function montgomeryLadderRaw(
  scalarBytes: Uint8Array,
  uBytes: Uint8Array,
): Uint8Array {
  if (scalarBytes.length !== 32) {
    throw new Error(`scalar must be 32 bytes, got ${scalarBytes.length}`);
  }
  if (uBytes.length !== 32) {
    throw new Error(`u must be 32 bytes, got ${uBytes.length}`);
  }
  // Mask high bit of u per RFC 7748 §5.
  const uMasked = new Uint8Array(uBytes);
  uMasked[31] = (uMasked[31] ?? 0) & 0x7f;
  const k = bytesToLeBigInt(scalarBytes);
  const u = modP(bytesToLeBigInt(uMasked));

  let x1 = u;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = u;
  let z3 = 1n;
  let swap = 0n;

  // Ladder over the 255 most-significant bits. The Rust ref's
  // Ed25519 scalar is bounded by 2^252, so bits 252-254 are
  // always zero and the ladder is effectively bit-251 down.
  // We still iterate the full 255 bits to keep the loop count
  // input-independent (constant-iteration-count).
  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    if (swap === 1n) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;
    const a = modP(x2 + z2);
    const aa = modP(a * a);
    const b = modP(x2 - z2);
    const bb = modP(b * b);
    const e = modP(aa - bb);
    const c = modP(x3 + z3);
    const d = modP(x3 - z3);
    const da = modP(d * a);
    const cb = modP(c * b);
    const sum = modP(da + cb);
    const diff = modP(da - cb);
    x3 = modP(sum * sum);
    z3 = modP(x1 * (diff * diff));
    x2 = modP(aa * bb);
    z2 = modP(e * (aa + A24 * e));
  }
  if (swap === 1n) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }

  if (z2 === 0n) {
    // Result is the point at infinity. RFC 7748 specifies
    // returning a zero u-coordinate in this case.
    return new Uint8Array(32);
  }

  const result = modP(x2 * modInvP(z2));
  return leBigIntToBytes32(result);
}
