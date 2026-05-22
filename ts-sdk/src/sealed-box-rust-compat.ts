/**
 * TARDUS Sealed-Box AEAD — Rust-compatible variant.
 *
 * Wire-format-byte-equal with the Rust reference at
 * `crates/tardus-wallet/src/sealed_box.rs`. Uses an unclamped
 * Curve25519 Montgomery ladder (see `montgomery.ts`) and accepts
 * Ed25519-compressed recipient pubkeys (with on-the-fly Edwards
 * → Montgomery conversion via `@noble/curves`).
 *
 * **This is the v0.2 path.** The default `sealed-box.ts` ships
 * v0.1 (TS-only X25519-clamped, internally consistent but NOT
 * Rust-byte-equal).
 *
 * Construction:
 *   1. Sender samples ephemeral 32-byte scalar `esk` (mod ℓ).
 *   2. `epk_x = montgomeryLadderRaw(esk, X25519_BASE_U=9)`.
 *   3. `recipient_x = ed25519.utils.toMontgomery(recipient_ed_pk)`.
 *   4. `shared = montgomeryLadderRaw(esk, recipient_x)`.
 *   5. `(key, nonce) = HKDF-SHA-256(salt="TARDUS-sealed-box-v1",
 *                                    ikm=shared,
 *                                    info=epk_x || recipient_x)`.
 *   6. ChaCha20-Poly1305(key, nonce, plaintext) → ciphertext.
 *   7. Wire: `epk_x(32) || ciphertext_with_tag`.
 *
 * Receiver:
 *   1. Parse `epk_x`, `ct`.
 *   2. `recipient_x = montgomeryLadderRaw(sk, X25519_BASE_U=9)`.
 *   3. `shared = montgomeryLadderRaw(sk, epk_x)`.
 *   4. Derive (key, nonce); ChaCha20-Poly1305 decrypt.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes } from '@noble/hashes/utils';
import { randomBytes } from 'node:crypto';
import { montgomeryLadderRaw } from './montgomery.ts';
import { SealedBoxError, EPHEMERAL_KEY_LEN } from './sealed-box.ts';

const HKDF_SALT = new TextEncoder().encode('TARDUS-sealed-box-v1');
const KEY_INFO = new TextEncoder().encode('chacha20poly1305-key');
const NONCE_INFO = new TextEncoder().encode('chacha20poly1305-nonce');

/** Curve25519 base point u-coordinate (= 9 little-endian). */
const X25519_BASE_U: Uint8Array = (() => {
  const b = new Uint8Array(32);
  b[0] = 9;
  return b;
})();

/** Ed25519 group order ℓ = 2^252 + 27742317777372353535851937790883648493. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function sampleRustCompatScalar(): Uint8Array {
  // The Rust reference uses `Scalar::random(&mut OsRng)` which
  // samples a uniform scalar in [0, ℓ). We mirror that here:
  // rejection-sample by reducing mod ℓ from 64 random bytes.
  const wide = randomBytes(64);
  let acc = 0n;
  for (let i = wide.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(wide[i] ?? 0);
  }
  const reduced = acc % L;
  const out = new Uint8Array(32);
  let v = reduced;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function deriveKeyAndNonce(
  shared: Uint8Array,
  info1: Uint8Array,
  info2: Uint8Array,
): { key: Uint8Array; nonce: Uint8Array } {
  const keyInfo = concatBytes(KEY_INFO, info1, info2);
  const nonceInfo = concatBytes(NONCE_INFO, info1, info2);
  const key = hkdf(sha256, shared, HKDF_SALT, keyInfo, 32);
  const nonce = hkdf(sha256, shared, HKDF_SALT, nonceInfo, 12);
  return { key, nonce };
}

/** Rust-compat: encrypt for an Ed25519-compressed recipient pubkey. */
export function sealRustCompat(
  plaintext: Uint8Array,
  recipientEd25519Pk: Uint8Array,
): Uint8Array {
  if (recipientEd25519Pk.length !== 32) {
    throw new SealedBoxError(
      'BadRecipient',
      `recipient pk must be 32 bytes, got ${recipientEd25519Pk.length}`,
    );
  }
  let recipientX: Uint8Array;
  try {
    recipientX = ed25519.utils.toMontgomery(recipientEd25519Pk);
  } catch (e) {
    throw new SealedBoxError('BadRecipient', `pk → Montgomery: ${(e as Error).message}`);
  }

  const esk = sampleRustCompatScalar();
  const epkX = montgomeryLadderRaw(esk, X25519_BASE_U);
  const shared = montgomeryLadderRaw(esk, recipientX);
  const { key, nonce } = deriveKeyAndNonce(shared, epkX, recipientX);

  const aead = chacha20poly1305(key, nonce);
  const ct = aead.encrypt(plaintext);

  const out = new Uint8Array(EPHEMERAL_KEY_LEN + ct.length);
  out.set(epkX, 0);
  out.set(ct, EPHEMERAL_KEY_LEN);
  return out;
}

/** Rust-compat: decrypt with a canonical Ed25519 secret scalar. */
export function openRustCompat(
  sealed: Uint8Array,
  recipientEd25519Sk: Uint8Array,
): Uint8Array {
  const MIN_LEN = EPHEMERAL_KEY_LEN + 16;
  if (sealed.length < MIN_LEN) {
    throw new SealedBoxError(
      'SealedTooShort',
      `sealed too short: ${sealed.length} bytes`,
    );
  }
  if (recipientEd25519Sk.length !== 32) {
    throw new SealedBoxError(
      'BadSecret',
      `sk must be 32 bytes, got ${recipientEd25519Sk.length}`,
    );
  }
  const epkX = sealed.slice(0, EPHEMERAL_KEY_LEN);
  const ct = sealed.slice(EPHEMERAL_KEY_LEN);

  const recipientPubX = montgomeryLadderRaw(recipientEd25519Sk, X25519_BASE_U);
  const shared = montgomeryLadderRaw(recipientEd25519Sk, epkX);

  const { key, nonce } = deriveKeyAndNonce(shared, epkX, recipientPubX);
  const aead = chacha20poly1305(key, nonce);
  try {
    return aead.decrypt(ct);
  } catch (e) {
    throw new SealedBoxError('AeadFailure', `decrypt: ${(e as Error).message}`);
  }
}
