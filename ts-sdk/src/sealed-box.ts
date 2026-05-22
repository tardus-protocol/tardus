/**
 * TARDUS Sealed-Box AEAD — TypeScript implementation.
 *
 * Mirrors the Rust reference at
 * `crates/tardus-wallet/src/sealed_box.rs` (spec v1.6 §9.6).
 *
 * Construction (NaCl `crypto_box_seal` adapted for Ed25519 recipient
 * keys):
 *
 *   1. Sender samples ephemeral X25519 keypair (esk, epk).
 *   2. Recipient ed25519 pk → Montgomery (X25519) via RFC 7748 §5.
 *   3. ECDH shared = esk * recipient_X25519_pk.
 *   4. (key, nonce) =
 *        HKDF-SHA-256(salt="TARDUS-sealed-box-v1",
 *                     ikm=shared,
 *                     info=epk || recipient_X25519_pk)
 *   5. ChaCha20-Poly1305(key, nonce, plaintext) → ciphertext.
 *   6. Wire bytes: epk(32) || ciphertext_with_tag.
 *
 * Recipient inverts 1-5 with its ed25519 sk → X25519 sk.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes } from '@noble/hashes/utils';

const HKDF_SALT = new TextEncoder().encode('TARDUS-sealed-box-v1');
const KEY_INFO = new TextEncoder().encode('chacha20poly1305-key');
const NONCE_INFO = new TextEncoder().encode('chacha20poly1305-nonce');

export const EPHEMERAL_KEY_LEN = 32;

export class SealedBoxError extends Error {
  readonly kind: string;
  constructor(kind: string, message: string) {
    super(message);
    this.name = 'SealedBoxError';
    this.kind = kind;
  }
}

/**
 * **TS v0.1**: the TS SDK uses X25519-format recipient keys
 * directly (see `mnemonic.ts` for the keypair derivation). The
 * Rust reference uses Ed25519 keys with a birational map; full
 * Rust↔TS cross-decryption is a v0.2 work item.
 */
function recipientPubAsX25519(pk: Uint8Array): Uint8Array {
  if (pk.length !== 32) {
    throw new SealedBoxError('BadRecipient', `pk must be 32 bytes, got ${pk.length}`);
  }
  return pk;
}

function recipientSkAsX25519Scalar(sk: Uint8Array): Uint8Array {
  if (sk.length !== 32) {
    throw new SealedBoxError('BadSecret', `sk must be 32 bytes, got ${sk.length}`);
  }
  return sk;
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

/**
 * Encrypt `plaintext` so only the holder of `recipientEd25519Pk`'s
 * matching secret key can read it. Returns wire bytes:
 * `ephemeral_x25519_pk(32) || ciphertext_with_aead_tag`.
 */
export function seal(plaintext: Uint8Array, recipientEd25519Pk: Uint8Array): Uint8Array {
  const recipientX = recipientPubAsX25519(recipientEd25519Pk);

  // Sample ephemeral X25519 keypair (noble handles clamping).
  const esk = x25519.utils.randomPrivateKey();
  const epk = x25519.getPublicKey(esk);

  // ECDH shared secret.
  const shared = x25519.getSharedSecret(esk, recipientX);

  // Derive AEAD key + nonce, bound to epk + recipient_X25519.
  const { key, nonce } = deriveKeyAndNonce(shared, epk, recipientX);

  const aead = chacha20poly1305(key, nonce);
  const ct = aead.encrypt(plaintext);

  const out = new Uint8Array(EPHEMERAL_KEY_LEN + ct.length);
  out.set(epk, 0);
  out.set(ct, EPHEMERAL_KEY_LEN);
  return out;
}

/**
 * Decrypt a `seal()` output using the matching ed25519 secret key
 * (raw 32-byte canonical scalar).
 */
export function open(sealed: Uint8Array, recipientEd25519Sk: Uint8Array): Uint8Array {
  const MIN_LEN = EPHEMERAL_KEY_LEN + 16;
  if (sealed.length < MIN_LEN) {
    throw new SealedBoxError(
      'SealedTooShort',
      `sealed blob too short: ${sealed.length} bytes (need ≥ ${MIN_LEN})`,
    );
  }
  const epk = sealed.slice(0, EPHEMERAL_KEY_LEN);
  const ct = sealed.slice(EPHEMERAL_KEY_LEN);

  const skScalar = recipientSkAsX25519Scalar(recipientEd25519Sk);
  const shared = x25519.getSharedSecret(skScalar, epk);
  const recipientPubX = x25519.getPublicKey(skScalar);

  const { key, nonce } = deriveKeyAndNonce(shared, epk, recipientPubX);
  const aead = chacha20poly1305(key, nonce);
  try {
    return aead.decrypt(ct);
  } catch (e) {
    throw new SealedBoxError('AeadFailure', `decrypt: ${(e as Error).message}`);
  }
}
