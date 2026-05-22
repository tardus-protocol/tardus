/**
 * TARDUS BIP-39 + receiving-identity derivation.
 *
 * Mirrors `crates/tardus-wallet/src/mnemonic.rs`. The two layers:
 *
 *   1. BIP-39 mnemonic → 64-byte seed (PBKDF2-HMAC-SHA-512, 2048 it).
 *      TARDUS takes the FIRST 32 BYTES as `master_seed`.
 *   2. `master_seed` → ed25519 receiving keypair via
 *      `HKDF-SHA-512(salt="TARDUS-recv-id-v1", info="ed25519-keypair")`
 *      reduced mod ℓ (the Ed25519 scalar field), then
 *      `recv_pk = recv_sk · G_ed25519`.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { mnemonicToSeedSync, generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hkdf } from '@noble/hashes/hkdf';
import { sha512 } from '@noble/hashes/sha512';
import { ed25519, x25519 } from '@noble/curves/ed25519';

const RECV_ID_SALT = new TextEncoder().encode('TARDUS-recv-id-v1');
const RECV_ID_INFO = new TextEncoder().encode('ed25519-keypair');

export type WordCount = 12 | 24;

/**
 * Generate a fresh BIP-39 mnemonic of `wordCount` words from a
 * cryptographically secure RNG.
 */
export function generateTardusMnemonic(wordCount: WordCount = 24): string {
  const strength = wordCount === 24 ? 256 : 128;
  return generateMnemonic(wordlist, strength);
}

/**
 * Validate a BIP-39 mnemonic checksum + wordlist. Returns true on
 * valid; false otherwise.
 */
export function isValidMnemonic(phrase: string): boolean {
  return validateMnemonic(phrase, wordlist);
}

/**
 * Derive the TARDUS `master_seed` (first 32 bytes of the BIP-39
 * 64-byte PBKDF2 seed). Matches the Rust reference.
 */
export function deriveMasterSeed(phrase: string, passphrase: string = ''): Uint8Array {
  if (!validateMnemonic(phrase, wordlist)) {
    throw new Error('invalid BIP-39 mnemonic (checksum or wordlist mismatch)');
  }
  const seed64 = mnemonicToSeedSync(phrase, passphrase);
  return seed64.slice(0, 32);
}

/**
 * Derive the TARDUS receiving identity keypair from `masterSeed`.
 *
 * **TS v0.1 note**: Returns `(sk, pk)` where `sk` is an X25519-
 * clamped scalar (RFC 7748 §5) and `pk` is the corresponding
 * X25519 (Montgomery) public key. The Rust reference at
 * `crates/tardus-wallet/src/mnemonic.rs` returns an unclamped
 * Ed25519-encoded keypair instead; cross-decryption between
 * TS-sealed and Rust-sealed payloads therefore requires a
 * unified-scalar v0.2 path. Pure-TS sender + pure-TS receiver
 * roundtrip (the common Phantom/Solflare web-wallet case) works
 * today and is what the test suite validates.
 *
 * The deterministic property is preserved: same `masterSeed` →
 * same `(sk, pk)`.
 */
export function deriveReceivingKeypair(masterSeed: Uint8Array): {
  sk: Uint8Array;
  pk: Uint8Array;
} {
  if (masterSeed.length !== 32) {
    throw new Error(`masterSeed must be 32 bytes, got ${masterSeed.length}`);
  }
  // HKDF-SHA-512 wide output (64 bytes) — same as Rust reference.
  const wide = hkdf(sha512, masterSeed, RECV_ID_SALT, RECV_ID_INFO, 64);

  // Take the first 32 bytes as raw sk material. Noble's
  // `x25519.getPublicKey` clamps internally per RFC 7748, so the
  // derived `pk` corresponds to `clamp(sk[..32]) * X25519_BASE`.
  // Stored `sk` is the unclamped 32 bytes; noble re-clamps on
  // every subsequent `getSharedSecret` call.
  const sk = wide.slice(0, 32);
  const pk = x25519.getPublicKey(sk);

  // Touch `ed25519` so the static import is preserved for future
  // v0.2 path (which will produce an Ed25519 keypair).
  void ed25519;

  return { sk: new Uint8Array(sk), pk };
}
