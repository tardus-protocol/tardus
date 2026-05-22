/**
 * BIP-39 + receiving-identity derivation — Rust-compatible variant.
 *
 * Mirrors `crates/tardus-wallet/src/mnemonic.rs::derive_receiving_keypair`
 * EXACTLY:
 *
 *   1. master_seed = first 32 bytes of PBKDF2-HMAC-SHA-512(mnemonic, passphrase).
 *   2. wide = HKDF-SHA-512(salt="TARDUS-recv-id-v1", ikm=master_seed,
 *                          info="ed25519-keypair", length=64).
 *   3. sk_scalar = wide as little-endian bigint, reduce mod ℓ.
 *   4. pk_edwards = (sk_scalar * Ed25519_BASE).compress()  — 32 bytes.
 *   5. sk_bytes = scalar as 32 little-endian bytes.
 *
 * This produces an Ed25519-compressed pubkey (Edwards y || sign-of-x),
 * usable with `sealed-box-rust-compat.ts`.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hkdf } from '@noble/hashes/hkdf';
import { sha512 } from '@noble/hashes/sha512';
import { ed25519 } from '@noble/curves/ed25519';

const RECV_ID_SALT = new TextEncoder().encode('TARDUS-recv-id-v1');
const RECV_ID_INFO = new TextEncoder().encode('ed25519-keypair');

/** Ed25519 group order ℓ. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

export function deriveMasterSeedRustCompat(
  phrase: string,
  passphrase = '',
): Uint8Array {
  if (!validateMnemonic(phrase, wordlist)) {
    throw new Error('invalid BIP-39 mnemonic');
  }
  const seed64 = mnemonicToSeedSync(phrase, passphrase);
  return seed64.slice(0, 32);
}

/**
 * Returns `{ sk, pk }` where `sk` is the 32-byte canonical
 * Ed25519 scalar (little-endian) and `pk` is the 32-byte
 * Edwards-compressed pubkey. Both arrays are wire-format-byte-equal
 * with the Rust reference's `derive_receiving_keypair` output for
 * the same `masterSeed`.
 */
export function deriveReceivingKeypairRustCompat(masterSeed: Uint8Array): {
  sk: Uint8Array;
  pk: Uint8Array;
} {
  if (masterSeed.length !== 32) {
    throw new Error(`masterSeed must be 32 bytes, got ${masterSeed.length}`);
  }
  const wide = hkdf(sha512, masterSeed, RECV_ID_SALT, RECV_ID_INFO, 64);

  let acc = 0n;
  for (let i = wide.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(wide[i] ?? 0);
  }
  const skScalar = acc % L;

  const sk = new Uint8Array(32);
  let v = skScalar;
  for (let i = 0; i < 32; i++) {
    sk[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const pk = ed25519.ExtendedPoint.BASE.multiply(skScalar).toRawBytes();
  return { sk, pk };
}
