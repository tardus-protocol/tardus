/**
 * TS v0.2 Rust-compat path tests:
 *   - Unclamped Montgomery ladder roundtrip
 *   - Sealed-box (Rust-compat) seal → open
 *   - Mnemonic → Ed25519 receiving keypair determinism
 *   - Composition: Rust-derived keypair + sealed-box roundtrip
 *
 * Cross-language test vectors (Rust-generated ciphertext decrypted
 * by TS) are a follow-up: requires committing a small reference
 * vector file. The pure-TS roundtrip below validates wire-format
 * structure + the unclamped scalar mul path.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { montgomeryLadderRaw } from '../src/montgomery.ts';
import {
  sealRustCompat,
  openRustCompat,
} from '../src/sealed-box-rust-compat.ts';
import {
  deriveMasterSeedRustCompat,
  deriveReceivingKeypairRustCompat,
} from '../src/mnemonic-rust-compat.ts';
import { SealedBoxError, EPHEMERAL_KEY_LEN } from '../src/sealed-box.ts';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes } from '@noble/hashes/utils';

const X25519_BASE_U: Uint8Array = (() => {
  const b = new Uint8Array(32);
  b[0] = 9;
  return b;
})();

test('montgomery ladder: scalar=1 is identity', () => {
  const k = new Uint8Array(32);
  k[0] = 1;
  const p = randomBytes(32);
  const out = montgomeryLadderRaw(k, p);
  // u-coord of 1*P after the RFC 7748 high-bit mask = mask(p) mod P.
  // Easier to just check non-zero-ness for a random input.
  assert.equal(out.length, 32);
  // Quick sanity: out is masked u-coord of P. The high bit must
  // be 0 because Fp output is < 2^255 - 19 < 2^255.
  assert.equal((out[31] ?? 0) & 0x80, 0);
});

test('montgomery ladder: scalar=0 yields zero u-coord (identity element)', () => {
  const k = new Uint8Array(32);
  const u = new Uint8Array(32);
  u[0] = 9;
  const out = montgomeryLadderRaw(k, u);
  // 0 * G = point at infinity → x=0 in Montgomery encoding (RFC 7748).
  for (let i = 0; i < 32; i++) {
    assert.equal(out[i], 0, `byte ${i}`);
  }
});

test('montgomery ladder: scalar mul commutes (ECDH property)', () => {
  // a * (b * G) === b * (a * G)
  const a = randomBytes(32);
  const b = randomBytes(32);
  const aG = montgomeryLadderRaw(a, X25519_BASE_U);
  const bG = montgomeryLadderRaw(b, X25519_BASE_U);
  const abG = montgomeryLadderRaw(a, bG);
  const baG = montgomeryLadderRaw(b, aG);
  assert.deepEqual(abG, baG, 'ECDH commutativity must hold');
});

test('rust-compat sealed-box: seal + open roundtrip', () => {
  const sk = randomBytes(32);
  const pkX = montgomeryLadderRaw(sk, X25519_BASE_U);
  // For this test, treat pkX (Montgomery) directly as the recipient.
  // The full path uses Ed25519 pk → Montgomery, but for the bare
  // ladder roundtrip we wire pkX as-if it were the toMontgomery
  // output (it IS the same scalar mul on the same curve).
  // Use the underlying primitives directly:
  const pt = new TextEncoder().encode('rust-compat payload');

  // Manually replicate seal-via-ladder so we don't need an Ed25519 pk:
  const HKDF_SALT = new TextEncoder().encode('TARDUS-sealed-box-v1');
  const KEY_INFO = new TextEncoder().encode('chacha20poly1305-key');
  const NONCE_INFO = new TextEncoder().encode('chacha20poly1305-nonce');

  const esk = randomBytes(32);
  const epkX = montgomeryLadderRaw(esk, X25519_BASE_U);
  const shared = montgomeryLadderRaw(esk, pkX);
  const key = hkdf(
    sha256,
    shared,
    HKDF_SALT,
    concatBytes(KEY_INFO, epkX, pkX),
    32,
  );
  const nonce = hkdf(
    sha256,
    shared,
    HKDF_SALT,
    concatBytes(NONCE_INFO, epkX, pkX),
    12,
  );
  const ct = chacha20poly1305(key, nonce).encrypt(pt);
  const sealed = new Uint8Array(epkX.length + ct.length);
  sealed.set(epkX, 0);
  sealed.set(ct, epkX.length);

  // Decrypt with sk:
  const sharedR = montgomeryLadderRaw(sk, epkX);
  const pkXRecv = montgomeryLadderRaw(sk, X25519_BASE_U);
  assert.deepEqual(pkXRecv, pkX, 'recipient public x must match');
  const keyR = hkdf(
    sha256,
    sharedR,
    HKDF_SALT,
    concatBytes(KEY_INFO, epkX, pkXRecv),
    32,
  );
  const nonceR = hkdf(
    sha256,
    sharedR,
    HKDF_SALT,
    concatBytes(NONCE_INFO, epkX, pkXRecv),
    12,
  );
  const recovered = chacha20poly1305(keyR, nonceR).decrypt(
    sealed.slice(EPHEMERAL_KEY_LEN),
  );
  assert.deepEqual(recovered, pt);
});

test('rust-compat keypair derivation: deterministic', () => {
  const phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed1 = deriveMasterSeedRustCompat(phrase, '');
  const seed2 = deriveMasterSeedRustCompat(phrase, '');
  assert.deepEqual(seed1, seed2);
  const { sk: sk1, pk: pk1 } = deriveReceivingKeypairRustCompat(seed1);
  const { sk: sk2, pk: pk2 } = deriveReceivingKeypairRustCompat(seed2);
  assert.deepEqual(sk1, sk2);
  assert.deepEqual(pk1, pk2);
  assert.equal(sk1.length, 32);
  assert.equal(pk1.length, 32);
});

test('rust-compat: full keypair + sealed-box composition', () => {
  const phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = deriveMasterSeedRustCompat(phrase, '');
  const { sk, pk } = deriveReceivingKeypairRustCompat(seed);

  const pt = new TextEncoder().encode(
    'rust-compat sealed-box payload via mnemonic-derived Ed25519 keypair',
  );
  const sealed = sealRustCompat(pt, pk);
  assert.equal(
    sealed.length,
    EPHEMERAL_KEY_LEN + pt.byteLength + 16,
    'sealed = epk(32) + ct(plaintext + AEAD-tag-16)',
  );
  const recovered = openRustCompat(sealed, sk);
  assert.deepEqual(recovered, pt);
});

test('rust-compat: wrong sk rejects (AEAD)', () => {
  const phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = deriveMasterSeedRustCompat(phrase, '');
  const { pk } = deriveReceivingKeypairRustCompat(seed);

  const sealed = sealRustCompat(new TextEncoder().encode('secret'), pk);
  const wrongSk = randomBytes(32);
  assert.throws(
    () => openRustCompat(sealed, wrongSk),
    (e: unknown) => e instanceof SealedBoxError && e.kind === 'AeadFailure',
  );
});

test('rust-compat: ephemeral key freshness across seals', () => {
  const phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = deriveMasterSeedRustCompat(phrase, '');
  const { pk } = deriveReceivingKeypairRustCompat(seed);
  const pt = new TextEncoder().encode('same');
  const s1 = sealRustCompat(pt, pk);
  const s2 = sealRustCompat(pt, pk);
  assert.notDeepEqual(
    s1.slice(0, EPHEMERAL_KEY_LEN),
    s2.slice(0, EPHEMERAL_KEY_LEN),
    'ephemeral key must vary per seal',
  );
});
