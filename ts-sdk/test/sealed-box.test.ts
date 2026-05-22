/**
 * Sealed-box AEAD round-trip + cross-validation tests.
 *
 * Run with: `node --test --experimental-strip-types test/sealed-box.test.ts`
 * (Requires Node.js ≥ 22 for native TS strip + node:test.)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seal, open, SealedBoxError, EPHEMERAL_KEY_LEN } from '../src/sealed-box.ts';
import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'node:crypto';

/** TS v0.1 keypair: X25519 (Montgomery) directly. See note in mnemonic.ts. */
function fakePair(): { sk: Uint8Array; pk: Uint8Array } {
  const sk = randomBytes(32);
  const pk = x25519.getPublicKey(sk);
  return { sk, pk };
}

test('seal then open round-trip preserves plaintext', () => {
  const { sk, pk } = fakePair();
  const pt = new TextEncoder().encode('the quick brown fox jumps over the lazy dog');
  const sealed = seal(pt, pk);
  assert.ok(sealed.length >= EPHEMERAL_KEY_LEN + 16,
    `sealed must be >= EPHEMERAL_KEY_LEN + AEAD tag, got ${sealed.length}`);
  const recovered = open(sealed, sk);
  assert.deepEqual(recovered, pt);
});

test('wrong recipient cannot decrypt (AEAD failure)', () => {
  const alice = fakePair();
  const bob = fakePair();
  const pt = new TextEncoder().encode('hidden');
  const sealed = seal(pt, alice.pk);
  assert.throws(
    () => open(sealed, bob.sk),
    (e: unknown) => e instanceof SealedBoxError && e.kind === 'AeadFailure',
  );
});

test('tampered ciphertext rejected', () => {
  const { sk, pk } = fakePair();
  const sealed = seal(new TextEncoder().encode('payload'), pk);
  // Flip a byte in the ciphertext (past the 32-byte ephemeral pk).
  sealed[EPHEMERAL_KEY_LEN + 1] ^= 0x01;
  assert.throws(
    () => open(sealed, sk),
    (e: unknown) => e instanceof SealedBoxError && e.kind === 'AeadFailure',
  );
});

test('ephemeral key varies per seal call (forward secrecy property)', () => {
  const { pk } = fakePair();
  const pt = new TextEncoder().encode('same plaintext');
  const s1 = seal(pt, pk);
  const s2 = seal(pt, pk);
  const epk1 = s1.slice(0, EPHEMERAL_KEY_LEN);
  const epk2 = s2.slice(0, EPHEMERAL_KEY_LEN);
  assert.notDeepEqual(epk1, epk2, 'ephemeral key MUST be fresh per seal');
  assert.notDeepEqual(
    s1.slice(EPHEMERAL_KEY_LEN),
    s2.slice(EPHEMERAL_KEY_LEN),
    'ciphertext MUST differ when ephemeral key differs',
  );
});

test('short sealed blob rejected', () => {
  const sk = randomBytes(32);
  assert.throws(
    () => open(new Uint8Array(8), sk),
    (e: unknown) => e instanceof SealedBoxError && e.kind === 'SealedTooShort',
  );
});
