/**
 * BIP-39 mnemonic + receiving-identity derivation tests.
 * Includes the cross-language regression vector: the canonical
 * BIP-39 "abandon abandon ... about" mnemonic must produce a
 * specific master seed prefix matching the Rust reference.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveMasterSeed,
  deriveReceivingKeypair,
  generateTardusMnemonic,
  isValidMnemonic,
} from '../src/mnemonic.ts';
import { seal, open } from '../src/sealed-box.ts';

const TEST_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const EXPECTED_MASTER_SEED_PREFIX = '5eb00bbddcf069084889a8ab9155568165f5c453';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

test('BIP-39 canonical "abandon × 11 about" matches reference seed', () => {
  const seed = deriveMasterSeed(TEST_PHRASE, '');
  assert.equal(seed.length, 32);
  const hex = bytesToHex(seed);
  assert.ok(
    hex.startsWith(EXPECTED_MASTER_SEED_PREFIX),
    `master seed prefix mismatch: got ${hex.slice(0, 40)}…, expected ${EXPECTED_MASTER_SEED_PREFIX}…`,
  );
});

test('mnemonic validate rejects bad phrase', () => {
  assert.equal(isValidMnemonic('not a real mnemonic at all'), false);
  assert.equal(isValidMnemonic(TEST_PHRASE), true);
});

test('generate 24-word mnemonic is valid + deterministic structure', () => {
  const m = generateTardusMnemonic(24);
  assert.equal(m.split(' ').length, 24);
  assert.equal(isValidMnemonic(m), true);
});

test('generate 12-word mnemonic', () => {
  const m = generateTardusMnemonic(12);
  assert.equal(m.split(' ').length, 12);
  assert.equal(isValidMnemonic(m), true);
});

test('receiving keypair is deterministic from master seed', () => {
  const seed1 = deriveMasterSeed(TEST_PHRASE, '');
  const seed2 = deriveMasterSeed(TEST_PHRASE, '');
  assert.deepEqual(seed1, seed2);

  const { sk: sk1, pk: pk1 } = deriveReceivingKeypair(seed1);
  const { sk: sk2, pk: pk2 } = deriveReceivingKeypair(seed2);
  assert.deepEqual(sk1, sk2);
  assert.deepEqual(pk1, pk2);
  assert.equal(pk1.length, 32);
  assert.equal(sk1.length, 32);
});

test('receiving keypair roundtrips with sealed-box', () => {
  const seed = deriveMasterSeed(TEST_PHRASE, '');
  const { sk, pk } = deriveReceivingKeypair(seed);
  const pt = new TextEncoder().encode('sealed payload via mnemonic-derived recv keypair');
  const sealed = seal(pt, pk);
  const recovered = open(sealed, sk);
  assert.deepEqual(recovered, pt);
});

test('passphrase changes derived seed', () => {
  const a = deriveMasterSeed(TEST_PHRASE, '');
  const b = deriveMasterSeed(TEST_PHRASE, 'extra-pass');
  assert.notDeepEqual(a, b, 'passphrase must affect seed');
});
