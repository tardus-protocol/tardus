/**
 * Dynamic Rust ↔ TS drift-detection test.
 *
 * Reads `test/fixtures/rust-vectors.json` (generated freshly by
 * the CI workflow `cross-language-compat.yml` from the latest
 * Rust example output), then asserts:
 *
 *   1. The Rust-emitted master_seed / recv_sk / recv_pk match
 *      what TS independently derives from the same mnemonic
 *      (catches any drift in `derive_master_seed` /
 *      `derive_receiving_keypair` between languages).
 *   2. The Rust-emitted sealed_box ciphertext decrypts under
 *      TS's openRustCompat to the original plaintext (catches
 *      any drift in `sealed_box::seal` wire format).
 *
 * Skipped when the fixture file is absent (local dev runs
 * `rust-cross-language.test.ts` with hardcoded vectors instead;
 * CI generates fresh fixtures every push).
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { test } from 'node:test';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';
import {
  deriveMasterSeedRustCompat,
  deriveReceivingKeypairRustCompat,
} from '../src/mnemonic-rust-compat.ts';
import { openRustCompat } from '../src/sealed-box-rust-compat.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_PATH = join(__dirname, 'fixtures', 'rust-vectors.json');

interface RustVectors {
  mnemonic: string;
  master_seed_hex: string;
  recv_sk_hex: string;
  recv_pk_hex: string;
  plaintext_hex: string;
  sealed_box_hex: string;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

const fixtureAvailable = existsSync(FIXTURE_PATH);

test(
  'CI dynamic fixture: Rust master_seed/recv_sk/recv_pk byte-equal in TS',
  { skip: !fixtureAvailable ? 'no fixture (run via cross-language-compat workflow)' : false },
  () => {
    const v = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as RustVectors;
    const seed = deriveMasterSeedRustCompat(v.mnemonic, '');
    assert.equal(bytesToHex(seed), v.master_seed_hex);
    const { sk, pk } = deriveReceivingKeypairRustCompat(seed);
    assert.equal(bytesToHex(sk), v.recv_sk_hex);
    assert.equal(bytesToHex(pk), v.recv_pk_hex);
  },
);

test(
  'CI dynamic fixture: TS decrypts fresh Rust-produced sealed_box',
  { skip: !fixtureAvailable ? 'no fixture (run via cross-language-compat workflow)' : false },
  () => {
    const v = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as RustVectors;
    const sk = hexToBytes(v.recv_sk_hex);
    const sealed = hexToBytes(v.sealed_box_hex);
    const recovered = openRustCompat(sealed, sk);
    assert.equal(bytesToHex(recovered), v.plaintext_hex);
  },
);
