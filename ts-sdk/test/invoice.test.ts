/**
 * Invoice URI codec tests — symmetric round-trip + cross-format
 * compatibility with the Rust `tardus_client::invoice` reference.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeInvoice, parseInvoice } from '../src/invoice.ts';

test('encode then parse round-trip', () => {
  const recipient = new Uint8Array(32);
  for (let i = 0; i < 32; i++) recipient[i] = (i * 7 + 11) & 0xff;
  const inv = {
    recipientPubkey: recipient,
    denom: 1_000_000n,
    relays: [
      'https://relay-eu-west-1.tardus.example.com:9799',
      'https://relay-us-east-1.tardus.example.com:9799',
    ],
    memo: new TextEncoder().encode('thanks for the coffee'),
  };
  const uri = encodeInvoice(inv);
  assert.ok(uri.startsWith('tardus://'));
  const back = parseInvoice(uri);
  assert.deepEqual(back.recipientPubkey, inv.recipientPubkey);
  assert.equal(back.denom, inv.denom);
  assert.deepEqual(back.relays, inv.relays);
  assert.deepEqual(back.memo, inv.memo);
});

test('memo omitted is OK', () => {
  const recipient = new Uint8Array(32);
  const inv = {
    recipientPubkey: recipient,
    denom: 50_000n,
    relays: ['https://r1'],
  };
  const uri = encodeInvoice(inv);
  const back = parseInvoice(uri);
  assert.equal(back.memo, undefined);
});

test('reject wrong scheme', () => {
  assert.throws(() => parseInvoice('http://example.com'));
});

test('reject malformed pubkey length', () => {
  assert.throws(() => parseInvoice('tardus://abcd?denom=1&relay=https://r'));
});

test('reject missing denom', () => {
  const pk = '00'.repeat(32);
  assert.throws(() => parseInvoice(`tardus://${pk}?relay=https://r`));
});

test('reject missing relay', () => {
  const pk = '00'.repeat(32);
  assert.throws(() => parseInvoice(`tardus://${pk}?denom=1`));
});

test('reject oversize memo (after base64 decode)', () => {
  const pk = '00'.repeat(32);
  // 200 'A's base64-encoded ≈ 268 chars, decode → 200 bytes > 128 cap.
  const memo = 'A'.repeat(200);
  const b64 = btoa(memo).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  assert.throws(() =>
    parseInvoice(`tardus://${pk}?denom=1&relay=https://r&memo=${b64}`),
  );
});

test('forward-compat: unknown query keys tolerated', () => {
  const pk = '00'.repeat(32);
  const inv = parseInvoice(`tardus://${pk}?denom=1&relay=https://r&future=value`);
  assert.equal(inv.denom, 1n);
});
