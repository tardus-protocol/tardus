/**
 * TARDUS `tardus://` invoice URI codec — TypeScript.
 *
 * Mirrors `crates/tardus-client/src/invoice.rs`. Wire format:
 *
 *   tardus://<recipient_pubkey_hex>?denom=<u64>&relay=<url>(&relay=<url>)*(&memo=<base64>)?
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

const SCHEME = 'tardus://';

export interface Invoice {
  recipientPubkey: Uint8Array; // 32 bytes
  denom: bigint;
  relays: string[];
  memo?: Uint8Array; // ≤ 128 bytes after decode
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hex length must be even, got ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hex parse failed at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  // Use built-in btoa for browser/node compat.
  let bin = '';
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin)
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64ToBytes(b64: string): Uint8Array {
  // Restore padding.
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const fullyPadded = padded + '='.repeat((4 - (padded.length % 4)) % 4);
  const bin = atob(fullyPadded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function encodeInvoice(inv: Invoice): string {
  if (inv.recipientPubkey.length !== 32) {
    throw new Error(`recipientPubkey must be 32 bytes, got ${inv.recipientPubkey.length}`);
  }
  if (inv.relays.length === 0) {
    throw new Error('invoice must include at least one relay');
  }
  const parts: string[] = [];
  parts.push(`denom=${inv.denom.toString()}`);
  for (const r of inv.relays) {
    parts.push(`relay=${encodeURIComponent(r)}`);
  }
  if (inv.memo) {
    if (inv.memo.length > 128) {
      throw new Error(`memo must be ≤ 128 bytes, got ${inv.memo.length}`);
    }
    parts.push(`memo=${bytesToBase64(inv.memo)}`);
  }
  return `${SCHEME}${bytesToHex(inv.recipientPubkey)}?${parts.join('&')}`;
}

export function parseInvoice(uri: string): Invoice {
  if (!uri.startsWith(SCHEME)) {
    throw new Error(`expected scheme ${SCHEME}, got ${uri.slice(0, 16)}…`);
  }
  const rest = uri.slice(SCHEME.length);
  const qIdx = rest.indexOf('?');
  if (qIdx < 0) {
    throw new Error('invoice URI must have a query string');
  }
  const pkHex = rest.slice(0, qIdx);
  if (pkHex.length !== 64) {
    throw new Error(`recipient pubkey hex must be 64 chars, got ${pkHex.length}`);
  }
  const recipientPubkey = hexToBytes(pkHex);

  let denom: bigint | undefined;
  const relays: string[] = [];
  let memo: Uint8Array | undefined;

  const query = rest.slice(qIdx + 1);
  for (const pair of query.split('&')) {
    if (pair.length === 0) continue;
    const eqIdx = pair.indexOf('=');
    if (eqIdx < 0) {
      throw new Error(`malformed query pair (no =): ${pair}`);
    }
    const key = pair.slice(0, eqIdx);
    const value = pair.slice(eqIdx + 1);
    switch (key) {
      case 'denom':
        denom = BigInt(value);
        break;
      case 'relay':
        relays.push(decodeURIComponent(value));
        break;
      case 'memo':
        memo = base64ToBytes(value);
        if (memo.length > 128) {
          throw new Error(`memo decoded to ${memo.length} bytes (max 128)`);
        }
        break;
      default:
        // Unknown keys: tolerate for forward-compat.
        break;
    }
  }
  if (denom === undefined) {
    throw new Error('invoice missing required `denom`');
  }
  if (relays.length === 0) {
    throw new Error('invoice must include at least one `relay`');
  }
  return { recipientPubkey, denom, relays, memo };
}
