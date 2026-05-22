/**
 * Receiving-identity derivation — Phantom signMessage path.
 *
 * The user's TARDUS receiving identity is derived deterministically
 * from a fixed-message Ed25519 signature produced by their connected
 * wallet. No separate mnemonic is shown or stored.
 *
 * Properties:
 *   - same wallet + same canonical message → same receiving identity
 *   - identity never persists outside React state (closes tab → gone)
 *   - signature is the only sensitive value, never leaves the browser
 *   - returning visits re-derive by re-signing the same message
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import { deriveReceivingKeypair } from '@tardus/sdk'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'

/** Canonical message every TARDUS dApp signs to derive the same identity. */
export const TARDUS_DERIVATION_MESSAGE =
  'TARDUS receiving identity derivation v1'

export interface ReceivingIdentity {
  /** 32-byte ed25519 receiving public key (used as `tardus://` host). */
  receivingPubkey: Uint8Array
  /** 32-byte receiving secret scalar (unclamped Curve25519 form). */
  receivingSecret: Uint8Array
  /** Hex of `receivingPubkey` for display + invoice URI. */
  receivingPubkeyHex: string
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Convert a 64-byte Ed25519 signature into a 32-byte receiving-identity
 * seed via HKDF-SHA-256 with a TARDUS-specific domain separator.
 *
 * Using HKDF (not raw `sig.slice(0,32)`) gives:
 *   - cryptographic separation: the seed is bound to a TARDUS domain,
 *     so even if the same wallet signs a similar message for another
 *     dApp the resulting identities differ.
 *   - uniform output: HKDF whitens any structural bias in the
 *     signature bytes.
 */
function seedFromSignature(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) {
    throw new Error(`expected 64-byte signature, got ${sig.length}`)
  }
  const info = new TextEncoder().encode('tardus-recv-derivation-v1')
  return hkdf(sha256, sig, undefined, info, 32)
}

/**
 * Derive a receiving identity from a wallet's Ed25519 signature on the
 * canonical TARDUS derivation message.
 *
 * Callers typically do:
 *
 *   const sig = await wallet.signMessage(
 *     new TextEncoder().encode(TARDUS_DERIVATION_MESSAGE),
 *   )
 *   const id = deriveReceivingIdentity(sig)
 */
export function deriveReceivingIdentity(sig: Uint8Array): ReceivingIdentity {
  const seed = seedFromSignature(sig)
  const { pk, sk } = deriveReceivingKeypair(seed)
  return {
    receivingPubkey: pk,
    receivingSecret: sk,
    receivingPubkeyHex: bytesToHex(pk),
  }
}
