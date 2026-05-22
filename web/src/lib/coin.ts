/**
 * TARDUS coin material decoder.
 *
 * The sealed-box plaintext shipped between users is JSON, mirroring
 * `crates/tardus-wallet/src/bin/wallet.rs` Receive command:
 *
 *   { coin_secret: hex32, coin_pubkey: hex32, coin_signature: hex64, denom: u64 }
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

export interface Coin {
  /** 32-byte scalar `x` — the spending secret. */
  secret: Uint8Array
  /** 32-byte compressed public commitment `Cp = x*G`. */
  pubkey: Uint8Array
  /** 64-byte threshold mint signature on `pubkey`. */
  signature: Uint8Array
  /** Denomination in lamports. */
  denom: bigint
}

function hexToBytes(hex: string, expectedLen: number, name: string): Uint8Array {
  if (hex.length !== expectedLen * 2) {
    throw new Error(`${name}: expected ${expectedLen * 2} hex chars, got ${hex.length}`)
  }
  const out = new Uint8Array(expectedLen)
  for (let i = 0; i < expectedLen; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) {
      throw new Error(`${name}: bad hex at offset ${i * 2}`)
    }
    out[i] = byte
  }
  return out
}

/**
 * Decode the sealed-box plaintext into a `Coin`.
 *
 * @throws if the JSON shape is wrong or any hex field has the wrong length.
 */
export function parseCoinPayload(plaintext: Uint8Array): Coin {
  const text = new TextDecoder().decode(plaintext)
  let obj: unknown
  try {
    obj = JSON.parse(text)
  } catch (e) {
    throw new Error(`coin payload is not JSON: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (typeof obj !== 'object' || obj === null) {
    throw new Error('coin payload JSON is not an object')
  }
  const j = obj as Record<string, unknown>
  if (typeof j.coin_secret !== 'string') throw new Error('missing coin_secret')
  if (typeof j.coin_pubkey !== 'string') throw new Error('missing coin_pubkey')
  if (typeof j.coin_signature !== 'string') throw new Error('missing coin_signature')
  if (typeof j.denom !== 'number' && typeof j.denom !== 'bigint' && typeof j.denom !== 'string') {
    throw new Error('missing denom')
  }
  const denom = typeof j.denom === 'bigint' ? j.denom : BigInt(j.denom)
  return {
    secret: hexToBytes(j.coin_secret, 32, 'coin_secret'),
    pubkey: hexToBytes(j.coin_pubkey, 32, 'coin_pubkey'),
    signature: hexToBytes(j.coin_signature, 64, 'coin_signature'),
    denom,
  }
}
