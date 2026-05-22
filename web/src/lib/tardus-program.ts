/**
 * TARDUS on-chain program — TS client.
 *
 * Mirrors `crates/tardus-program/src/instruction.rs` + `pda.rs` +
 * `sbf_processor.rs`. Devnet program ID is the v1.4.14 deployment.
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

import {
  Connection,
  Ed25519Program,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
} from '@solana/web3.js'
import type { Coin } from './coin'

export const TARDUS_PROGRAM_ID = new PublicKey(
  'AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u',
)

const TARDUS_PREFIX = new TextEncoder().encode('tardus')
const REGISTRY_TAG = new TextEncoder().encode('keyset-registry')
const VAULT_TAG = new TextEncoder().encode('vault')
const NULLIFIER_TAG = new TextEncoder().encode('nullifier-tree')

function u64LE(n: bigint): Uint8Array {
  const buf = new Uint8Array(8)
  const view = new DataView(buf.buffer)
  view.setBigUint64(0, n, true)
  return buf
}

/** Find the keyset-registry PDA. */
export function keysetRegistryPda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TARDUS_PREFIX, REGISTRY_TAG],
    TARDUS_PROGRAM_ID,
  )
}

/** Find the per-denomination vault PDA. */
export function vaultPda(denom: bigint): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TARDUS_PREFIX, VAULT_TAG, u64LE(denom)],
    TARDUS_PROGRAM_ID,
  )
}

/** Find the nullifier-tree PDA. */
export function nullifierTreePda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TARDUS_PREFIX, NULLIFIER_TAG],
    TARDUS_PROGRAM_ID,
  )
}

/**
 * Build the borsh-serialised body of the Withdraw instruction.
 *
 *   tag = 0x03
 *   coin_pubkey       : 32 bytes
 *   coin_signature    : 64 bytes
 *   denom (u64 LE)    :  8 bytes
 *   recipient         : 32 bytes
 *   ─────────────────────────────
 *   total            : 137 bytes
 */
function encodeWithdrawData(coin: Coin, recipient: PublicKey): Uint8Array {
  const data = new Uint8Array(1 + 32 + 64 + 8 + 32)
  let off = 0
  data[off] = 0x03
  off += 1
  data.set(coin.pubkey, off)
  off += 32
  data.set(coin.signature, off)
  off += 64
  data.set(u64LE(coin.denom), off)
  off += 8
  data.set(recipient.toBytes(), off)
  return data
}

/**
 * The joint mint public key isn't known to the client; it lives in
 * the on-chain `keyset_registry` PDA. For the ed25519 precompile we
 * need this key. The Rust client reads it from chain; here we expose
 * a small helper to do the same.
 *
 * Layout of `KeysetRegistry`: list of `KeysetEntry { keyset_id 33,
 * denom u64, joint_pk 32, epoch u64, status u8 }`. The Rust struct
 * is borsh-serialised. We read it lazily and look up the entry whose
 * `denom` matches the coin's denom and whose `status == Active (0)`.
 *
 * v1.4.14: registry data is preceded by an 8-byte `len` field
 * (Vec<KeysetEntry>). We skip headers and scan.
 */
export async function readJointPkForDenom(
  connection: Connection,
  denom: bigint,
): Promise<Uint8Array> {
  const [registryAddr] = keysetRegistryPda()
  const info = await connection.getAccountInfo(registryAddr, 'confirmed')
  if (!info) {
    throw new Error(`keyset_registry PDA not found at ${registryAddr.toBase58()}`)
  }
  const data = new Uint8Array(info.data)

  // borsh Vec<T>: 4-byte u32 LE length, then entries.
  if (data.length < 4) throw new Error('registry too small')
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const count = view.getUint32(0, true)

  // KeysetEntry layout (matches `crates/tardus-program/src/state.rs`):
  //   keyset_id 33  | denom u64  | joint_pk 32  | epoch u64  | status u8
  //   = 82 bytes per entry
  const ENTRY = 33 + 8 + 32 + 8 + 1
  for (let i = 0; i < count; i++) {
    const base = 4 + i * ENTRY
    if (base + ENTRY > data.length) break
    const entryDenom = view.getBigUint64(base + 33, true)
    const status = data[base + 33 + 8 + 32 + 8]
    if (entryDenom === denom && status === 0 /* Active */) {
      return data.slice(base + 33 + 8, base + 33 + 8 + 32)
    }
  }
  throw new Error(
    `no Active keyset for denom ${denom.toString()} in on-chain registry`,
  )
}

/**
 * Build a complete Withdraw transaction:
 *   ix0: ed25519 precompile (verifies σ on Cp under joint_pk)
 *   ix1: TARDUS Withdraw instruction
 *
 * The user (their wallet) is the signer + fee payer. The recipient
 * is `recipientPubkey` (typically the user's own connected wallet).
 *
 * Returns an UNSIGNED Transaction; pass it to wallet-adapter's
 * `signTransaction()` then `connection.sendRawTransaction`.
 */
export async function buildWithdrawTx({
  connection,
  signer,
  recipientPubkey,
  coin,
}: {
  connection: Connection
  signer: PublicKey
  recipientPubkey: PublicKey
  coin: Coin
}): Promise<Transaction> {
  const jointPk = await readJointPkForDenom(connection, coin.denom)
  const [registry] = keysetRegistryPda()
  const [vault] = vaultPda(coin.denom)
  const [nullifierTree] = nullifierTreePda()

  // ix0: ed25519 precompile. Verifies coin.signature on coin.pubkey
  // under jointPk. The TARDUS program reads this from instructions
  // sysvar and short-circuits its own check.
  const precompileIx = Ed25519Program.createInstructionWithPublicKey({
    publicKey: jointPk,
    message: coin.pubkey,
    signature: coin.signature,
    instructionIndex: 0,
  })

  // ix1: TARDUS Withdraw.
  const withdrawIx = new TransactionInstruction({
    programId: TARDUS_PROGRAM_ID,
    keys: [
      { pubkey: signer, isSigner: true, isWritable: true },
      { pubkey: registry, isSigner: false, isWritable: false },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: nullifierTree, isSigner: false, isWritable: true },
      { pubkey: recipientPubkey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(encodeWithdrawData(coin, recipientPubkey)),
  })

  const tx = new Transaction().add(precompileIx, withdrawIx)
  tx.feePayer = signer
  const { blockhash } = await connection.getLatestBlockhash('confirmed')
  tx.recentBlockhash = blockhash
  return tx
}
