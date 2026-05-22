import { useState, useMemo, useCallback, useEffect } from 'react'
import { useWallet, useConnection } from '@solana/wallet-adapter-react'
import { parseInvoice, encodeInvoice, openRustCompat } from '@tardus/sdk'
import {
  deriveReceivingIdentity,
  TARDUS_DERIVATION_MESSAGE,
  type ReceivingIdentity,
} from '../lib/identity'
import {
  RelayClient,
  payloadBytes,
  RelayError,
  type RelayMessage,
} from '../lib/relay'
import { parseCoinPayload, type Coin } from '../lib/coin'
import { buildWithdrawTx } from '../lib/tardus-program'

type Mode = 'receive' | 'send'

// Default devnet relay URL — replace via the "Relay" input. The web app
// is published as a static page; the relay it talks to is configurable.
const DEFAULT_RELAY = 'http://localhost:9799'

export default function PrivateTransfer() {
  const [mode, setMode] = useState<Mode>('receive')

  return (
    <section className="max-w-xl mx-auto">
      <div className="glass p-6 md:p-8">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl md:text-2xl m-0">Private transfer</h1>
          <span className="kicker">SOLANA · DEVNET</span>
        </div>

        <div className="glass-soft p-1 grid grid-cols-2 gap-1 mb-6">
          <button
            type="button"
            className={`btn ${mode === 'receive' ? 'btn-primary' : 'btn-ghost'} text-sm`}
            onClick={() => setMode('receive')}
          >
            Receive
          </button>
          <button
            type="button"
            className={`btn ${mode === 'send' ? 'btn-primary' : 'btn-ghost'} text-sm`}
            onClick={() => setMode('send')}
          >
            Send
          </button>
        </div>

        {mode === 'receive' ? <ReceiveFlow /> : <SendFlow />}

        <p className="mt-6 text-xs text-[var(--color-fg-meta)] leading-relaxed">
          Native SOL goes in, native SOL comes out. Between deposit and
          withdrawal, nothing on chain links them. Devnet only — research
          protocol, not for production.
        </p>
      </div>
    </section>
  )
}

// ─────────────────────────────────────────────────────────────────
// RECEIVE FLOW
// ─────────────────────────────────────────────────────────────────

function ReceiveFlow() {
  const { connected, publicKey, signMessage } = useWallet()
  const [identity, setIdentity] = useState<ReceivingIdentity | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [relayUrl, setRelayUrl] = useState(DEFAULT_RELAY)
  const [messages, setMessages] = useState<RelayMessage[]>([])
  const [pollError, setPollError] = useState<string | null>(null)
  const [polling, setPolling] = useState(false)

  // When the user disconnects their wallet, drop the identity too.
  useEffect(() => {
    if (!connected) {
      setIdentity(null)
      setMessages([])
    }
  }, [connected])

  const inviteUri = useMemo(() => {
    if (!identity) return ''
    try {
      return encodeInvoice({
        recipientPubkey: identity.receivingPubkey,
        denom: 1_000_000n,
        relays: [relayUrl],
      })
    } catch {
      return ''
    }
  }, [identity, relayUrl])

  const handleVerify = useCallback(async () => {
    if (!signMessage) {
      setVerifyError('Connected wallet does not support signMessage.')
      return
    }
    setVerifying(true)
    setVerifyError(null)
    try {
      const msg = new TextEncoder().encode(TARDUS_DERIVATION_MESSAGE)
      const sig = await signMessage(msg)
      setIdentity(deriveReceivingIdentity(sig))
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : String(e))
    } finally {
      setVerifying(false)
    }
  }, [signMessage])

  const handlePoll = useCallback(async () => {
    if (!identity) return
    setPolling(true)
    setPollError(null)
    try {
      const client = new RelayClient(relayUrl)
      const list = await client.list(identity.receivingPubkey)
      setMessages(list)
    } catch (e) {
      const msg =
        e instanceof RelayError
          ? `relay ${e.status || ''}: ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e)
      setPollError(msg)
    } finally {
      setPolling(false)
    }
  }, [identity, relayUrl])

  if (!connected) {
    return (
      <div className="glass-soft p-5 text-center">
        <p className="text-sm text-[var(--color-fg-soft)] leading-relaxed">
          Connect a wallet to derive your TARDUS receiving identity.
          Your receiving keypair is derived deterministically from a
          single signature — no separate mnemonic to manage.
        </p>
      </div>
    )
  }

  if (!identity) {
    return (
      <div className="space-y-5">
        <div className="glass-soft p-4">
          <div className="kicker mb-2">Step 1 · Verify with your wallet</div>
          <p className="text-sm text-[var(--color-fg-soft)] leading-relaxed">
            Your wallet will be asked to sign the canonical TARDUS message
            below. The signature stays in this browser; we derive your
            receiving keypair from it via HKDF-SHA-256 and never see your
            secret key.
          </p>
          <div className="mt-3 p-3 rounded-md font-mono text-xs text-[var(--color-fg)]"
               style={{ background: 'rgba(131, 77, 251, 0.06)', border: '1px solid var(--color-border-edge)' }}>
            "{TARDUS_DERIVATION_MESSAGE}"
          </div>
        </div>

        <button
          type="button"
          className="btn btn-primary w-full"
          onClick={handleVerify}
          disabled={verifying || !signMessage}
          title={
            !signMessage
              ? 'Connected wallet does not support signMessage'
              : ''
          }
        >
          {verifying ? 'Waiting for signature…' : 'Verify with your wallet'}
        </button>

        {verifyError && (
          <p className="text-sm" style={{ color: 'var(--color-error)' }}>
            {verifyError}
          </p>
        )}

        <p className="text-xs text-[var(--color-fg-meta)] text-center leading-relaxed">
          Same wallet + same message = same receiving identity, every time.
          Returning visits re-derive in one click; nothing is persisted.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="kicker mb-3">Your receiving identity</div>
        <div className="font-mono text-xs leading-relaxed break-all text-[var(--color-fg-soft)]">
          {identity.receivingPubkeyHex}
        </div>
        <p className="text-xs text-[var(--color-fg-meta)] mt-2">
          Derived from {publicKey?.toBase58().slice(0, 4)}…{publicKey?.toBase58().slice(-4)} ·
          ephemeral · session only
        </p>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-[var(--color-fg)]">
            Invoice you can share
          </span>
          <span className="pill">denom 0.001 SOL</span>
        </div>
        <div className="glass-soft p-3">
          <code className="text-xs break-all text-[var(--color-fg-soft)]">
            {inviteUri}
          </code>
        </div>
        <button
          type="button"
          className="btn btn-glass text-xs mt-2"
          onClick={() => {
            navigator.clipboard.writeText(inviteUri).catch(() => {})
          }}
        >
          Copy invoice URI
        </button>
      </div>

      <div>
        <label className="block mb-3">
          <span className="text-sm font-medium text-[var(--color-fg)] mb-2 block">
            Relay endpoint
          </span>
          <input
            value={relayUrl}
            onChange={e => setRelayUrl(e.target.value)}
            placeholder="http://localhost:9799"
            className="input text-xs"
          />
        </label>
        <button
          type="button"
          className="btn btn-primary w-full"
          disabled={polling}
          onClick={handlePoll}
        >
          {polling ? 'Polling…' : 'Check inbox'}
        </button>
        {pollError && (
          <p className="text-xs mt-2" style={{ color: 'var(--color-error)' }}>
            {pollError}
          </p>
        )}
      </div>

      {messages.length > 0 && (
        <MessageList
          messages={messages}
          identity={identity}
          phantomConnected={connected}
          phantomAddress={publicKey?.toBase58() ?? ''}
        />
      )}
    </div>
  )
}

function MessageList({
  messages,
  identity,
  phantomConnected,
  phantomAddress,
}: {
  messages: RelayMessage[]
  identity: ReceivingIdentity
  phantomConnected: boolean
  phantomAddress: string
}) {
  return (
    <div>
      <div className="kicker mb-3">Inbox · {messages.length} message{messages.length === 1 ? '' : 's'}</div>
      <ul className="space-y-2">
        {messages.map(m => (
          <MessageRow
            key={m.id}
            message={m}
            identity={identity}
            phantomConnected={phantomConnected}
            phantomAddress={phantomAddress}
          />
        ))}
      </ul>
    </div>
  )
}

type WithdrawState =
  | { kind: 'idle' }
  | { kind: 'building' }
  | { kind: 'signing' }
  | { kind: 'sending' }
  | { kind: 'success'; signature: string }
  | { kind: 'error'; error: string }

function MessageRow({
  message,
  identity,
  phantomConnected,
  phantomAddress,
}: {
  message: RelayMessage
  identity: ReceivingIdentity
  phantomConnected: boolean
  phantomAddress: string
}) {
  const { connection } = useConnection()
  const { publicKey, signTransaction } = useWallet()
  const [coin, setCoin] = useState<Coin | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [withdraw, setWithdraw] = useState<WithdrawState>({ kind: 'idle' })

  useEffect(() => {
    try {
      const sealed = payloadBytes(message)
      const plain = openRustCompat(sealed, identity.receivingSecret)
      setCoin(parseCoinPayload(plain))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [message, identity])

  const handleWithdraw = useCallback(async () => {
    if (!coin || !publicKey || !signTransaction) return
    setWithdraw({ kind: 'building' })
    try {
      const tx = await buildWithdrawTx({
        connection,
        signer: publicKey,
        recipientPubkey: publicKey,
        coin,
      })
      setWithdraw({ kind: 'signing' })
      const signed = await signTransaction(tx)
      setWithdraw({ kind: 'sending' })
      const signature = await connection.sendRawTransaction(signed.serialize(), {
        skipPreflight: false,
        preflightCommitment: 'confirmed',
      })
      await connection.confirmTransaction(signature, 'confirmed')
      setWithdraw({ kind: 'success', signature })
    } catch (e) {
      setWithdraw({
        kind: 'error',
        error: e instanceof Error ? e.message : String(e),
      })
    }
  }, [coin, connection, publicKey, signTransaction])

  const busy =
    withdraw.kind === 'building' ||
    withdraw.kind === 'signing' ||
    withdraw.kind === 'sending'

  return (
    <li className="glass-soft p-3 text-xs">
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-[var(--color-fg-meta)]">
          {message.id.slice(0, 8)}…
        </span>
        <span className="pill" style={{ fontSize: '0.6rem' }}>
          {coin
            ? `${(Number(coin.denom) / 1e9).toFixed(3)} SOL`
            : error
              ? 'decrypt failed'
              : 'opening…'}
        </span>
      </div>
      {error && <p className="text-[var(--color-error)] text-xs">{error}</p>}
      {coin && withdraw.kind !== 'success' && (
        <>
          <div className="text-[var(--color-fg-soft)] my-2 leading-relaxed">
            Coin verified · denom {coin.denom.toString()} lamports · Cp{' '}
            <span className="font-mono">
              {Array.from(coin.pubkey.slice(0, 6), b => b.toString(16).padStart(2, '0')).join('')}…
            </span>
          </div>
          <button
            type="button"
            className="btn btn-primary text-xs"
            disabled={!phantomConnected || !signTransaction || busy}
            onClick={handleWithdraw}
            title={
              !phantomConnected
                ? 'Connect a wallet first'
                : !signTransaction
                  ? 'Wallet does not support signTransaction'
                  : ''
            }
          >
            {busy
              ? withdraw.kind === 'building'
                ? 'Building TX…'
                : withdraw.kind === 'signing'
                  ? 'Sign in your wallet…'
                  : 'Submitting…'
              : `Withdraw → ${phantomAddress.slice(0, 4)}…${phantomAddress.slice(-4)}`}
          </button>
          {withdraw.kind === 'error' && (
            <p className="text-[var(--color-error)] text-xs mt-2 break-words">
              {withdraw.error}
            </p>
          )}
        </>
      )}
      {withdraw.kind === 'success' && (
        <div className="mt-2">
          <span className="pill" style={{ background: 'rgba(22, 163, 124, 0.12)', color: 'var(--color-success)' }}>
            ✓ Withdrawn
          </span>
          <p className="mt-2 text-[var(--color-fg-soft)] break-all">
            TX:{' '}
            <a
              href={`https://explorer.solana.com/tx/${withdraw.signature}?cluster=devnet`}
              target="_blank"
              rel="noreferrer"
              className="font-mono"
            >
              {withdraw.signature.slice(0, 14)}…{withdraw.signature.slice(-6)} ↗
            </a>
          </p>
        </div>
      )}
    </li>
  )
}

// ─────────────────────────────────────────────────────────────────
// SEND FLOW (parser wired; orchestration stub)
// ─────────────────────────────────────────────────────────────────

function SendFlow() {
  const { connected, publicKey } = useWallet()
  const [invoiceText, setInvoiceText] = useState('')

  const parsed = useMemo(() => {
    if (!invoiceText.trim().startsWith('tardus://')) return null
    try {
      return parseInvoice(invoiceText.trim())
    } catch {
      return null
    }
  }, [invoiceText])

  return (
    <div className="space-y-5">
      <label className="block">
        <span className="text-sm font-medium text-[var(--color-fg)] mb-2 block">
          Recipient's TARDUS invoice
        </span>
        <textarea
          value={invoiceText}
          onChange={e => setInvoiceText(e.target.value)}
          placeholder="tardus://4afa35d8…?denom=1000000&relay=…"
          className="input min-h-[5rem] resize-y"
        />
      </label>

      {parsed && (
        <div className="glass-soft p-4 space-y-2 text-xs">
          <Row k="Recipient" v={`${Array.from(parsed.recipientPubkey, b => b.toString(16).padStart(2, '0')).join('').slice(0, 12)}…`} mono />
          <Row k="Denom" v={`${Number(parsed.denom) / 1e9} SOL  (${parsed.denom.toString()} lamports)`} />
          <Row k="Relays" v={parsed.relays.join('\n')} mono />
          {parsed.memo && (
            <Row k="Memo" v={new TextDecoder().decode(parsed.memo)} />
          )}
        </div>
      )}

      <div className="relative">
        <button
          type="button"
          className="btn btn-primary w-full"
          disabled
        >
          <span>
            Send privately {connected ? `from ${publicKey?.toBase58().slice(0, 4)}…${publicKey?.toBase58().slice(-4)}` : ''}
          </span>
          <span className="pill pill-highlight ml-2" style={{ fontSize: '0.6rem' }}>
            Coming W-MVP-B
          </span>
        </button>
      </div>

      <div className="glass-soft p-3 text-xs text-[var(--color-fg-soft)] leading-relaxed">
        <div className="font-mono uppercase tracking-widest text-[0.65rem] text-[var(--color-accent)] mb-2">
          What this button will do
        </div>
        <ol className="space-y-1 list-decimal list-inside">
          <li>Phantom signs a Deposit TX moving 0.001 SOL into the per-denom vault</li>
          <li>Browser runs the threshold blind sign ceremony with validators</li>
          <li>Resulting coin is sealed for the recipient's pubkey</li>
          <li>Sealed payload is POSTed to the recipient's relay</li>
        </ol>
        <p className="mt-3 text-[var(--color-fg-meta)]">
          Pipeline ships in W-MVP-B once the validator + relay daemons are
          publicly available on devnet. Invoice parser is fully wired now.
        </p>
      </div>
    </div>
  )
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <span className="text-[var(--color-fg-meta)] min-w-[5rem] font-mono uppercase tracking-widest text-[0.65rem] mt-0.5">
        {k}
      </span>
      <span
        className={`flex-1 break-all text-[var(--color-fg)] ${mono ? 'font-mono' : ''}`}
        style={{ whiteSpace: mono && v.includes('\n') ? 'pre-line' : 'normal' }}
      >
        {v}
      </span>
    </div>
  )
}
