import { useState, useCallback } from 'react'
import { useWallet } from '@solana/wallet-adapter-react'

/**
 * Premium connect/disconnect button with a small dropdown picker.
 * Uses wallet-adapter hooks (no default UI). Tailwind-styled to match
 * the Quantus glass design.
 */
export default function ConnectButton() {
  const { wallets, wallet, publicKey, connected, connecting, connect, disconnect, select } =
    useWallet()
  const [open, setOpen] = useState(false)

  const onSelect = useCallback(
    async (name: string) => {
      select(name as never)
      setOpen(false)
      // Small async tick so select() propagates before connect().
      setTimeout(() => {
        connect().catch(err => {
          console.error('connect failed:', err)
        })
      }, 30)
    },
    [select, connect],
  )

  if (connected && publicKey) {
    const addr = publicKey.toBase58()
    const short = `${addr.slice(0, 4)}…${addr.slice(-4)}`
    return (
      <div className="flex items-center gap-2">
        <span className="pill" title={addr}>
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-accent)]" />
          {wallet?.adapter.name ?? 'Wallet'} · {short}
        </span>
        <button
          type="button"
          className="btn btn-glass"
          onClick={() => disconnect().catch(console.error)}
        >
          Disconnect
        </button>
      </div>
    )
  }

  return (
    <div className="relative">
      <button
        type="button"
        className="btn btn-primary"
        disabled={connecting}
        onClick={() => setOpen(o => !o)}
      >
        {connecting ? 'Connecting…' : 'Connect wallet'}
      </button>
      {open && (
        <div
          role="menu"
          className="glass absolute right-0 mt-2 w-64 p-2 z-20"
          onMouseLeave={() => setOpen(false)}
        >
          {wallets.length === 0 ? (
            <p className="px-3 py-2 text-sm text-[var(--color-fg-soft)]">
              No wallets detected. Install Phantom or Solflare.
            </p>
          ) : (
            wallets.map(w => (
              <button
                key={w.adapter.name}
                type="button"
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-left hover:bg-[var(--color-accent-tint)] transition-colors"
                onClick={() => onSelect(w.adapter.name)}
              >
                {w.adapter.icon && (
                  <img
                    src={w.adapter.icon}
                    alt=""
                    className="w-6 h-6 rounded-md"
                  />
                )}
                <span className="text-sm font-medium text-[var(--color-fg)]">
                  {w.adapter.name}
                </span>
                <span className="ml-auto text-xs text-[var(--color-fg-meta)] font-mono">
                  {w.readyState === 'Installed' ? 'Ready' : 'Detect'}
                </span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  )
}
