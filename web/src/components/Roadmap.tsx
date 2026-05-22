const items = [
  {
    n: '01',
    title: 'Web app',
    body: 'Connect a Solana wallet, claim or send privately. You are here.',
    state: 'active' as const,
  },
  {
    n: '02',
    title: 'TypeScript SDK',
    body: 'Public @tardus/sdk for third-party dApps to integrate.',
    state: 'soon' as const,
  },
  {
    n: '03',
    title: 'Browser extension',
    body: 'Persistent vault, sealed-box notifications, dApp authorisation.',
    state: 'soon' as const,
  },
  {
    n: '04',
    title: 'Desktop wallet',
    body: 'Linux AppImage shipped as a power-user option. macOS + Windows next.',
    state: 'soon' as const,
  },
  {
    n: '05',
    title: 'Token-2022 vault',
    body: 'ConfidentialMint integration closes the per-coin denomination leak.',
    state: 'later' as const,
  },
  {
    n: '06',
    title: 'Mobile',
    body: 'Native iOS + Android. Subject to app store policy.',
    state: 'later' as const,
  },
]

export default function Roadmap() {
  return (
    <section className="max-w-xl mx-auto mt-16 md:mt-24">
      <div className="flex items-center gap-3 mb-6">
        <span className="kicker">Roadmap</span>
        <span className="h-px flex-1 bg-[var(--color-border-edge)]" />
      </div>

      <ol className="space-y-2">
        {items.map(item => (
          <li key={item.n}>
            <div className="glass-soft p-4 flex items-start gap-4 transition-colors hover:bg-white/70">
              <span className="font-mono text-xs tracking-widest text-[var(--color-fg-meta)] pt-0.5 min-w-[2rem]">
                {item.n}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-sm font-semibold m-0 text-[var(--color-fg)]">
                    {item.title}
                  </h3>
                  <StateChip state={item.state} />
                </div>
                <p className="text-sm text-[var(--color-fg-soft)] leading-relaxed">
                  {item.body}
                </p>
              </div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  )
}

function StateChip({ state }: { state: 'active' | 'soon' | 'later' }) {
  if (state === 'active') {
    return (
      <span className="pill pill-highlight">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-[var(--color-highlight-soft)] animate-pulse" />
        Active
      </span>
    )
  }
  if (state === 'soon') {
    return <span className="pill">Soon</span>
  }
  return (
    <span className="pill" style={{ background: 'rgba(24,16,43,0.05)', color: 'var(--color-fg-meta)' }}>
      Later
    </span>
  )
}
