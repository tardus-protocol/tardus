import ConnectButton from './ConnectButton'

export default function Header() {
  return (
    <header className="relative z-10">
      <div className="container py-6 md:py-8 flex items-center justify-between gap-4">
        <a
          href="/"
          className="inline-flex items-center gap-2 text-[var(--color-fg)] hover:no-underline"
        >
          <span className="inline-block w-7 h-7 rounded-md bg-[var(--color-bg-glass)] border border-[var(--color-border)] flex items-center justify-center backdrop-blur">
            <svg viewBox="0 0 32 32" className="w-5 h-5" aria-hidden="true">
              <path
                d="M7 9.5h18v3.2h-7V25h-4V12.7H7z"
                fill="var(--color-accent)"
              />
            </svg>
          </span>
          <span className="font-semibold tracking-tight text-base">tardus</span>
          <span className="pill ml-2 hidden sm:inline-flex">Devnet</span>
        </a>
        <ConnectButton />
      </div>
    </header>
  )
}
