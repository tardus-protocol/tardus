export default function Footer() {
  return (
    <footer className="container py-12 md:py-16">
      <div className="max-w-xl mx-auto flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <p className="text-xs font-mono tracking-wider text-[var(--color-fg-meta)]">
          tardus · research protocol · 2026
        </p>
        <nav className="flex gap-5 text-xs font-mono tracking-wider text-[var(--color-fg-meta)]">
          <a
            href="https://explorer.solana.com/address/AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u?cluster=devnet"
            target="_blank"
            rel="noreferrer"
            className="hover:text-[var(--color-accent)]"
          >
            Program ↗
          </a>
        </nav>
      </div>
    </footer>
  )
}
