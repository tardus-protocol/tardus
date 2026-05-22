import { useMemo, type ReactNode } from 'react'
import { Connection, clusterApiUrl } from '@solana/web3.js'
import {
  ConnectionProvider,
  WalletProvider,
} from '@solana/wallet-adapter-react'
import {
  PhantomWalletAdapter,
  SolflareWalletAdapter,
} from '@solana/wallet-adapter-wallets'
import { WalletAdapterNetwork } from '@solana/wallet-adapter-base'

// Devnet for now; mainnet ship-gate (see deploy/runbooks/mainnet-ship-gate)
// is still open.
const NETWORK = WalletAdapterNetwork.Devnet
const ENDPOINT = clusterApiUrl(NETWORK)

interface Props {
  children: ReactNode
}

export default function TardusWalletProvider({ children }: Props) {
  const wallets = useMemo(
    () => [new PhantomWalletAdapter(), new SolflareWalletAdapter()],
    [],
  )

  // Memoised so the connection isn't rebuilt on every render.
  const connection = useMemo(() => new Connection(ENDPOINT, 'confirmed'), [])
  void connection

  return (
    <ConnectionProvider endpoint={ENDPOINT}>
      <WalletProvider wallets={wallets} autoConnect>
        {children}
      </WalletProvider>
    </ConnectionProvider>
  )
}
