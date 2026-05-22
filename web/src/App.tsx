import TardusWalletProvider from './lib/wallet-provider'
import Header from './components/Header'
import PrivateTransfer from './components/PrivateTransfer'
import Roadmap from './components/Roadmap'
import Footer from './components/Footer'

export default function App() {
  return (
    <TardusWalletProvider>
      <div className="ambient-bg" aria-hidden="true" />
      <Header />
      <main className="container py-12 md:py-20">
        <PrivateTransfer />
        <Roadmap />
      </main>
      <Footer />
    </TardusWalletProvider>
  )
}
