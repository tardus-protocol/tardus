import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    // @solana/web3.js + wallet-adapter expect `global` and `process.env`
    // shims for browser builds.
    global: 'globalThis',
    'process.env.ANCHOR_BROWSER': JSON.stringify('true'),
  },
  resolve: {
    alias: {
      // @tardus/sdk imports `randomBytes` from `node:crypto`; map to a
      // tiny WebCrypto-backed shim so the browser build works.
      'node:crypto': new URL('./src/lib/node-crypto-shim.ts', import.meta.url).pathname,
    },
  },
  server: {
    host: '0.0.0.0',
    port: 4321,
    strictPort: false,
  },
  build: {
    target: 'es2022',
    sourcemap: true,
  },
  optimizeDeps: {
    esbuildOptions: {
      target: 'es2022',
    },
  },
})
