import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['server/tests/**/*.test.js'],
    testTimeout: 30000,
    server: {
      deps: {
        // Let Node load noble packages natively — Vite's transforms corrupt
        // the internal TypedArray operations in @noble/post-quantum.
        external: ['@noble/post-quantum', '@noble/curves', '@noble/hashes', '@noble/ed25519'],
      },
    },
  },
})
