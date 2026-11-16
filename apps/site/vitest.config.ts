import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@schemas': fileURLToPath(new URL('../../schemas/v1', import.meta.url)),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    // The build test runs a full astro build once.
    testTimeout: 30_000,
    hookTimeout: 240_000,
  },
});
