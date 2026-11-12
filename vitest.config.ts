import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const p = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@acb\/core\/node$/, replacement: p('./packages/core/src/node.ts') },
      { find: /^@acb\/core$/, replacement: p('./packages/core/src/index.ts') },
      { find: /^@acb\/broker$/, replacement: p('./packages/broker/src/index.ts') },
      { find: /^@acb\/vault-fake$/, replacement: p('./packages/vault-fake/src/index.ts') },
      { find: /^@acb\/vault-bitwarden$/, replacement: p('./packages/vault-bitwarden/src/index.ts') },
      { find: /^@acb\/mcp-server$/, replacement: p('./packages/mcp-server/src/index.ts') },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts', 'test/**/*.test.ts'],
    environment: 'node',
  },
});
