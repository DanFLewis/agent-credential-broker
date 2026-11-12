// Bundles the service worker with esbuild and copies the static files into build/.
// @acb/core is aliased to its TS source so the bundle never touches Node modules
// (@acb/core/node is deliberately not aliased: bundling it would fail loudly).
import { build } from 'esbuild';
import { copyFile, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

await rm(here('build'), { recursive: true, force: true });
await mkdir(here('build'), { recursive: true });

await build({
  entryPoints: [here('src/background.ts')],
  outfile: here('build/background.js'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'chrome116',
  alias: { '@acb/core': here('../core/src/index.ts') },
  logLevel: 'info',
});

for (const f of ['manifest.json', 'popup.html', 'popup.js']) {
  await copyFile(here(f), here(`build/${f}`));
}
