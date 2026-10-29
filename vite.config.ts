import { resolve } from 'node:path';
import { defineConfig } from 'vite';

const root = resolve(import.meta.dirname, 'src');

// Main build: popup, options page and the module service worker.
// The content script is built separately (see vite.content.config.ts) because
// it is injected as a classic script and must not import shared chunks.
export default defineConfig({
  root,
  publicDir: resolve(import.meta.dirname, 'public'),
  base: '',
  build: {
    outDir: resolve(import.meta.dirname, 'dist'),
    emptyOutDir: true,
    target: 'chrome116',
    modulePreload: { polyfill: false },
    sourcemap: false,
    rolldownOptions: {
      input: {
        popup: resolve(root, 'popup/popup.html'),
        options: resolve(root, 'options/options.html'),
        unlock: resolve(root, 'unlock/unlock.html'),
        serviceWorker: resolve(root, 'background/serviceWorker.ts'),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'serviceWorker' ? 'background/serviceWorker.js' : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
