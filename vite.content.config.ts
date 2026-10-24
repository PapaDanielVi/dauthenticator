import { resolve } from 'node:path';
import { defineConfig } from 'vite';

// Content script build: a single self-contained IIFE with no imports, so it can
// be injected on demand with chrome.scripting.executeScript({ files }).
export default defineConfig({
  publicDir: false,
  build: {
    outDir: resolve(import.meta.dirname, 'dist'),
    emptyOutDir: false,
    target: 'chrome116',
    sourcemap: false,
    lib: {
      entry: resolve(import.meta.dirname, 'src/content/autofill.ts'),
      name: 'DAuthenticatorAutofill',
      formats: ['iife'],
      fileName: () => 'content/autofill.js',
    },
  },
});
