import { defineConfig } from 'astro/config';

// Static output only: the site and the feed under dist/api/v1/ are plain files.
export default defineConfig({
  output: 'static',
  outDir: './dist',
});
