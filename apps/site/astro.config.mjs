import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import { publishFeed } from './src/integrations/publish-feed.ts';

// catalog/, data/, notes/ and schemas/ are read from the repository root unless
// ADVISORYDECK_ROOT already points elsewhere (the build test uses a copy).
process.env.ADVISORYDECK_ROOT ||= fileURLToPath(new URL('../..', import.meta.url));
const root = process.env.ADVISORYDECK_ROOT;

// Where the site is served. The default is the GitHub Pages project URL; set SITE_URL and
// SITE_BASE when it moves (a custom domain uses SITE_BASE=/). The generator derives the feed URL
// it writes into advisorydeck.yml from these two values.
const site = process.env.SITE_URL || 'https://shironex.github.io';
const base = process.env.SITE_BASE || '/advisorydeck';

// Static output only: the pages, the Atom feeds and the v1 feed under api/v1/ are plain files.
export default defineConfig({
  output: 'static',
  outDir: './dist',
  site,
  base,
  trailingSlash: 'ignore',
  build: { format: 'directory' },
  integrations: [publishFeed(root)],
  vite: {
    resolve: {
      alias: {
        '@schemas': fileURLToPath(new URL('../../schemas/v1', import.meta.url)),
      },
    },
  },
});
