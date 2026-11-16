import { createHash } from 'node:crypto';
import { cpSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AstroIntegration } from 'astro';

interface ManifestShape {
  products: Record<string, { etag: string }>;
}

/**
 * Copies data/api/v1/ into the build as api/v1/, byte for byte, so the image can poll the same
 * host that serves the pages. The manifest etags are sha256 hashes of the product files, so the
 * copy is checked against them: a mismatch fails the build instead of publishing a feed every
 * image would reject.
 */
export function publishFeed(root: string): AstroIntegration {
  return {
    name: 'advisorydeck:publish-feed',
    hooks: {
      'astro:build:done': ({ dir, logger }) => {
        const from = join(root, 'data/api/v1');
        const to = join(fileURLToPath(dir), 'api/v1');
        if (!existsSync(join(from, 'manifest.json'))) {
          throw new Error(`no feed to publish: ${from}/manifest.json is missing`);
        }
        cpSync(from, to, { recursive: true });
        const manifest = JSON.parse(
          readFileSync(join(to, 'manifest.json'), 'utf8'),
        ) as ManifestShape;
        for (const [slug, entry] of Object.entries(manifest.products)) {
          const bytes = readFileSync(join(to, 'products', `${slug}.json`));
          const etag = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
          if (etag !== entry.etag) {
            throw new Error(`api/v1/products/${slug}.json does not match its manifest etag`);
          }
        }
        logger.info(`published api/v1 with ${Object.keys(manifest.products).length} products`);
      },
    },
  };
}
