import { resolve } from 'node:path';

/**
 * The folder that holds catalog/, data/, notes/ and schemas/. astro.config.mjs sets
 * ADVISORYDECK_ROOT to the repository root unless it is already set (the build test points it at
 * a copy with extra notes). Bundled page code cannot locate the repository from its own path,
 * so it always goes through this variable.
 */
export function dataRoot(): string {
  const fromEnv = process.env['ADVISORYDECK_ROOT'];
  if (fromEnv === undefined || fromEnv === '') {
    throw new Error('ADVISORYDECK_ROOT is not set; build through astro.config.mjs');
  }
  return resolve(fromEnv);
}
