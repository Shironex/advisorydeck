/** @type {import('lint-staged').Configuration} */
export default {
  '*.{js,mjs,cjs,ts,mts,cts,astro}': [
    'eslint --max-warnings=0 --no-warn-ignored',
    'prettier --write',
  ],
  '*.{json,jsonc,md,yml,yaml,css,html}': 'prettier --write',
  '*.go': 'gofmt -w',
};
