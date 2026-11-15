/** @type {import('@commitlint/types').UserConfig} */
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-empty': [2, 'never'],
    'scope-enum': [
      2,
      'always',
      [
        'catalog',
        'schemas',
        'ingest',
        'matcher',
        'site',
        'image',
        'notes',
        'docs',
        'ci',
        'build',
        'deps',
        'repo',
        'test',
      ],
    ],
    'subject-case': [2, 'always', 'lower-case'],
  },
};
