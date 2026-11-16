import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  imageConfigProblems,
  repoRoot,
  validateAgainst,
  type ImageConfig,
} from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  buildConfig,
  decodeState,
  defaultState,
  encodeState,
  nextEnvName,
  formProblems,
  stateProblems,
  toCompose,
  toConfigYaml,
  toEnvTemplate,
  yamlScalar,
  type GeneratorState,
} from '../src/lib/generator.ts';
import { validateConfigYaml } from '../src/lib/validate-config.ts';

const FEED = 'https://shironex.github.io/advisorydeck/api/v1/';
const SLUGS = new Set(['postgresql', 'traefik', 'coolify', 'redis', 'docker-engine']);

function state(overrides: Partial<GeneratorState>): GeneratorState {
  return { ...defaultState('UTC'), ...overrides };
}

const combinations: [string, GeneratorState][] = [
  [
    'one floating branch, digest, discord',
    state({ products: [{ slug: 'postgresql', kind: 'floating', version: '17' }] }),
  ],
  [
    'pinned versions, instant, slack and a generic webhook',
    state({
      products: [
        { slug: 'traefik', kind: 'exact', version: '3.7.19' },
        { slug: 'coolify', kind: 'exact', version: '4.0.0-beta.474' },
      ],
      minSeverity: 'medium',
      mode: 'instant',
      channels: [
        { type: 'slack', urlEnv: 'SLACK_WEBHOOK_URL', name: 'security' },
        { type: 'webhook', urlEnv: 'GENERIC_WEBHOOK_URL', name: '' },
      ],
    }),
  ],
  [
    'every product, both modes, a zone with a slash, two discord channels',
    state({
      products: [
        { slug: 'postgresql', kind: 'exact', version: '16.4' },
        { slug: 'traefik', kind: 'floating', version: '3.7' },
        { slug: 'coolify', kind: 'exact', version: '4.0.0-beta.474' },
        { slug: 'redis', kind: 'floating', version: '8.8' },
        { slug: 'docker-engine', kind: 'exact', version: '29.9.3' },
      ],
      minSeverity: 'low',
      mode: 'both',
      digestTime: '23:59',
      timezone: 'America/Argentina/Buenos_Aires',
      channels: [
        { type: 'discord', urlEnv: 'DISCORD_WEBHOOK_URL', name: "it's ops: #1" },
        { type: 'discord', urlEnv: 'DISCORD_WEBHOOK_URL_2', name: 'yes' },
      ],
    }),
  ],
];

function combo(index: number): GeneratorState {
  const found = combinations[index];
  if (found === undefined) {
    throw new Error(`no combination ${index}`);
  }
  return found[1];
}

describe('generator output', () => {
  it.each(combinations)('%s: advisorydeck.yml validates against the schema', (_name, picked) => {
    expect(stateProblems(picked)).toEqual([]);
    const text = toConfigYaml(picked, FEED);
    const parsed = parse(text) as ImageConfig;
    expect(validateAgainst('image-config', parsed)).toEqual([]);
    expect(imageConfigProblems(parsed)).toEqual([]);
    // The YAML says exactly what the config object says (versions stay strings, names survive quoting).
    expect(parsed).toEqual(buildConfig(picked, FEED));
    // The browser validator agrees.
    expect(validateConfigYaml(text)).toEqual([]);
  });

  it('accepts a feed URL with a path before /api/v1/ (GitHub Pages project sites)', () => {
    const config = buildConfig(combo(0), FEED);
    expect(config.feed.url).toBe(FEED);
    expect(validateAgainst('image-config', config)).toEqual([]);
  });

  it('the browser validator rejects what the schema and the image rules reject', () => {
    expect(
      validateConfigYaml(
        'version: 1\nfeed:\n  url: http://x/api/v1/\nproducts: []\nchannels: []\n',
      ),
    ).not.toEqual([]);
    const twice = toConfigYaml(
      state({
        products: [
          { slug: 'postgresql', kind: 'exact', version: '17.4' },
          { slug: 'postgresql', kind: 'exact', version: '16.4' },
        ],
      }),
      FEED,
    );
    expect(validateConfigYaml(twice)).toEqual(['products: postgresql is listed more than once']);
    expect(
      validateConfigYaml(
        toConfigYaml(
          state({
            products: [{ slug: 'redis', kind: 'exact', version: '8.8' }],
            timezone: 'Mars/Olympus',
          }),
          FEED,
        ),
      ),
    ).toEqual(['digest.timezone: Mars/Olympus is not an IANA time zone']);
  });

  it('reports form problems before validation', () => {
    expect(stateProblems(state({}))).toContain('Pick at least one product.');
    expect(
      stateProblems(
        state({
          products: [{ slug: 'redis', kind: 'exact', version: '8 8' }],
          channels: [{ type: 'discord', urlEnv: 'lower', name: '' }],
        }),
      ),
    ).toHaveLength(2);
  });

  it('points each form problem at its field', () => {
    const problems = formProblems(
      state({
        products: [
          { slug: 'redis', kind: 'exact', version: '8.2.1' },
          { slug: 'traefik', kind: 'exact', version: '' },
        ],
        channels: [{ type: 'slack', urlEnv: 'slack-hook', name: '' }],
      }),
    );
    expect(problems.map((p) => p.target)).toEqual([
      { kind: 'product', index: 1 },
      { kind: 'channel', index: 0 },
    ]);
  });

  it('compose.yml keeps the hardening of docs/examples/compose.yml and never mounts the socket', () => {
    const picked = combo(2);
    const text = toCompose(picked);
    expect(text).not.toMatch(/docker\.sock/);
    expect(text).not.toMatch(/ports:/);
    const generated = parse(text) as { services: Record<string, Record<string, unknown>> };
    const example = parse(readFileSync(join(repoRoot(), 'docs/examples/compose.yml'), 'utf8')) as {
      services: Record<string, Record<string, unknown>>;
    };
    const ours = generated.services['advisorydeck'] ?? {};
    const theirs = example.services['advisorydeck'] ?? {};
    for (const key of [
      'image',
      'restart',
      'read_only',
      'cap_drop',
      'security_opt',
      'user',
      'volumes',
    ]) {
      expect(ours[key], key).toEqual(theirs[key]);
    }
    expect(ours['environment']).toEqual({
      DISCORD_WEBHOOK_URL: '${DISCORD_WEBHOOK_URL:?set it in .env}',
      DISCORD_WEBHOOK_URL_2: '${DISCORD_WEBHOOK_URL_2:?set it in .env}',
    });
  });

  it('.env holds variable names only, never a URL', () => {
    const text = toEnvTemplate(combo(1));
    expect(text).toMatch(/^SLACK_WEBHOOK_URL=$/m);
    expect(text).toMatch(/^GENERIC_WEBHOOK_URL=$/m);
    expect(text).not.toMatch(/=\S/);
    expect(toConfigYaml(combo(1), FEED)).not.toMatch(/hooks\.slack|discord\.com\/api/);
  });

  it('quotes YAML scalars that would be misread', () => {
    expect(yamlScalar('17')).toBe("'17'");
    expect(yamlScalar('08:00')).toBe("'08:00'");
    expect(yamlScalar('yes')).toBe("'yes'");
    expect(yamlScalar("it's")).toBe("'it''s'");
    expect(yamlScalar('Europe/Berlin')).toBe('Europe/Berlin');
  });
});

describe('shareable state in the URL fragment', () => {
  it.each(combinations)('%s: round-trips', (_name, picked) => {
    const decoded = decodeState(`#${encodeState(picked)}`, SLUGS);
    expect(buildConfig(decoded, FEED)).toEqual(
      buildConfig(
        {
          ...picked,
          channels: picked.channels.map((c) => ({ ...c, name: c.name.replace(/[~,]/g, ' ') })),
        },
        FEED,
      ),
    );
  });

  it('drops malformed or hostile pieces instead of failing', () => {
    const decoded = decodeState(
      '#p=postgresql~f~17,unknown~e~1,../x~e~1,traefik~z~3,redis~e~<script>&s=urgent&m=often&t=99:99&z=a b&c=discord~not-an-env,irc~IRC_URL,slack~SLACK_WEBHOOK_URL~ok',
      SLUGS,
    );
    expect(decoded.products).toEqual([
      { slug: 'postgresql', kind: 'floating', version: '17' },
      { slug: 'redis', kind: 'exact', version: '' },
    ]);
    expect(decoded.minSeverity).toBe('high');
    expect(decoded.mode).toBe('digest');
    expect(decoded.digestTime).toBe('08:00');
    expect(decoded.timezone).toBe('UTC');
    expect(decoded.channels).toEqual([{ type: 'slack', urlEnv: 'SLACK_WEBHOOK_URL', name: 'ok' }]);
  });

  it('picks the next free variable name', () => {
    expect(nextEnvName('discord', [])).toBe('DISCORD_WEBHOOK_URL');
    expect(nextEnvName('discord', ['DISCORD_WEBHOOK_URL', 'DISCORD_WEBHOOK_URL_2'])).toBe(
      'DISCORD_WEBHOOK_URL_3',
    );
  });
});
