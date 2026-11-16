/**
 * The generator's pure logic: from what the visitor picked to advisorydeck.yml, compose.yml and a
 * .env template, plus the URL fragment that makes a setup shareable. No I/O and no node imports,
 * so the same code runs in the browser and in the tests.
 */
import type { ImageConfig } from '@advisorydeck/contract';

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Mode = 'instant' | 'digest' | 'both';
export type ChannelType = 'discord' | 'slack' | 'webhook';
/** floating: the visitor runs a floating tag of the branch (postgres:17). exact: a pinned version. */
export type VersionKind = 'floating' | 'exact';

export interface PickedProduct {
  slug: string;
  kind: VersionKind;
  /** A branch name for floating, an exact version for exact. */
  version: string;
}

export interface PickedChannel {
  type: ChannelType;
  urlEnv: string;
  name: string;
}

export interface GeneratorState {
  products: PickedProduct[];
  minSeverity: Severity;
  mode: Mode;
  digestTime: string;
  timezone: string;
  channels: PickedChannel[];
}

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical'];
export const MODES: readonly Mode[] = ['digest', 'instant', 'both'];
export const CHANNEL_TYPES: readonly ChannelType[] = ['discord', 'slack', 'webhook'];

export const CHANNEL_LABELS: Record<ChannelType, string> = {
  discord: 'Discord',
  slack: 'Slack',
  webhook: 'Generic webhook (JSON)',
};

export const DEFAULT_ENV: Record<ChannelType, string> = {
  discord: 'DISCORD_WEBHOOK_URL',
  slack: 'SLACK_WEBHOOK_URL',
  webhook: 'GENERIC_WEBHOOK_URL',
};

/** Where to get each webhook URL, for the .env template comments. */
const ENV_HELP: Record<ChannelType, string> = {
  discord: 'Discord: Server settings > Integrations > Webhooks > New webhook > Copy webhook URL',
  slack: 'Slack: create an app with Incoming Webhooks and copy the webhook URL',
  webhook: 'Your receiver (ntfy, Gotify, n8n ...). https, or http on your own network',
};

export const IMAGE_NAME = 'advisorydeck:local';
export const SERVICE_NAME = 'advisorydeck';

const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;
const TIME = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
const ZONE = /^[A-Za-z_]+(\/[A-Za-z0-9_+-]+)*$/;

export const isVersion = (v: string): boolean => VERSION.test(v) && v.length <= 64;
export const isEnvName = (v: string): boolean => ENV_NAME.test(v);
export const isTime = (v: string): boolean => TIME.test(v);

export function defaultState(timezone = 'UTC'): GeneratorState {
  return {
    products: [],
    minSeverity: 'high',
    mode: 'digest',
    digestTime: '08:00',
    timezone: ZONE.test(timezone) ? timezone : 'UTC',
    channels: [{ type: 'discord', urlEnv: DEFAULT_ENV.discord, name: '' }],
  };
}

/** A channel label: control characters dropped, trimmed, at most 64 characters. */
export function cleanName(name: string): string {
  return (
    name
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .trim()
      .slice(0, 64)
  );
}

/** The config object. Optional settings equal to the image defaults are still written: explicit is clearer. */
export function buildConfig(state: GeneratorState, feedUrl: string): ImageConfig {
  const config: ImageConfig = {
    version: 1,
    feed: { url: feedUrl, poll_interval: '30m' },
    products: state.products.map((p) => ({
      slug: p.slug,
      version: p.version.trim(),
    })) as ImageConfig['products'],
    min_severity: state.minSeverity,
    mode: state.mode,
    channels: state.channels.map((c) => {
      const name = cleanName(c.name);
      return name === ''
        ? { type: c.type, url_env: c.urlEnv }
        : { type: c.type, url_env: c.urlEnv, name };
    }) as ImageConfig['channels'],
  };
  if (state.mode !== 'instant') {
    config.digest = { time: state.digestTime, timezone: state.timezone };
  }
  return config;
}

const YAML_RESERVED = /^(true|false|yes|no|on|off|y|n|null|~)$/i;

/** A YAML scalar: plain when it cannot be misread, otherwise single-quoted. */
export function yamlScalar(value: string | number): string {
  if (typeof value === 'number') {
    return String(value);
  }
  if (/^[A-Za-z_][A-Za-z0-9_./-]*$/.test(value) && !YAML_RESERVED.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "''")}'`;
}

function productComment(p: PickedProduct): string {
  return p.kind === 'floating'
    ? '  # floating tag of this branch: re-pull after each fix'
    : '  # pinned version';
}

/** advisorydeck.yml, with comments. Webhook URLs never appear: only variable names. */
export function toConfigYaml(state: GeneratorState, feedUrl: string): string {
  const config = buildConfig(state, feedUrl);
  const lines: string[] = [
    '# Advisorydeck notifier config. Schema:',
    '# https://raw.githubusercontent.com/Shironex/advisorydeck/main/schemas/v1/image-config.schema.json',
    '# Webhook URLs are secrets: they live in .env, this file only names the variables.',
    `version: ${yamlScalar(config.version)}`,
    'feed:',
    `  url: ${yamlScalar(config.feed.url)}`,
    `  poll_interval: ${yamlScalar(config.feed.poll_interval ?? '30m')}`,
    'products:',
  ];
  config.products.forEach((p, i) => {
    const picked = state.products[i];
    lines.push(`  - slug: ${yamlScalar(p.slug)}`);
    lines.push(`    version: ${yamlScalar(p.version)}${picked ? productComment(picked) : ''}`);
  });
  lines.push(`min_severity: ${yamlScalar(config.min_severity ?? 'high')}`);
  lines.push(`mode: ${yamlScalar(config.mode ?? 'digest')}`);
  if (config.digest !== undefined) {
    lines.push('digest:');
    lines.push(`  time: ${yamlScalar(config.digest.time ?? '08:00')}`);
    lines.push(`  timezone: ${yamlScalar(config.digest.timezone ?? 'UTC')}`);
  }
  lines.push('channels:');
  for (const channel of config.channels) {
    lines.push(`  - type: ${yamlScalar(channel.type)}`);
    lines.push(`    url_env: ${yamlScalar(channel.url_env)}`);
    if (channel.name !== undefined) {
      lines.push(`    name: ${yamlScalar(channel.name)}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

function uniqueEnvNames(state: GeneratorState): string[] {
  return [...new Set(state.channels.map((c) => c.urlEnv))];
}

/** compose.yml, the same hardening as docs/examples/compose.yml: read-only, no capabilities, no socket. */
export function toCompose(state: GeneratorState): string {
  const env = uniqueEnvNames(state);
  return [
    '# Advisorydeck notifier. No image is published yet: build it first with',
    '#   docker build -t advisorydeck:local https://github.com/Shironex/advisorydeck.git#main:image',
    '# Put advisorydeck.yml and .env next to this file, then:',
    '#   docker compose run --rm advisorydeck once -dry-run   (shows what would be sent, sends nothing)',
    '#   docker compose up -d',
    'services:',
    `  ${SERVICE_NAME}:`,
    `    image: ${IMAGE_NAME}`,
    '    restart: unless-stopped',
    '    read_only: true',
    '    cap_drop: [ALL]',
    "    security_opt: ['no-new-privileges:true']",
    "    user: '65532:65532'",
    '    # Webhook URLs come only from the environment, named by url_env in advisorydeck.yml.',
    '    environment:',
    ...env.map((name) => `      ${name}: \${${name}:?set it in .env}`),
    '    volumes:',
    '      - ./advisorydeck.yml:/config/advisorydeck.yml:ro',
    '      - advisorydeck-state:/data',
    '    # No ports and no Docker socket: the container only makes outbound HTTPS requests.',
    '',
    'volumes:',
    '  advisorydeck-state:',
    '',
  ].join('\n');
}

/** .env template: variable names with empty values and where to get each URL. */
export function toEnvTemplate(state: GeneratorState): string {
  const lines = [
    '# Paste each webhook URL after the = sign. Never commit this file or share it:',
    '# anyone with a webhook URL can post to your channel.',
  ];
  const seen = new Set<string>();
  for (const channel of state.channels) {
    if (seen.has(channel.urlEnv)) {
      continue;
    }
    seen.add(channel.urlEnv);
    lines.push('', `# ${ENV_HELP[channel.type]}`, `${channel.urlEnv}=`);
  }
  return `${lines.join('\n')}\n`;
}

/** Problems the form itself can catch before schema validation, as readable messages. */
export function stateProblems(state: GeneratorState): string[] {
  const problems: string[] = [];
  if (state.products.length === 0) {
    problems.push('Pick at least one product.');
  }
  for (const p of state.products) {
    if (!isVersion(p.version.trim())) {
      problems.push(
        p.version.trim() === ''
          ? `${p.slug}: enter a version.`
          : `${p.slug}: "${p.version}" is not a version (letters, digits and . + : ~ _ - only).`,
      );
    }
  }
  if (state.channels.length === 0) {
    problems.push('Add at least one channel.');
  }
  for (const c of state.channels) {
    if (!isEnvName(c.urlEnv)) {
      problems.push(
        `"${c.urlEnv}" is not a valid variable name (capital letters, digits and _, starting with a letter).`,
      );
    }
  }
  if (state.mode !== 'instant' && !isTime(state.digestTime)) {
    problems.push('Digest time must be HH:MM.');
  }
  return problems;
}

/* URL fragment: #p=postgresql~f~17,traefik~e~3.7.19&s=high&m=digest&t=08:00&z=Europe/Berlin&c=discord~DISCORD_WEBHOOK_URL~ops */

export function encodeState(state: GeneratorState): string {
  const params = new URLSearchParams();
  if (state.products.length > 0) {
    params.set(
      'p',
      state.products
        .map((p) => `${p.slug}~${p.kind === 'floating' ? 'f' : 'e'}~${p.version}`)
        .join(','),
    );
  }
  params.set('s', state.minSeverity);
  params.set('m', state.mode);
  if (state.mode !== 'instant') {
    params.set('t', state.digestTime);
    params.set('z', state.timezone);
  }
  params.set(
    'c',
    state.channels
      .map((c) =>
        [c.type, c.urlEnv, cleanName(c.name).replace(/[~,]/g, ' ')]
          .filter((part) => part !== '')
          .join('~'),
      )
      .join(','),
  );
  return params.toString();
}

/**
 * Reads a fragment back. Anything malformed is dropped piece by piece, never thrown: a shared
 * link is untrusted input, and the result only ever reaches the page as text.
 */
export function decodeState(
  fragment: string,
  knownSlugs: ReadonlySet<string>,
  fallbackZone = 'UTC',
): GeneratorState {
  const state = defaultState(fallbackZone);
  const params = new URLSearchParams(fragment.replace(/^#/, ''));
  const products = params.get('p');
  if (products !== null) {
    const seen = new Set<string>();
    for (const part of products.split(',')) {
      const [slug = '', kind = '', ...rest] = part.split('~');
      const version = rest.join('~');
      if (
        SLUG.test(slug) &&
        knownSlugs.has(slug) &&
        !seen.has(slug) &&
        (kind === 'f' || kind === 'e')
      ) {
        seen.add(slug);
        state.products.push({
          slug,
          kind: kind === 'f' ? 'floating' : 'exact',
          version: isVersion(version) ? version : '',
        });
      }
    }
  }
  const severity = params.get('s');
  if (severity !== null && (SEVERITIES as readonly string[]).includes(severity)) {
    state.minSeverity = severity as Severity;
  }
  const mode = params.get('m');
  if (mode !== null && (MODES as readonly string[]).includes(mode)) {
    state.mode = mode as Mode;
  }
  const time = params.get('t');
  if (time !== null && isTime(time)) {
    state.digestTime = time;
  }
  const zone = params.get('z');
  if (zone !== null && ZONE.test(zone)) {
    state.timezone = zone;
  }
  const channels = params.get('c');
  if (channels !== null) {
    const parsed: PickedChannel[] = [];
    for (const part of channels.split(',')) {
      const [type = '', urlEnv = '', name = ''] = part.split('~');
      if ((CHANNEL_TYPES as readonly string[]).includes(type) && isEnvName(urlEnv)) {
        parsed.push({ type: type as ChannelType, urlEnv, name: cleanName(name) });
      }
    }
    if (parsed.length > 0) {
      state.channels = parsed.slice(0, 10);
    }
  }
  return state;
}

/** A variable name not used yet for this channel type: DISCORD_WEBHOOK_URL, then DISCORD_WEBHOOK_URL_2 ... */
export function nextEnvName(type: ChannelType, taken: readonly string[]): string {
  const base = DEFAULT_ENV[type];
  if (!taken.includes(base)) {
    return base;
  }
  let n = 2;
  while (taken.includes(`${base}_${n}`)) {
    n += 1;
  }
  return `${base}_${n}`;
}
