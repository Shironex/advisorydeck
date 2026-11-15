import type { ImageConfig } from './generated/types.ts';

/** Defaults the image applies to optional settings. Keep in sync with image/internal/config. */
export const imageConfigDefaults = {
  pollInterval: '30m',
  minSeverity: 'high',
  mode: 'digest',
  digestTime: '08:00',
  digestTimezone: 'UTC',
  statePath: '/data/state.json',
} as const;

export const MIN_POLL_SECONDS = 5 * 60;

const UNIT_SECONDS = { s: 1, m: 60, h: 3600 } as const;

/** Seconds in a duration such as 30m, or undefined when it is not one. */
export function durationSeconds(value: string): number | undefined {
  const match = /^([0-9]+)(s|m|h)$/.exec(value);
  if (match === null) {
    return undefined;
  }
  return Number(match[1]) * UNIT_SECONDS[match[2] as keyof typeof UNIT_SECONDS];
}

function isTimeZone(name: string): boolean {
  try {
    new Intl.DateTimeFormat('en', { timeZone: name });
    return true;
  } catch {
    return false;
  }
}

/**
 * Rules the image enforces that the JSON Schema cannot express. Run after schema validation.
 * The Go image applies the same rules (image/internal/config); fixtures/image/invalid-semantic pins both.
 */
export function imageConfigProblems(config: ImageConfig): string[] {
  const problems: string[] = [];
  const seconds = durationSeconds(config.feed.poll_interval ?? imageConfigDefaults.pollInterval);
  if (seconds === undefined || seconds < MIN_POLL_SECONDS) {
    problems.push('feed.poll_interval must be at least 5m');
  }
  const slugs = new Set<string>();
  for (const product of config.products) {
    if (slugs.has(product.slug)) {
      problems.push(`products: ${product.slug} is listed more than once`);
    }
    slugs.add(product.slug);
  }
  const zone = config.digest?.timezone ?? imageConfigDefaults.digestTimezone;
  if (!isTimeZone(zone)) {
    problems.push(`digest.timezone: ${zone} is not an IANA time zone`);
  }
  return problems;
}
