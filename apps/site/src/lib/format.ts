/**
 * Date and number formatting. Day headings are long ("Thursday 12 November 2026"), dense rows
 * and facts short ("12 Nov 2026"), times in UTC with the zone written out. Machine-readable
 * values (datetime attributes, Atom) keep ISO days.
 */

export function isoDay(timestamp: string): string {
  return timestamp.slice(0, 10);
}

function utc(timestamp: string): Date {
  // A bare day (2026-11-12) is read as midnight UTC.
  return new Date(timestamp.length === 10 ? `${timestamp}T00:00:00Z` : timestamp);
}

/** Thursday 12 November 2026 */
export function longDay(timestamp: string): string {
  const d = utc(timestamp);
  const weekday = d.toLocaleString('en-GB', { weekday: 'long', timeZone: 'UTC' });
  return `${weekday} ${d.toLocaleString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' })}`;
}

/** 12 Nov 2026 */
export function shortDate(timestamp: string): string {
  return utc(timestamp).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

/** 12 Nov 2026, 14:15 UTC */
export function dateTimeUtc(timestamp: string): string {
  const d = utc(timestamp);
  const time = d.toLocaleString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
  });
  return `${shortDate(timestamp)}, ${time} UTC`;
}

export function monthLabel(timestamp: string): string {
  return utc(timestamp).toLocaleString('en', { month: 'long', year: 'numeric', timeZone: 'UTC' });
}

export function percent(value: number): string {
  const pct = value * 100;
  return `${pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}
