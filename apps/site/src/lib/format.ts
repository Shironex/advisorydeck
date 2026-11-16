/** Date and number formatting. Dates are shown as ISO days (2026-11-16): unambiguous everywhere. */

export function isoDay(timestamp: string): string {
  return timestamp.slice(0, 10);
}

export function monthLabel(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString('en', { month: 'long', year: 'numeric', timeZone: 'UTC' });
}

export function percent(value: number): string {
  const pct = value * 100;
  return `${pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}
