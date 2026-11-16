/**
 * Groups advisories by publication day and product, so one vendor release that fixes dozens of
 * CVEs reads as one block instead of burying everything else. Display only: the feed and the
 * image are unaffected.
 */
import { SEVERITY_ORDER, type AdvisoryView, type SeverityLevel } from './feed.ts';

export interface DayGroup {
  day: string;
  products: ProductGroup[];
}

export interface ProductGroup {
  slug: string;
  name: string;
  /** Newest first, as given. */
  advisories: AdvisoryView[];
  /** The most severe first (level, then score), for the preview rows. */
  bySeverity: AdvisoryView[];
  highest: SeverityLevel;
}

const rank = (level: SeverityLevel): number => SEVERITY_ORDER.indexOf(level);

export function groupByDayAndProduct(advisories: readonly AdvisoryView[]): DayGroup[] {
  const days: DayGroup[] = [];
  for (const advisory of advisories) {
    const day = advisory.publishedAt.slice(0, 10);
    let group = days.at(-1);
    if (group?.day !== day) {
      group = { day, products: [] };
      days.push(group);
    }
    const first = advisory.affected[0];
    const slug = first?.slug ?? 'unknown';
    let product = group.products.find((p) => p.slug === slug);
    if (product === undefined) {
      product = {
        slug,
        name: first?.name ?? slug,
        advisories: [],
        bySeverity: [],
        highest: 'unknown',
      };
      group.products.push(product);
    }
    product.advisories.push(advisory);
  }
  for (const day of days) {
    for (const product of day.products) {
      product.bySeverity = [...product.advisories].sort(
        (a, b) =>
          rank(a.severity.level) - rank(b.severity.level) ||
          (b.severity.score ?? -1) - (a.severity.score ?? -1),
      );
      product.highest = product.bySeverity[0]?.severity.level ?? 'unknown';
    }
  }
  return days;
}
