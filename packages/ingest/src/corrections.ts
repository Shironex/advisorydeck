import { isDeepStrictEqual } from 'node:util';
import type {
  Advisory,
  AppliedCorrection,
  CorrectionEntry,
  VersionRange,
} from '@advisorydeck/contract';
import { revisionOf } from './advisories.ts';
import { rangeKey } from './versions.ts';

export interface CorrectionReport {
  advisories: Advisory[];
  /** Per published advisory, warnings about its corrections, for data/quality.json. */
  quality: Record<string, string[]>;
  /** Warnings about corrections whose advisory is no longer in the feed (no quality entry to hold them). */
  warnings: string[];
}

/** A range in schema key order, so a correction file's YAML order never reaches the feed. */
function rangeOf(range: VersionRange): VersionRange {
  return {
    introduced: range.introduced,
    ...(range.fixed === undefined ? {} : { fixed: range.fixed }),
    ...(range.last_affected === undefined ? {} : { last_affected: range.last_affected }),
  };
}

/** Same set of ranges, whatever the order. */
export function sameRanges(a: readonly VersionRange[], b: readonly VersionRange[]): boolean {
  return isDeepStrictEqual(a.map(rangeKey).sort(), b.map(rangeKey).sort());
}

/** Ranges as one line of text for a warning: `0 < 26.37.1, 26.7.0 <= 26.7`. */
export function describeRanges(ranges: readonly VersionRange[]): string {
  if (ranges.length === 0) return 'unknown';
  return ranges
    .map((r) =>
      r.fixed !== undefined
        ? `${r.introduced} < ${r.fixed}`
        : r.last_affected !== undefined
          ? `${r.introduced} <= ${r.last_affected}`
          : `>= ${r.introduced}`,
    )
    .join(', ');
}

/** The advisory with its affected list and corrections replaced, keys in schema order, revision recomputed. */
function withCorrections(
  advisory: Advisory,
  affected: Advisory['affected'],
  corrections: AppliedCorrection[],
): Advisory {
  const { note, ...rest } = advisory;
  const draft: Omit<Advisory, 'revision'> = {
    id: rest.id,
    aliases: rest.aliases,
    title: rest.title,
    summary: rest.summary,
    published_at: rest.published_at,
    modified_at: rest.modified_at,
    severity: rest.severity,
    kev: rest.kev,
    epss: rest.epss,
    ...(rest.cwes === undefined ? {} : { cwes: rest.cwes }),
    affected,
    ...(corrections.length > 0
      ? { corrections: corrections as [AppliedCorrection, ...AppliedCorrection[]] }
      : {}),
    references: rest.references,
    sources: rest.sources,
    note,
  };
  const { note: draftNote, ...body } = draft;
  return { ...body, revision: revisionOf(draft), note: draftNote };
}

/**
 * Applies the hand corrections in corrections/ to the built advisories. A correction replaces the
 * ranges of one product in the advisory whose id or alias it names and is listed under the
 * advisory's corrections. It warns, so stale files get removed, when the advisory is no longer in
 * the feed, no longer names the product, or upstream now reads the corrected ranges itself; and it
 * warns but still applies when the upstream reading changed since the correction was written.
 */
export function applyCorrections(
  advisories: readonly Advisory[],
  corrections: readonly CorrectionEntry[],
): CorrectionReport {
  const quality: Record<string, string[]> = {};
  const warnings: string[] = [];
  const byId = new Map<string, number>();
  for (const [i, advisory] of advisories.entries()) {
    for (const id of [advisory.id, ...advisory.aliases]) byId.set(id, i);
  }
  const result = [...advisories];
  const applied = new Map<number, AppliedCorrection[]>();
  const warn = (index: number | undefined, file: string, message: string) => {
    const advisory = index === undefined ? undefined : result[index];
    if (advisory === undefined) {
      warnings.push(`${file}: ${message}`);
    } else {
      quality[advisory.id] = [
        ...(quality[advisory.id] ?? []),
        `hand correction ${file}: ${message}`,
      ];
    }
  };

  const ordered = [...corrections].sort((a, b) => (a.file < b.file ? -1 : 1));
  for (const { file, correction } of ordered) {
    const index = byId.get(correction.advisory);
    const advisory = index === undefined ? undefined : result[index];
    if (index === undefined || advisory === undefined) {
      warn(
        undefined,
        file,
        `${correction.advisory} is no longer in the feed; remove the correction`,
      );
      continue;
    }
    const position = advisory.affected.findIndex((a) => a.product === correction.product);
    const entry = advisory.affected[position];
    if (entry === undefined) {
      warn(
        index,
        file,
        `${advisory.id} no longer names ${correction.product}; remove the correction`,
      );
      continue;
    }
    const done = applied.get(index) ?? [];
    if (done.some((c) => c.product === correction.product)) {
      warn(
        index,
        file,
        `${advisory.id} already has a correction for ${correction.product}; skipped`,
      );
      continue;
    }
    const upstream = entry.ranges.map(rangeOf);
    const ranges = correction.ranges.map(rangeOf);
    if (sameRanges(upstream, ranges)) {
      warn(index, file, 'upstream now reads the corrected ranges itself; remove the correction');
      continue;
    }
    if (!sameRanges(upstream, correction.upstream_ranges)) {
      warn(
        index,
        file,
        `upstream changed since ${correction.corrected_at}: it now reads ${describeRanges(upstream)} instead of ${describeRanges(correction.upstream_ranges)}; recheck the correction (still applied)`,
      );
    }
    const affected = advisory.affected.map((a, i) =>
      i === position ? { product: a.product, ranges } : a,
    ) as Advisory['affected'];
    const corrected: AppliedCorrection = {
      product: correction.product,
      advisory: correction.advisory,
      reason: correction.reason.trim(),
      evidence: correction.evidence,
      corrected_at: correction.corrected_at,
      upstream_ranges: upstream,
    };
    const list = [...done, corrected].sort((a, b) => (a.product < b.product ? -1 : 1));
    applied.set(index, list);
    result[index] = withCorrections(advisory, affected, list);
  }
  return { advisories: result, quality, warnings };
}
