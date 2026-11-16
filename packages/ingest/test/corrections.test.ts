import type { Advisory, Correction, CorrectionEntry, VersionRange } from '@advisorydeck/contract';
import { describe, expect, it } from 'vitest';
import { revisionOf } from '../src/advisories.ts';
import { applyCorrections, describeRanges, sameRanges } from '../src/corrections.ts';

function advisory(ranges: Advisory['affected'][number]['ranges']): Advisory {
  const draft: Omit<Advisory, 'revision'> = {
    id: 'CVE-2026-16443',
    aliases: ['GHSA-f8m4-v488-rmrm'],
    title: 'SAML broker metadata import disables response signature validation',
    summary: 'Summary.',
    published_at: '2026-08-06T07:34:42Z',
    modified_at: '2026-08-06T07:34:42Z',
    severity: { level: 'high', score: 7.4, vector: null, source: 'ghsa' },
    kev: { listed: false, added_at: null, checked: true },
    epss: null,
    affected: [
      { product: 'keycloak', ranges },
      { product: 'other', ranges: [{ introduced: '0', fixed: '1.0.0' }] },
    ],
    references: [],
    sources: [
      {
        type: 'ghsa',
        id: 'GHSA-f8m4-v488-rmrm',
        url: 'https://github.com/advisories/GHSA-f8m4-v488-rmrm',
        license: 'CC-BY-4.0',
      },
    ],
    note: null,
  };
  const { note, ...rest } = draft;
  return { ...rest, revision: revisionOf(draft), note };
}

const typo = [
  { introduced: '0', fixed: '26.4.14' },
  { introduced: '26.5.0', fixed: '26.6.5' },
  { introduced: '26.7.0', fixed: '26.37.1' },
];
const fixedRanges: [VersionRange, ...VersionRange[]] = [
  { introduced: '0', fixed: '26.4.14' },
  { introduced: '26.5.0', fixed: '26.6.5' },
  { introduced: '26.7.0', fixed: '26.7.1' },
];

function entry(extra: Partial<Correction> = {}): CorrectionEntry {
  const correction: Correction = {
    advisory: 'GHSA-f8m4-v488-rmrm',
    product: 'keycloak',
    reason: 'The third entry says < 26.37.1 but the fix shipped in 26.7.1.',
    evidence: ['https://github.com/keycloak/keycloak/releases/tag/26.7.1'],
    corrected_at: '2026-11-16',
    upstream_ranges: typo,
    ranges: fixedRanges,
    ...extra,
  };
  return { file: `corrections/${correction.product}/${correction.advisory}.yml`, correction };
}

describe('applyCorrections', () => {
  it('replaces the ranges of the product, lists the correction and recomputes the revision', () => {
    const before = advisory(typo);
    const report = applyCorrections([before], [entry()]);
    const after = report.advisories[0];
    expect(after?.affected[0]).toEqual({ product: 'keycloak', ranges: fixedRanges });
    expect(after?.affected[1]).toEqual(before.affected[1]);
    expect(after?.corrections).toEqual([
      {
        product: 'keycloak',
        advisory: 'GHSA-f8m4-v488-rmrm',
        reason: 'The third entry says < 26.37.1 but the fix shipped in 26.7.1.',
        evidence: ['https://github.com/keycloak/keycloak/releases/tag/26.7.1'],
        corrected_at: '2026-11-16',
        upstream_ranges: typo,
      },
    ]);
    expect(after?.revision).not.toBe(before.revision);
    expect(Object.keys(after ?? {})).toEqual([
      'id',
      'aliases',
      'title',
      'summary',
      'published_at',
      'modified_at',
      'severity',
      'kev',
      'epss',
      'affected',
      'corrections',
      'references',
      'sources',
      'revision',
      'note',
    ]);
    expect(report.warnings).toEqual([]);
    expect(report.quality).toEqual({});
  });

  it('matches the advisory by its id as well as an alias', () => {
    const report = applyCorrections([advisory(typo)], [entry({ advisory: 'CVE-2026-16443' })]);
    expect(report.advisories[0]?.affected[0]?.ranges).toEqual(fixedRanges);
  });

  it('warns when the advisory is no longer in the feed', () => {
    const report = applyCorrections([advisory(typo)], [entry({ advisory: 'GHSA-xxxx-xxxx-xxxx' })]);
    expect(report.warnings).toEqual([
      'corrections/keycloak/GHSA-xxxx-xxxx-xxxx.yml: GHSA-xxxx-xxxx-xxxx is no longer in the feed; remove the correction',
    ]);
    expect(report.advisories[0]?.corrections).toBeUndefined();
  });

  it('warns when the advisory no longer names the product', () => {
    const report = applyCorrections([advisory(typo)], [entry({ product: 'beszel' })]);
    expect(report.quality['CVE-2026-16443']).toEqual([
      'hand correction corrections/beszel/GHSA-f8m4-v488-rmrm.yml: CVE-2026-16443 no longer names beszel; remove the correction',
    ]);
  });

  it('warns and changes nothing when upstream now reads the corrected ranges', () => {
    const before = advisory([...fixedRanges].reverse());
    const report = applyCorrections([before], [entry()]);
    expect(report.advisories[0]).toBe(before);
    expect(report.quality['CVE-2026-16443']?.[0]).toMatch(
      /upstream now reads the corrected ranges/,
    );
  });

  it('still applies but warns when the upstream reading changed since the correction', () => {
    const changed = [{ introduced: '0', fixed: '26.37.2' }];
    const report = applyCorrections([advisory(changed)], [entry()]);
    expect(report.advisories[0]?.affected[0]?.ranges).toEqual(fixedRanges);
    expect(report.advisories[0]?.corrections?.[0]?.upstream_ranges).toEqual(changed);
    expect(report.quality['CVE-2026-16443']?.[0]).toMatch(
      /upstream changed since 2026-11-16: it now reads 0 < 26\.37\.2 instead of 0 < 26\.4\.14, 26\.5\.0 < 26\.6\.5, 26\.7\.0 < 26\.37\.1; recheck/,
    );
  });

  it('skips a second correction of the same advisory and product filed under another id', () => {
    const report = applyCorrections(
      [advisory(typo)],
      [entry(), entry({ advisory: 'CVE-2026-16443' })],
    );
    expect(report.advisories[0]?.corrections).toHaveLength(1);
    expect(report.quality['CVE-2026-16443']?.[0]).toMatch(/already has a correction/);
  });

  it('writes ranges in schema key order whatever the YAML order', () => {
    const report = applyCorrections(
      [advisory(typo)],
      [entry({ ranges: [{ fixed: '26.7.1', introduced: '26.7.0' }] })],
    );
    expect(Object.keys(report.advisories[0]?.affected[0]?.ranges[0] ?? {})).toEqual([
      'introduced',
      'fixed',
    ]);
  });
});

describe('range helpers', () => {
  it('compares ranges as a set', () => {
    expect(sameRanges(typo, [...typo].reverse())).toBe(true);
    expect(sameRanges(typo, fixedRanges)).toBe(false);
  });

  it('describes ranges in one line', () => {
    expect(
      describeRanges([
        { introduced: '0', fixed: '1.2.0' },
        { introduced: '2.0.0', last_affected: '2.1' },
        { introduced: '3.0.0' },
      ]),
    ).toBe('0 < 1.2.0, 2.0.0 <= 2.1, >= 3.0.0');
    expect(describeRanges([])).toBe('unknown');
  });
});
