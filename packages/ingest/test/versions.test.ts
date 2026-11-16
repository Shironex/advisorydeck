import { describe, expect, it } from 'vitest';
import {
  cleanVersion,
  clipOpenRanges,
  compactHyphenRange,
  compareSemverLike,
  parseRangeExpression,
  pep440Prereleases,
  perBranchUpperBounds,
  singlePatchedVersion,
} from '../src/versions.ts';

describe('cleanVersion', () => {
  it('trims and drops a leading v', () => {
    expect(cleanVersion(' v3.7.18 ')).toBe('3.7.18');
    expect(cleanVersion('4.0.0-beta.420.6 ')).toBe('4.0.0-beta.420.6');
    expect(cleanVersion('26.1.5+incompatible')).toBe('26.1.5+incompatible');
  });

  it('reads Java milestone and release suffixes as semver', () => {
    expect(cleanVersion('9.0.0.M1')).toBe('9.0.0-M1');
    expect(cleanVersion('9.0.0.RC3')).toBe('9.0.0-RC3');
    expect(cleanVersion('5.2.25.RELEASE')).toBe('5.2.25');
    expect(cleanVersion('11.0.0-M1')).toBe('11.0.0-M1');
    expect(cleanVersion('5.2.25.SR1')).toBe('5.2.25.SR1');
  });

  it('rejects text that is not a version', () => {
    expect(cleanVersion('< 1.0')).toBeUndefined();
    expect(cleanVersion('x.58.0')).toBeUndefined();
    expect(cleanVersion('R36')).toBeUndefined();
    expect(cleanVersion('All')).toBeUndefined();
    expect(cleanVersion('')).toBeUndefined();
  });
});

describe('parseRangeExpression (real upstream strings)', () => {
  it('reads a lower and an upper bound joined by a comma as one range', () => {
    expect(parseRangeExpression('>= v3.1.0, <= v3.7.17')).toEqual([
      { introduced: '3.1.0', last_affected: '3.7.17' },
    ]);
  });

  it('reads a lone upper bound from the first version', () => {
    expect(parseRangeExpression('< 29.9.3')).toEqual([{ introduced: '0', fixed: '29.9.3' }]);
    expect(parseRangeExpression('<=v2.0.0-beta.28')).toEqual([
      { introduced: '0', last_affected: '2.0.0-beta.28' },
    ]);
  });

  it('reads a comma as a separator between ranges and a hyphen range', () => {
    expect(parseRangeExpression('<= 25.0.18, 26.0.0 - 29.8.1')).toEqual([
      { introduced: '0', last_affected: '25.0.18' },
      { introduced: '26.0.0', last_affected: '29.8.1' },
    ]);
  });

  it('starts each listed branch at its own major.minor (docker-ce)', () => {
    expect(parseRangeExpression('<= v19.03.15, <= v20.10.27, <= v26.1.4')).toEqual([
      { introduced: '0', last_affected: '19.03.15' },
      { introduced: '20.10.0', last_affected: '20.10.27' },
      { introduced: '26.1.0', last_affected: '26.1.4' },
    ]);
  });

  it('sorts upper bounds written newest first (Valkey)', () => {
    expect(parseRangeExpression('<= 9.1.1, <= 9.0.5, <= 8.1.9, <= 8.0.10')).toEqual([
      { introduced: '0', last_affected: '8.0.10' },
      { introduced: '8.1.0', last_affected: '8.1.9' },
      { introduced: '9.0.0', last_affected: '9.0.5' },
      { introduced: '9.1.0', last_affected: '9.1.1' },
    ]);
  });

  it('starts a branch whose bound is a prerelease at its lowest prerelease (runc)', () => {
    expect(parseRangeExpression('<=1.3.5,<=1.4.2,<=1.5.0-rc.2')).toEqual([
      { introduced: '0', last_affected: '1.3.5' },
      { introduced: '1.4.0', last_affected: '1.4.2' },
      { introduced: '1.5.0-0', last_affected: '1.5.0-rc.2' },
    ]);
    expect(parseRangeExpression('< 1.0.4, < 1.1.0')).toEqual([
      { introduced: '0', fixed: '1.0.4' },
      { introduced: '1.1.0-0', fixed: '1.1.0' },
    ]);
  });

  it('reads an operator written after its version, swapped, or a && join', () => {
    expect(parseRangeExpression('v3.23.0>=, <v6.23.0')).toEqual([
      { introduced: '3.23.0', fixed: '6.23.0' },
    ]);
    expect(parseRangeExpression('=>9.0.0, <= 9.0.2')).toEqual([
      { introduced: '9.0.0', last_affected: '9.0.2' },
    ]);
    expect(parseRangeExpression('>= 5.18.0 && < 6.21.1')).toEqual([
      { introduced: '5.18.0', fixed: '6.21.1' },
    ]);
  });

  it('reads a lower bound alone as no fix yet, and an exact version', () => {
    expect(parseRangeExpression('>= 7.0.0')).toEqual([{ introduced: '7.0.0' }]);
    expect(parseRangeExpression('= 1.2.3')).toEqual([
      { introduced: '1.2.3', last_affected: '1.2.3' },
    ]);
  });

  it('reads a lower and an upper bound joined by a space (n8n)', () => {
    expect(parseRangeExpression('< 1.123.22, >= 2.0.0 < 2.9.3, >= 2.10.0 < 2.10.1')).toEqual([
      { introduced: '0', fixed: '1.123.22' },
      { introduced: '2.0.0', fixed: '2.9.3' },
      { introduced: '2.10.0', fixed: '2.10.1' },
    ]);
  });

  it('reads a hyphen range written without spaces (Oracle, MariaDB)', () => {
    expect(parseRangeExpression('8.4.0-8.4.12')).toEqual([
      { introduced: '8.4.0', last_affected: '8.4.12' },
    ]);
    expect(parseRangeExpression('10.6.1-10.6.27, 13.0.1')).toEqual([
      { introduced: '10.6.1', last_affected: '10.6.27' },
      { introduced: '13.0.1', last_affected: '13.0.1' },
    ]);
    expect(parseRangeExpression('8.4.12-8.4.0')).toBeUndefined();
  });

  it('still reads prereleases and distro revisions as one version', () => {
    expect(parseRangeExpression('1.2.0-rc.1')).toEqual([
      { introduced: '1.2.0-rc.1', last_affected: '1.2.0-rc.1' },
    ]);
    expect(parseRangeExpression('< 4.0.0-beta.474')).toEqual([
      { introduced: '0', fixed: '4.0.0-beta.474' },
    ]);
    expect(parseRangeExpression('<= 5.15.0-122.132')).toEqual([
      { introduced: '0', last_affected: '5.15.0-122.132' },
    ]);
    expect(parseRangeExpression('>= 8.0-rc1')).toEqual([{ introduced: '8.0-rc1' }]);
  });

  it('refuses words that carry no range', () => {
    expect(parseRangeExpression('All')).toBeUndefined();
    expect(parseRangeExpression('')).toBeUndefined();
    expect(parseRangeExpression('< TBD!')).toBeUndefined();
  });
});

describe('singlePatchedVersion', () => {
  it('takes one version, with or without >=', () => {
    expect(singlePatchedVersion('>= v4.0.0-beta.469')).toBe('4.0.0-beta.469');
    expect(singlePatchedVersion('29.9.3')).toBe('29.9.3');
  });

  it('ignores lists and placeholders', () => {
    expect(singlePatchedVersion('8.2.2, 7.4.6')).toBeUndefined();
    expect(singlePatchedVersion('TBD')).toBeUndefined();
    expect(singlePatchedVersion('None')).toBeUndefined();
    expect(singlePatchedVersion(null)).toBeUndefined();
  });
});

describe('compareSemverLike', () => {
  it('orders prerelease numbers numerically and releases after prereleases', () => {
    expect(compareSemverLike('4.0.0-beta.9', '4.0.0-beta.474')).toBe(-1);
    expect(compareSemverLike('4.0.0-beta.474', '4.0.0')).toBe(-1);
    expect(compareSemverLike('3.6.12', '3.6.11')).toBe(1);
    expect(compareSemverLike('4.0.0-beta.420.7', '4.0.0-beta.420.6')).toBe(1);
    expect(compareSemverLike('17', '17.1')).toBeUndefined();
  });
});

describe('perBranchUpperBounds', () => {
  it('sorts the bounds and starts each on the line after the previous one', () => {
    expect(
      perBranchUpperBounds([
        { introduced: '0', fixed: '26.7.1' },
        { introduced: '0', fixed: '26.4.14' },
        { introduced: '0', last_affected: '26.6.4' },
      ]),
    ).toEqual([
      { introduced: '0', fixed: '26.4.14' },
      { introduced: '26.5.0', last_affected: '26.6.4' },
      { introduced: '26.7.0', fixed: '26.7.1' },
    ]);
  });

  it('keeps the prereleases of a line whose first release or prerelease is the bound', () => {
    expect(
      perBranchUpperBounds([
        { introduced: '0', last_affected: '9.2.0-rc1' },
        { introduced: '0', last_affected: '9.1.2' },
      ]),
    ).toEqual([
      { introduced: '0', last_affected: '9.1.2' },
      { introduced: '9.2.0-0', last_affected: '9.2.0-rc1' },
    ]);
  });

  it('leaves shapes it cannot read as one fix per branch', () => {
    expect(perBranchUpperBounds([{ introduced: '0', fixed: '1.2.3' }])).toBeUndefined();
    expect(
      perBranchUpperBounds([
        { introduced: '0', fixed: '4.0.0-beta.471' },
        { introduced: '0', fixed: '4.0.0-beta.470' },
      ]),
    ).toBeUndefined();
    expect(
      perBranchUpperBounds([
        { introduced: '0', fixed: '1.2.3' },
        { introduced: '2.0.0', fixed: '2.1.3' },
      ]),
    ).toBeUndefined();
    expect(
      perBranchUpperBounds([{ introduced: '0', fixed: '1.2.3' }, { introduced: '0' }]),
    ).toBeUndefined();
    expect(
      perBranchUpperBounds([
        { introduced: '0', fixed: '17' },
        { introduced: '0', fixed: '16.4' },
      ]),
    ).toBeUndefined();
  });
});

describe('compactHyphenRange', () => {
  it('takes two versions with the same number of parts', () => {
    expect(compactHyphenRange('26.7.0-26.7.1')).toEqual({
      introduced: '26.7.0',
      last_affected: '26.7.1',
    });
    expect(compactHyphenRange('v1.2-v1.4')).toEqual({ introduced: '1.2', last_affected: '1.4' });
  });

  it('leaves prereleases, distro revisions and single versions alone', () => {
    for (const raw of [
      '1.2.0-rc.1',
      '4.0.0-beta.474',
      '1.0.0-alpha.1',
      '5.15.0-122.132',
      '8.4.0',
    ]) {
      expect(compactHyphenRange(raw)).toBeUndefined();
    }
  });

  it('marks a reversed range as unreadable', () => {
    expect(compactHyphenRange('8.4.12-8.4.0')).toBeNull();
  });
});

describe('pep440Prereleases', () => {
  it('writes PEP 440 prereleases as semver prereleases', () => {
    expect(pep440Prereleases('>= 6.0a1, < 6.0.8')).toBe('>= 6.0-a1, < 6.0.8');
    expect(pep440Prereleases('3.15.0rc3')).toBe('3.15.0-rc3');
    expect(pep440Prereleases('3.15.0b2')).toBe('3.15.0-b2');
    expect(pep440Prereleases('1.2c1')).toBe('1.2-rc1');
  });

  it('leaves releases, other suffixes and semver prereleases alone', () => {
    for (const text of ['< 5.2.17', '1.0.post1', '1.0.dev3', '3.14.0-rc1', '18beta1', 'All']) {
      expect(pep440Prereleases(text)).toBe(text);
    }
  });
});

describe('clipOpenRanges', () => {
  it('ends an open range on the branch before the next listed start', () => {
    expect(
      clipOpenRanges([
        { introduced: '1.31.0', fixed: '1.31.7' },
        { introduced: '1.30.0', fixed: '1.30.6' },
        { introduced: '1.25.0' },
      ]),
    ).toEqual([
      { introduced: '1.31.0', fixed: '1.31.7' },
      { introduced: '1.30.0', fixed: '1.30.6' },
      { introduced: '1.25.0', last_affected: '1.29' },
    ]);
    expect(clipOpenRanges([{ introduced: '0' }, { introduced: '3.0.0', fixed: '3.0.4' }])).toEqual([
      { introduced: '0', last_affected: '2' },
      { introduced: '3.0.0', fixed: '3.0.4' },
    ]);
  });

  it('leaves an open range open when nothing later starts a line', () => {
    const ranges = [{ introduced: '7.0.0' }, { introduced: '6.2.0', fixed: '6.2.20' }];
    expect(clipOpenRanges(ranges)).toEqual(ranges);
    const midLine = [{ introduced: '1.25.0' }, { introduced: '1.30.2', fixed: '1.30.6' }];
    expect(clipOpenRanges(midLine)).toEqual(midLine);
    const unfixed = [{ introduced: '1.25.0' }, { introduced: '1.30.0' }];
    expect(clipOpenRanges(unfixed)).toEqual(unfixed);
  });
});
