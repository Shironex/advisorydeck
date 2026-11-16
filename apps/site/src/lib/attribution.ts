/**
 * Who the data comes from and under which terms, as NOTICE states it. Used on product pages,
 * advisory pages and the data sources page.
 */
import type { ProductView } from './feed.ts';

export interface Attribution {
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  credit: string;
}

export const ATTRIBUTIONS = {
  cve: {
    name: 'CVE Program, CVE List (cvelistV5)',
    url: 'https://github.com/CVEProject/cvelistV5',
    license: 'CVE Program Terms of Use',
    licenseUrl: 'https://www.cve.org/Legal/TermsOfUse',
    credit:
      'Copyright (c) 1999-2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation.',
  },
  ghsa: {
    name: 'GitHub Advisory Database and repository security advisories',
    url: 'https://github.com/advisories',
    license: 'CC-BY-4.0',
    licenseUrl: 'https://creativecommons.org/licenses/by/4.0/',
    credit:
      'GitHub, Inc. and the advisory authors. Records are trimmed, normalized and merged with the CVE record of the same vulnerability; version ranges are rewritten as described in docs/ingest.md.',
  },
  endoflife: {
    name: 'endoflife.date',
    url: 'https://endoflife.date',
    license: 'MIT',
    licenseUrl: 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE',
    credit: 'Copyright 2020 endoflife.date contributors.',
  },
  kev: {
    name: 'CISA Known Exploited Vulnerabilities catalog',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    license: 'CC0 1.0 Universal',
    licenseUrl: 'https://creativecommons.org/publicdomain/zero/1.0/',
    credit: 'Cybersecurity and Infrastructure Security Agency (CISA).',
  },
  epss: {
    name: 'FIRST Exploit Prediction Scoring System (EPSS)',
    url: 'https://www.first.org/epss/',
    license: 'Free to use, attribution requested',
    licenseUrl: 'https://www.first.org/epss/',
    credit: 'EPSS scores are provided by FIRST.org, Inc.',
  },
  nvd: {
    name: 'National Vulnerability Database (NVD)',
    url: 'https://nvd.nist.gov',
    license: 'NVD terms of use',
    licenseUrl: 'https://nvd.nist.gov/developers/terms-of-use',
    credit: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.',
  },
} as const satisfies Record<string, Attribution>;

/** Feed `sources[].license` codes as readable names. */
export const LICENSE_NAMES: Record<string, { name: string; url: string }> = {
  'CVE-TOU': { name: 'CVE Program Terms of Use', url: ATTRIBUTIONS.cve.licenseUrl },
  'CC-BY-4.0': { name: 'CC-BY-4.0', url: ATTRIBUTIONS.ghsa.licenseUrl },
  CC0: { name: 'CC0', url: 'https://creativecommons.org/publicdomain/zero/1.0/' },
  'CC0-1.0': { name: 'CC0 1.0', url: ATTRIBUTIONS.kev.licenseUrl },
  'FIRST-EPSS': { name: 'FIRST EPSS terms', url: ATTRIBUTIONS.epss.licenseUrl },
  'NVD-TOU': { name: 'NVD terms of use', url: ATTRIBUTIONS.nvd.licenseUrl },
  MIT: { name: 'MIT', url: 'https://opensource.org/license/mit' },
};

export const SOURCE_TYPE_NAMES: Record<string, string> = {
  'cve-cna': 'CVE record',
  ghsa: 'GitHub advisory',
  osv: 'OSV record',
  nvd: 'NVD',
  kev: 'CISA KEV',
  epss: 'FIRST EPSS',
  'vendor-page': 'Vendor page',
  'vendor-feed': 'Vendor feed',
};

export interface ProductSourceLine {
  label: string;
  detail: string;
  url: string | null;
  attribution: Attribution | null;
  /** Only read by people as a cross-check; nothing from it is redistributed. */
  crossCheckOnly: boolean;
}

/** The catalog sources of a product, most trusted first, plus where its branches come from. */
export function productSources(product: ProductView): ProductSourceLine[] {
  const lines: ProductSourceLine[] = product.catalogSources.map((source) => {
    switch (source.type) {
      case 'cve-cna':
        return {
          label: 'CVE records',
          detail: `assigned by ${source.assigner} for ${source.products.join(', ')}`,
          url: ATTRIBUTIONS.cve.url,
          attribution: ATTRIBUTIONS.cve,
          crossCheckOnly: false,
        };
      case 'ghsa-repo':
        return {
          label: 'GitHub repository advisories',
          detail: source.repo,
          url: `https://github.com/${source.repo}/security/advisories`,
          attribution: ATTRIBUTIONS.ghsa,
          crossCheckOnly: false,
        };
      case 'ghsa-package':
        return {
          label: 'GitHub Advisory Database',
          detail: `${source.ecosystem} package ${source.package}`,
          url: ATTRIBUTIONS.ghsa.url,
          attribution: ATTRIBUTIONS.ghsa,
          crossCheckOnly: false,
        };
      case 'osv':
        return {
          label: 'OSV',
          detail: `${source.ecosystem} package ${source.package}`,
          url: 'https://osv.dev',
          attribution: null,
          crossCheckOnly: false,
        };
      case 'vendor-page':
        return {
          label: 'Vendor page',
          detail: source.url,
          url: source.url,
          attribution: null,
          crossCheckOnly: true,
        };
      case 'vendor-feed':
        return {
          label: `Vendor ${source.format} feed`,
          detail: source.url,
          url: source.url,
          attribution: null,
          crossCheckOnly: true,
        };
    }
  });
  if (product.branchSource === 'endoflife') {
    lines.push({
      label: 'Release branches and end-of-life dates',
      detail: 'endoflife.date',
      url: ATTRIBUTIONS.endoflife.url,
      attribution: ATTRIBUTIONS.endoflife,
      crossCheckOnly: false,
    });
  }
  return lines;
}
