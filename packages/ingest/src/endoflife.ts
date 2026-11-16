import type { Http } from './http.ts';
import type { BranchRecord } from './records.ts';
import { cleanVersion } from './versions.ts';

/** endoflife.date API v1 (MIT): release branches, EOL dates and latest versions, newest first. */
const API = 'https://endoflife.date/api/v1/products';

interface EolRelease {
  name: string;
  isEol: boolean;
  eolFrom: string | null;
  latest: { name: string } | null;
}

export function toBranches(releases: readonly EolRelease[]): BranchRecord[] {
  const out: BranchRecord[] = [];
  for (const release of releases) {
    const name = cleanVersion(release.name);
    if (name === undefined) continue;
    const latest = release.latest === null ? undefined : cleanVersion(release.latest.name);
    out.push({
      name,
      eol: release.isEol,
      eol_date:
        release.eolFrom !== null && /^\d{4}-\d{2}-\d{2}$/.test(release.eolFrom)
          ? release.eolFrom
          : null,
      latest: latest ?? null,
    });
  }
  return out;
}

export async function fetchBranches(http: Http, slug: string): Promise<BranchRecord[] | undefined> {
  const response = await http.json<{ result: { releases: EolRelease[] } }>(
    `${API}/${encodeURIComponent(slug)}`,
  );
  return response === undefined ? undefined : toBranches(response.data.result.releases);
}
