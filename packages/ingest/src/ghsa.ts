import type { CatalogEntry } from '@advisorydeck/contract';
import type { Http } from './http.ts';
import { trimGhsa, type GhsaAdvisory, type GhsaRecord } from './records.ts';
import type { IngestState, Store } from './store.ts';

/**
 * GitHub security advisories (GitHub Advisory Database, CC-BY-4.0), from the REST API:
 * - repository advisories, GET /repos/{owner}/{repo}/security-advisories (published ones are
 *   public), for products whose vendor publishes there (Coolify, Traefik, Moby, Redis);
 * - global advisories, GET /advisories?ecosystem=&affects=, for packages in the catalog.
 * Both are read newest-updated first and stop at the cursor, so a rerun costs one request per query.
 */
const API = 'https://api.github.com';

export interface GhsaQuery {
  key: string;
  url: string;
  kind: 'repo' | 'global';
  repository: string | null;
}

export interface GhsaContext {
  http: Http;
  store: Store;
  state: IngestState;
  log: (message: string) => void;
}

export interface GhsaResult {
  requests: number;
  seen: number;
  stored: number;
  removed: number;
}

/** One query per ghsa-repo and ghsa-package source in the catalog, in a stable order. */
export function ghsaQueries(entries: readonly CatalogEntry[]): GhsaQuery[] {
  const queries = new Map<string, GhsaQuery>();
  for (const { product } of entries) {
    for (const source of product.sources) {
      if (source.type === 'ghsa-repo') {
        queries.set(`repo:${source.repo}`, {
          key: `repo:${source.repo}`,
          url: `${API}/repos/${source.repo}/security-advisories?state=published&sort=updated&direction=desc&per_page=100`,
          kind: 'repo',
          repository: source.repo,
        });
      } else if (source.type === 'ghsa-package') {
        const key = `package:${source.ecosystem}:${source.package}`;
        queries.set(key, {
          key,
          url: `${API}/advisories?type=reviewed&ecosystem=${encodeURIComponent(source.ecosystem)}&affects=${encodeURIComponent(source.package)}&sort=updated&direction=desc&per_page=100`,
          kind: 'global',
          repository: null,
        });
      }
    }
  }
  return [...queries.values()].sort((a, b) => (a.key < b.key ? -1 : 1));
}

function storeAdvisory(
  ctx: GhsaContext,
  query: GhsaQuery,
  advisory: GhsaAdvisory,
  result: GhsaResult,
): void {
  const id = advisory.ghsa_id;
  const before = ctx.store.ghsa.get(id);
  const record: GhsaRecord = before ?? { id, repository: null, repo: null, global: null };
  const gone =
    advisory.withdrawn_at !== null || (advisory.published_at ?? '') < ctx.state.published_floor;
  const next: GhsaRecord =
    query.kind === 'repo'
      ? { ...record, repository: gone ? null : query.repository, repo: gone ? null : advisory }
      : { ...record, global: gone ? null : advisory };
  if (next.repo === null && next.global === null) {
    if (before !== undefined) {
      ctx.store.ghsa.delete(id);
      result.removed += 1;
    }
    return;
  }
  ctx.store.ghsa.set(id, next);
  result.stored += 1;
}

/**
 * Reads every GHSA query down to its cursor. Without a token GitHub allows 60 requests an hour,
 * so pages per query are capped lower; the cursor only moves when a query reached it.
 */
export async function ingestGhsa(
  ctx: GhsaContext,
  queries: readonly GhsaQuery[],
): Promise<GhsaResult> {
  const result: GhsaResult = { requests: 0, seen: 0, stored: 0, removed: 0 };
  const maxPages = ctx.http.authenticated ? 50 : 5;
  // Cursors of queries the catalog no longer has are dropped.
  ctx.state.ghsa = Object.fromEntries(
    Object.entries(ctx.state.ghsa).filter(([key]) => queries.some((q) => q.key === key)),
  );
  for (const query of queries) {
    const cursor = ctx.state.ghsa[query.key];
    let newest = cursor;
    let url: string | undefined = query.url;
    let pages = 0;
    let reached = false;
    while (url !== undefined) {
      if (pages >= maxPages) {
        ctx.log(`${query.key}: stopped after ${pages} pages, cursor kept`);
        break;
      }
      const page: { data: Record<string, unknown>[]; next: string | undefined } | undefined =
        await ctx.http.json<Record<string, unknown>[]>(url);
      pages += 1;
      result.requests += 1;
      if (page === undefined) {
        ctx.log(`${query.key}: not found`);
        reached = true;
        break;
      }
      for (const raw of page.data) {
        const advisory = trimGhsa(raw);
        if (cursor !== undefined && advisory.updated_at < cursor) {
          reached = true;
          break;
        }
        result.seen += 1;
        if (newest === undefined || advisory.updated_at > newest) newest = advisory.updated_at;
        if (raw['type'] === 'malware') continue;
        storeAdvisory(ctx, query, advisory, result);
      }
      if (reached) break;
      url = page.next;
      if (url === undefined) reached = true;
    }
    if (reached && newest !== undefined) ctx.state.ghsa[query.key] = newest;
  }
  return result;
}
