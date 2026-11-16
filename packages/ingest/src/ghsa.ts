import type { CatalogEntry } from '@advisorydeck/contract';
import type { Http } from './http.ts';
import { trimGhsa, type GhsaAdvisory, type GhsaRecord } from './records.ts';
import type { IngestState, Store } from './store.ts';

/**
 * GitHub security advisories (GitHub Advisory Database, CC-BY-4.0), from the REST API:
 * - repository advisories, GET /repos/{owner}/{repo}/security-advisories (published ones are
 *   public), for products whose vendor publishes there (Coolify, Traefik, Moby, Redis);
 * - global advisories, GET /advisories?ecosystem=&affects=a,b,c, one query per ecosystem for
 *   every package the catalog names in it.
 * Both are read newest-updated first and stop at the cursor, so a rerun costs one request per query.
 */
const API = 'https://api.github.com';

export interface GhsaQuery {
  key: string;
  url: string;
  kind: 'repo' | 'global';
  repository: string | null;
  /**
   * State keys holding the cursor of this query: the query key for a repository, one key per
   * package for a batched global query (package:<ecosystem>:<name>). A batch reads down to the
   * oldest of them, so a package added to the catalog starts with its full history.
   */
  cursorKeys: string[];
}

/** Packages per global query. GitHub accepts up to 1000; the URL must also stay under 2048 bytes. */
const MAX_PACKAGES_PER_QUERY = 100;
const MAX_URL_LENGTH = 2000;

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

/**
 * One query per ghsa-repo source and one per ecosystem for the ghsa-package sources (the global
 * endpoint takes a comma-separated affects list), in a stable order. A long package list is split
 * so each URL stays short.
 */
export function ghsaQueries(entries: readonly CatalogEntry[]): GhsaQuery[] {
  const queries = new Map<string, GhsaQuery>();
  const packages = new Map<string, Set<string>>();
  for (const { product } of entries) {
    for (const source of product.sources) {
      if (source.type === 'ghsa-repo') {
        queries.set(`repo:${source.repo}`, {
          key: `repo:${source.repo}`,
          url: `${API}/repos/${source.repo}/security-advisories?state=published&sort=updated&direction=desc&per_page=100`,
          kind: 'repo',
          repository: source.repo,
          cursorKeys: [`repo:${source.repo}`],
        });
      } else if (source.type === 'ghsa-package') {
        const names = packages.get(source.ecosystem) ?? new Set<string>();
        names.add(source.package);
        packages.set(source.ecosystem, names);
      }
    }
  }
  for (const [ecosystem, names] of packages) {
    const chunks: string[][] = [];
    for (const name of [...names].sort()) {
      const chunk = chunks.at(-1);
      const fits =
        chunk !== undefined &&
        chunk.length < MAX_PACKAGES_PER_QUERY &&
        globalUrl(ecosystem, [...chunk, name]).length <= MAX_URL_LENGTH;
      if (fits) chunk.push(name);
      else chunks.push([name]);
    }
    for (const [i, chunk] of chunks.entries()) {
      const key = `global:${ecosystem}${chunks.length > 1 ? `:${i + 1}` : ''}`;
      queries.set(key, {
        key,
        url: globalUrl(ecosystem, chunk),
        kind: 'global',
        repository: null,
        cursorKeys: chunk.map((name) => `package:${ecosystem}:${name}`),
      });
    }
  }
  return [...queries.values()].sort((a, b) => (a.key < b.key ? -1 : 1));
}

function globalUrl(ecosystem: string, names: readonly string[]): string {
  const affects = names.map((name) => encodeURIComponent(name)).join(',');
  return `${API}/advisories?type=reviewed&ecosystem=${encodeURIComponent(ecosystem)}&affects=${affects}&sort=updated&direction=desc&per_page=100`;
}

/** The cursor a query reads down to: the oldest of its keys, or none when any key has none. */
function queryCursor(state: Pick<IngestState, 'ghsa'>, query: GhsaQuery): string | undefined {
  let oldest: string | undefined;
  for (const key of query.cursorKeys) {
    const cursor = state.ghsa[key];
    if (cursor === undefined) return undefined;
    if (oldest === undefined || cursor < oldest) oldest = cursor;
  }
  return oldest;
}

/** Page cap per query without a token (60 requests an hour) and with one (5000). */
export const ANONYMOUS_MAX_PAGES = 5;
export const AUTHENTICATED_MAX_PAGES = 50;

/**
 * GitHub REST requests the GHSA queries will cost: at least one per query, and up to the page cap
 * for a query without a cursor (a source new to the catalog reads its whole history).
 */
export function planGhsaRequests(
  queries: readonly GhsaQuery[],
  state: Pick<IngestState, 'ghsa'>,
  authenticated: boolean,
): { minimum: number; worstCase: number; withoutCursor: number } {
  const cap = authenticated ? AUTHENTICATED_MAX_PAGES : ANONYMOUS_MAX_PAGES;
  let worstCase = 0;
  let withoutCursor = 0;
  for (const query of queries) {
    const fresh = queryCursor(state, query) === undefined;
    if (fresh) withoutCursor += 1;
    worstCase += fresh ? cap : 1;
  }
  return { minimum: queries.length, worstCase, withoutCursor };
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
  const maxPages = ctx.http.authenticated ? AUTHENTICATED_MAX_PAGES : ANONYMOUS_MAX_PAGES;
  // Cursors of queries the catalog no longer has are dropped.
  const keys = new Set(queries.flatMap((q) => q.cursorKeys));
  ctx.state.ghsa = Object.fromEntries(
    Object.entries(ctx.state.ghsa).filter(([key]) => keys.has(key)),
  );
  for (const query of queries) {
    const cursor = queryCursor(ctx.state, query);
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
    if (reached && newest !== undefined) {
      for (const key of query.cursorKeys) {
        const before = ctx.state.ghsa[key];
        if (before === undefined || newest > before) ctx.state.ghsa[key] = newest;
      }
    }
  }
  return result;
}
