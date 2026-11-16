import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type {
  BranchRecord,
  CveRecord,
  EpssScores,
  GhsaRecord,
  KevCatalog,
  NvdRecord,
} from './records.ts';

/** Paths inside the data directory (data/ in the repository). */
export const dataLayout = {
  advisories: 'advisories',
  api: 'api/v1',
  sources: 'sources',
  state: 'state.json',
  quality: 'quality.json',
} as const;

export interface IngestState {
  /** Only advisories first published on or after this date are kept. */
  published_floor: string;
  /** Last cvelistV5 delta release processed: the day and the release tag. */
  cvelist: { day: string | null; release: string | null };
  /** Per GHSA query (repo:owner/name or package:ecosystem:name), the newest updated_at seen. */
  ghsa: Record<string, string>;
  /** When the EPSS scores were last asked for (RFC 3339); they change once a day. */
  epss_fetched_at?: string;
}

/** JSON with sorted object keys, two-space indent and a final newline: the same input gives the same bytes. */
export function stableJson(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((key) => [key, sort((v as Record<string, unknown>)[key])]),
      );
    }
    return v;
  };
  return `${JSON.stringify(sort(value), null, 2)}\n`;
}

/** Writes the file only when its bytes change; returns true when it did. */
export function writeIfChanged(path: string, text: string): boolean {
  try {
    if (readFileSync(path, 'utf8') === text) return false;
  } catch {
    // missing: write it
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  return true;
}

function readJsonDir<T>(dir: string): Map<string, T> {
  const out = new Map<string, T>();
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue;
    out.set(basename(name, '.json'), JSON.parse(readFileSync(join(dir, name), 'utf8')) as T);
  }
  return out;
}

class Collection<T> {
  readonly items: Map<string, T>;
  private readonly dirty = new Set<string>();
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
    this.items = readJsonDir<T>(dir);
  }

  get(id: string): T | undefined {
    return this.items.get(id);
  }

  set(id: string, value: T): void {
    this.items.set(id, value);
    this.dirty.add(id);
  }

  delete(id: string): void {
    if (this.items.delete(id)) this.dirty.add(id);
  }

  /** Writes changed entries and removes deleted ones; returns the number of files touched. */
  flush(): number {
    let touched = 0;
    for (const id of [...this.dirty].sort()) {
      const path = join(this.dir, `${id}.json`);
      const value = this.items.get(id);
      if (value === undefined) {
        rmSync(path, { force: true });
        touched += 1;
      } else if (writeIfChanged(path, stableJson(value))) {
        touched += 1;
      }
    }
    this.dirty.clear();
    return touched;
  }
}

/** The committed source records and cursors that make reruns incremental. */
export class Store {
  readonly cve: Collection<CveRecord>;
  readonly ghsa: Collection<GhsaRecord>;
  readonly branches: Collection<BranchRecord[]>;
  /** One entry, catalog: the CISA KEV catalog. */
  readonly kev: Collection<KevCatalog>;
  /** One entry, scores: the EPSS scores of the feed's CVEs. */
  readonly epss: Collection<EpssScores>;
  readonly nvd: Collection<NvdRecord>;
  readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    const sources = join(dataDir, dataLayout.sources);
    this.cve = new Collection(join(sources, 'cve'));
    this.ghsa = new Collection(join(sources, 'ghsa'));
    this.branches = new Collection(join(sources, 'endoflife'));
    this.kev = new Collection(join(sources, 'kev'));
    this.epss = new Collection(join(sources, 'epss'));
    this.nvd = new Collection(join(sources, 'nvd'));
  }

  readState(): IngestState | undefined {
    try {
      return JSON.parse(readFileSync(join(this.dataDir, dataLayout.state), 'utf8')) as IngestState;
    } catch {
      return undefined;
    }
  }

  writeState(state: IngestState): void {
    writeIfChanged(join(this.dataDir, dataLayout.state), stableJson(state));
  }

  flush(): number {
    return (
      this.cve.flush() +
      this.ghsa.flush() +
      this.branches.flush() +
      this.kev.flush() +
      this.epss.flush() +
      this.nvd.flush()
    );
  }
}
