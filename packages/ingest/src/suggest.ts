/**
 * Pure logic of the weekly catalog suggestion: reads the images that deployment templates use,
 * diffs them against the catalog and renders one markdown issue body. No network, no file writes;
 * everything arrives as text so the input stays untrusted data that is parsed, never executed.
 */

export type TemplateSource = 'coolify' | 'dokploy';

export interface TemplateInput {
  source: TemplateSource;
  name: string;
  /** Text of the compose file. */
  compose: string;
  /** Upstream repository as owner/repo, when the template names one. */
  github?: string | undefined;
}

export interface CatalogImage {
  slug: string;
  ref: string;
  tagPattern: string;
}

export interface SourceNote {
  label: string;
  /** Branch, and the commit when known. */
  detail: string;
}

export type NormalizedImage =
  | { kind: 'image'; ref: string; tag: string | undefined; floating: boolean }
  | { kind: 'variable' }
  | { kind: 'denied'; ref: string };

const PLACEHOLDER = '<var>';

/** Tags that move, so they say nothing about a version. A tag without any digit counts too. */
const FLOATING_TAGS = new Set([
  'latest',
  'main',
  'master',
  'stable',
  'edge',
  'nightly',
  'dev',
  'develop',
  'canary',
  'beta',
  'alpha',
  'rolling',
  'release',
  'current',
]);

/** Helper and sidecar images that are not products. Kept small and explicit. */
export const DENIED_IMAGES: ReadonlySet<string> = new Set([
  'docker.io/library/busybox',
  'docker.io/library/alpine',
  'docker.io/library/scratch',
  'docker.io/library/bash',
  'docker.io/library/x',
  'docker.io/library/image',
  'docker.io/curlimages/curl',
  'docker.io/alpine/curl',
  'docker.io/alpine/socat',
  'docker.io/tianon/true',
]);

/** Registry hosts that are the same registry as Docker Hub. */
const DOCKER_HUB_HOSTS = new Set(['docker.io', 'index.docker.io', 'registry-1.docker.io']);

/** Vendor mirrors whose refs the catalog writes with the Docker Hub name. */
const REF_ALIASES: ReadonlyMap<string, string> = new Map([
  ['docker.n8n.io/n8nio/n8n', 'docker.io/n8nio/n8n'],
]);

const VARIABLE = /\$\{([^}]*)\}|\$[A-Za-z_][A-Za-z0-9_]*/g;
const NAME_SHAPE = /^[a-z0-9][a-z0-9._/:-]*$/;
const TAG_SHAPE = /^[A-Za-z0-9_<][A-Za-z0-9._<>-]{0,127}$/;
const GITHUB_URL = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/;

function substitute(text: string): string {
  return text.replace(VARIABLE, (match: string, inner: string | undefined) => {
    if (inner !== undefined) {
      const fallback = /^[A-Za-z_][A-Za-z0-9_]*:?-(.*)$/.exec(inner)?.[1];
      if (fallback !== undefined && fallback !== '' && !fallback.includes('$')) return fallback;
    }
    return PLACEHOLDER;
  });
}

function isFloatingTag(tag: string | undefined): boolean {
  if (tag === undefined || tag.includes(PLACEHOLDER)) return true;
  return FLOATING_TAGS.has(tag.toLowerCase()) || !/[0-9]/.test(tag);
}

/** Fully qualifies an image reference, splits the tag and drops a digest. */
export function normalizeImage(raw: string): NormalizedImage {
  const unquoted = raw.trim().replace(/^['"]+|['"]+$/g, '');
  const text = substitute(unquoted).split('@')[0] ?? '';
  if (text === '' || text.includes('{') || text.includes('}') || text.includes('$')) {
    return { kind: 'variable' };
  }
  const slash = text.lastIndexOf('/');
  const colon = text.indexOf(':', slash + 1);
  const rawName = (colon < 0 ? text : text.slice(0, colon)).toLowerCase();
  const tag = colon < 0 ? undefined : text.slice(colon + 1);
  if (!NAME_SHAPE.test(rawName) || rawName.includes(PLACEHOLDER)) return { kind: 'variable' };
  if (tag !== undefined && !TAG_SHAPE.test(tag)) return { kind: 'variable' };

  const segments = rawName.split('/');
  const first = segments[0] ?? '';
  const hasRegistry =
    segments.length > 1 && (first.includes('.') || first.includes(':') || first === 'localhost');
  let ref: string;
  if (!hasRegistry) {
    ref = `docker.io/${segments.length === 1 ? 'library/' : ''}${rawName}`;
  } else if (DOCKER_HUB_HOSTS.has(first)) {
    const rest = segments.slice(1);
    ref = `docker.io/${rest.length === 1 ? 'library/' : ''}${rest.join('/')}`;
  } else {
    ref = rawName;
  }
  ref = REF_ALIASES.get(ref) ?? ref;
  if (DENIED_IMAGES.has(ref)) return { kind: 'denied', ref };
  return { kind: 'image', ref, tag, floating: isFloatingTag(tag) };
}

/** The raw values of the image: keys of a compose file, read line by line (never executed). */
export function extractImages(compose: string): string[] {
  const out: string[] = [];
  for (const line of compose.split(/\r?\n/)) {
    const match = /^\s*(?:-\s+)?image:\s*(.+?)\s*$/.exec(line);
    if (match?.[1] === undefined) continue;
    const value = match[1].replace(/\s+#.*$/, '');
    if (value !== '' && !value.startsWith('#')) out.push(value);
  }
  return out;
}

/** owner/repo from a GitHub URL, or undefined for anything else. */
export function githubRepo(url: unknown): string | undefined {
  if (typeof url !== 'string') return undefined;
  const match = GITHUB_URL.exec(url.trim());
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  return `${match[1]}/${match[2]}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Coolify service templates: one JSON object, template name to an entry with base64 compose. */
export function coolifyTemplates(json: unknown): TemplateInput[] {
  if (!isRecord(json)) throw new Error('coolify templates: expected a JSON object');
  const out: TemplateInput[] = [];
  for (const name of Object.keys(json).sort()) {
    const entry = json[name];
    if (!isRecord(entry) || typeof entry['compose'] !== 'string') continue;
    const compose = Buffer.from(entry['compose'], 'base64').toString('utf8');
    const docs = entry['documentation'];
    out.push({ source: 'coolify', name, compose, github: githubRepo(docs) });
  }
  return out;
}

/** One Dokploy blueprint from the text of its docker-compose.yml and meta.json. */
export function dokployTemplate(id: string, compose: string, metaText: string | undefined) {
  let github: string | undefined;
  if (metaText !== undefined) {
    try {
      const meta: unknown = JSON.parse(metaText);
      if (isRecord(meta) && isRecord(meta['links'])) github = githubRepo(meta['links']['github']);
    } catch {
      github = undefined;
    }
  }
  return { source: 'dokploy', name: id, compose, github } satisfies TemplateInput;
}

/** The comment of a ZIP archive (GitHub puts the commit SHA there), if it looks like one. */
export function zipCommit(zip: Buffer): string | undefined {
  const floor = Math.max(0, zip.length - 22 - 0xffff);
  for (let i = zip.length - 22; i >= floor; i -= 1) {
    if (zip.readUInt32LE(i) !== 0x06054b50) continue;
    const length = zip.readUInt16LE(i + 20);
    const comment = zip.toString('utf8', i + 22, i + 22 + length).trim();
    return /^[0-9a-f]{40}$/.test(comment) ? comment : undefined;
  }
  return undefined;
}

export interface Candidate {
  ref: string;
  coolify: string[];
  dokploy: string[];
  pinnedTags: string[];
  upstream: string[];
}

export interface TagMismatch {
  slug: string;
  ref: string;
  tagPattern: string;
  tags: string[];
}

export interface Report {
  candidates: Candidate[];
  mismatches: TagMismatch[];
  unused: { slug: string; ref: string }[];
  stats: {
    coolifyTemplates: number;
    dokployTemplates: number;
    distinctImages: number;
    occurrences: number;
    floatingOccurrences: number;
    variableSkipped: number;
    deniedSkipped: number;
  };
}

interface Seen {
  coolify: Set<string>;
  dokploy: Set<string>;
  tags: Set<string>;
  upstream: Set<string>;
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Whether the last path segment of an image and a repository name point at the same project. */
function namesMatch(ref: string, repoName: string): boolean {
  const leaf = ref.split('/').pop() ?? '';
  return leaf.length >= 3 && (repoName.includes(leaf) || leaf.includes(repoName));
}

/** Diffs the images of the templates against the catalog. Order of the inputs does not matter. */
export function analyze(templates: readonly TemplateInput[], catalog: readonly CatalogImage[]) {
  const seen = new Map<string, Seen>();
  const stats: Report['stats'] = {
    coolifyTemplates: 0,
    dokployTemplates: 0,
    distinctImages: 0,
    occurrences: 0,
    floatingOccurrences: 0,
    variableSkipped: 0,
    deniedSkipped: 0,
  };
  for (const template of templates) {
    if (template.source === 'coolify') stats.coolifyTemplates += 1;
    else stats.dokployTemplates += 1;
    const images = new Map<string, { tags: Set<string>; floating: boolean }>();
    for (const raw of extractImages(template.compose)) {
      const image = normalizeImage(raw);
      if (image.kind === 'variable') stats.variableSkipped += 1;
      else if (image.kind === 'denied') stats.deniedSkipped += 1;
      else {
        const entry = images.get(image.ref) ?? { tags: new Set<string>(), floating: false };
        entry.floating = entry.floating || image.floating;
        if (!image.floating && image.tag !== undefined) entry.tags.add(image.tag);
        images.set(image.ref, entry);
        stats.occurrences += 1;
        if (image.floating) stats.floatingOccurrences += 1;
      }
    }
    for (const [ref, entry] of images) {
      const slot = seen.get(ref) ?? {
        coolify: new Set<string>(),
        dokploy: new Set<string>(),
        tags: new Set<string>(),
        upstream: new Set<string>(),
      };
      slot[template.source].add(template.name);
      for (const tag of entry.tags) slot.tags.add(tag);
      const repoName = template.github?.split('/')[1]?.toLowerCase();
      if (
        template.github !== undefined &&
        repoName !== undefined &&
        (images.size === 1 || namesMatch(ref, repoName))
      ) {
        slot.upstream.add(template.github);
      }
      seen.set(ref, slot);
    }
  }
  stats.distinctImages = seen.size;

  const known = new Set(catalog.map((image) => image.ref));
  const candidates: Candidate[] = [];
  for (const [ref, slot] of seen) {
    if (known.has(ref)) continue;
    candidates.push({
      ref,
      coolify: sorted(slot.coolify),
      dokploy: sorted(slot.dokploy),
      pinnedTags: sorted(slot.tags),
      upstream: sorted(slot.upstream),
    });
  }
  const total = (c: Candidate) => c.coolify.length + c.dokploy.length;
  candidates.sort(
    (a, b) =>
      total(b) - total(a) ||
      b.coolify.length - a.coolify.length ||
      (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0),
  );

  const mismatches: TagMismatch[] = [];
  const unused: Report['unused'] = [];
  for (const image of [...catalog].sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0))) {
    const slot = seen.get(image.ref);
    if (slot === undefined) {
      unused.push({ slug: image.slug, ref: image.ref });
      continue;
    }
    const pattern = new RegExp(image.tagPattern);
    const failing = sorted(slot.tags).filter(
      (tag) => pattern.exec(tag)?.groups?.['version'] === undefined,
    );
    if (failing.length > 0) {
      mismatches.push({
        slug: image.slug,
        ref: image.ref,
        tagPattern: image.tagPattern,
        tags: failing,
      });
    }
  }
  return { candidates, mismatches, unused, stats } satisfies Report;
}

/** Text that came from a template or the catalog, made safe for a markdown table cell. */
export function cell(text: string): string {
  return text.replace(/[^A-Za-z0-9._/:+(), -]/g, '').trim();
}

function code(text: string): string {
  return `\`${cell(text)}\``;
}

function listed(values: readonly string[], limit: number, wrap: (v: string) => string): string {
  if (values.length === 0) return '';
  const shown = values.slice(0, limit).map(wrap).join(', ');
  return values.length > limit ? `${shown} (+${String(values.length - limit)})` : shown;
}

const DOCS_URL = 'https://github.com/Shironex/advisorydeck/blob/main/docs/adding-a-product.md';

/** Renders the issue body. Same input, same text. */
export function renderReport(
  report: Report,
  sources: readonly SourceNote[],
  options: { top?: number } = {},
): string {
  const top = options.top ?? 60;
  const { stats } = report;
  const lines: string[] = [
    'This issue is generated weekly from the Coolify service templates and the Dokploy blueprints. It lists candidates only: nothing is added to the catalog automatically, and a person decides what is worth tracking (see [adding a product](' +
      DOCS_URL +
      ')).',
    '',
    '## New image candidates',
    '',
  ];
  if (report.candidates.length === 0) {
    lines.push('No unmatched images.', '');
  } else {
    lines.push(
      '| Image | Coolify | Dokploy | Templates | Pinned tags seen | Upstream |',
      '| --- | ---: | ---: | --- | --- | --- |',
    );
    for (const c of report.candidates.slice(0, top)) {
      const names = sorted(new Set([...c.coolify, ...c.dokploy]));
      lines.push(
        `| ${code(c.ref)} | ${String(c.coolify.length)} | ${String(c.dokploy.length)} | ${cell(listed(names, 3, cell))} | ${listed(c.pinnedTags, 3, code)} | ${listed(c.upstream, 2, code)} |`,
      );
    }
    lines.push('');
    if (report.candidates.length > top) {
      lines.push(
        `Showing the top ${String(top)} of ${String(report.candidates.length)} unmatched images; ${String(report.candidates.length - top)} more are not listed.`,
        '',
      );
    }
  }

  lines.push('## Catalog images whose tag pattern fails on a pinned template tag', '');
  if (report.mismatches.length === 0) {
    lines.push('None.', '');
  } else {
    lines.push('| Product | Image | Tags that do not match |', '| --- | --- | --- |');
    for (const m of report.mismatches) {
      lines.push(`| ${cell(m.slug)} | ${code(m.ref)} | ${listed(m.tags, 6, code)} |`);
    }
    lines.push('');
  }

  lines.push('## Catalog images no template uses', '');
  if (report.unused.length === 0) {
    lines.push('None.', '');
  } else {
    lines.push('| Product | Image |', '| --- | --- |');
    for (const u of report.unused) lines.push(`| ${cell(u.slug)} | ${code(u.ref)} |`);
    lines.push('');
  }

  const share =
    stats.occurrences === 0
      ? '0'
      : ((stats.floatingOccurrences / stats.occurrences) * 100).toFixed(1);
  lines.push('---', '');
  for (const source of sources) lines.push(`- ${cell(source.label)}: ${cell(source.detail)}`);
  lines.push(
    `- Templates read: ${String(stats.coolifyTemplates)} Coolify, ${String(stats.dokployTemplates)} Dokploy`,
    `- Distinct images: ${String(stats.distinctImages)} (${String(stats.occurrences)} uses, ${share}% on a floating or variable tag)`,
    `- Skipped: ${String(stats.variableSkipped)} images that are entirely a variable, ${String(stats.deniedSkipped)} helper images`,
    '',
  );
  return lines.join('\n');
}
