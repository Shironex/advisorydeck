/**
 * The product page version check. Loads this site's product JSON (api/v1/products/<slug>.json)
 * on first use and answers with the matcher's rules; nothing is sent anywhere else. The value
 * can be shared as #check=<version>.
 */
import { encodeState, defaultState } from '../lib/generator.ts';
import { checkInstalled, type CheckFeed, type Level, type Verdict } from '../lib/verdict.ts';

const LEVELS: readonly Level[] = ['critical', 'high', 'medium', 'low', 'unknown'];

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  node.append(...children);
  return node;
}

const code = (text: string): HTMLElement => el('code', {}, text);
const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

function shortDate(day: string): string {
  return new Date(`${day.slice(0, 10)}T00:00:00Z`).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

function sevCounts(counts: Record<Level, number>): HTMLElement {
  const wrap = el('span', { class: 'sev-counts' });
  for (const level of LEVELS) {
    if (counts[level] > 0) {
      wrap.append(el('span', { class: 'sev', 'data-sev': level }, `${counts[level]} ${level}`));
    }
  }
  return wrap;
}

function verdictLine(
  kind: 'affected' | 'clear' | 'unknown',
  mark: string,
  ...body: (Node | string)[]
): HTMLElement {
  return el(
    'p',
    { class: `verdict verdict--${kind}` },
    el('span', { class: 'verdict-mark', 'aria-hidden': 'true' }, mark),
    el('span', {}, ...body),
  );
}

function generatorLink(base: string, slug: string, input: string, isBranch: boolean): string {
  const state = defaultState('UTC');
  state.products = [{ slug, kind: isBranch ? 'floating' : 'exact', version: input }];
  const params = new URLSearchParams(encodeState(state));
  // Only the product: the generator fills the rest with its defaults and the visitor's zone.
  return `${base}#p=${encodeURIComponent(params.get('p') ?? '')}`;
}

function render(verdict: Verdict, feed: CheckFeed, section: HTMLElement): HTMLElement[] {
  const slug = feed.product.slug;
  const name = feed.product.name;
  const generator = section.dataset['generator'] ?? 'generator/';
  const image = section.dataset['image'] ?? '';
  if (verdict.kind === 'invalid') {
    return [
      verdictLine(
        'unknown',
        '?',
        verdict.input === '' ? 'Enter a version first' : code(verdict.input),
        verdict.input === '' ? '' : ` is not a ${name} version`,
      ),
      el(
        'div',
        { class: 'verdict-body' },
        el(
          'p',
          {},
          'Write it as the vendor does, without the image variant: for example the hint below the field.',
        ),
      ),
    ];
  }
  const subject = verdict.isBranch ? `Branch ${verdict.input}` : verdict.input;
  // A release on a supported branch gets alerts for its branch: the upgrade it is told to make
  // stays on that branch, and pinning the old release would keep alerting after it.
  const known = verdict.kind === 'affected' ? verdict.branch : null;
  const branch = known !== null && !known.eol ? known.name : null;
  const alertsFor = branch ?? verdict.input;
  const floating = branch !== null || verdict.isBranch;
  const alerts = el(
    'a',
    { class: 'link-arrow', href: generatorLink(generator, slug, alertsFor, floating) },
    `Get alerts for ${floating ? `branch ${alertsFor}` : alertsFor}`,
  );
  if (verdict.kind === 'clear') {
    return [
      verdictLine(
        'clear',
        '✓',
        verdict.isBranch ? `No release of branch ${verdict.input}` : code(verdict.input),
        ` is not affected by any of the ${plural(verdict.total, 'advisory', 'advisories')} in the feed`,
      ),
      el(
        'div',
        { class: 'verdict-body' },
        el(
          'p',
          { class: 'fix-line' },
          'Keep it that way: the notifier posts the next one that matches.',
        ),
        el('p', { class: 'verdict-actions' }, alerts),
      ),
    ];
  }
  if (verdict.kind === 'unknown') {
    return [
      verdictLine(
        'unknown',
        '?',
        verdict.isBranch ? `Branch ${verdict.input}` : code(verdict.input),
        `: ${plural(verdict.unknown.length, 'advisory does', 'advisories do')} not say which versions are affected`,
      ),
      el(
        'div',
        { class: 'verdict-body' },
        el(
          'p',
          { class: 'fix-line' },
          'None of the others affects it. Check these against the vendor advisory: ',
          ...verdict.unknown.flatMap((id, i) => [
            i > 0 ? ', ' : '',
            el('a', { href: `../../advisories/${id}/` }, id),
          ]),
        ),
        el('p', { class: 'verdict-actions' }, alerts),
      ),
    ];
  }
  const n = verdict.affected.length;
  const fix = el('p', { class: 'fix-line' });
  const advice = verdict.advice;
  const pull =
    verdict.isBranch && image !== ''
      ? ` Pull ${image}:${verdict.input} again and recreate the container, or upgrade to `
      : 'Upgrade to ';
  if (advice.kind === 'latest') {
    fix.append(
      pull.trimStart(),
      code(advice.version),
      `, the latest release on branch ${advice.branch.name}. It fixes ${n === 1 ? 'it' : `all ${n}`}.`,
    );
  } else if (advice.kind === 'latest-partial') {
    fix.append(
      'The latest release on branch ',
      `${advice.branch.name}, `,
      code(advice.version),
      `, fixes ${n - advice.left} of them. ${plural(advice.left, 'advisory has', 'advisories have')} no fix on this branch: move to a newer branch.`,
    );
  } else if (advice.kind === 'upgrade') {
    fix.append(
      'Upgrade to ',
      code(advice.version),
      advice.left === 0
        ? ` or later. It fixes ${n === 1 ? 'it' : `all ${n}`}.`
        : ` or later. ${plural(advice.left, 'advisory still names', 'advisories still name')} no fix there.`,
    );
  } else {
    fix.append('No advisory names a fixed release yet. Read each one for workarounds.');
  }
  const body = el('div', { class: 'verdict-body' }, el('p', {}, sevCounts(verdict.counts)), fix);
  if (verdict.branch?.eol) {
    body.append(
      el(
        'p',
        { class: 'fix-line' },
        `Branch ${verdict.branch.name} is end of life${verdict.branch.eolDate ? ` since ${shortDate(verdict.branch.eolDate)}` : ''} and gets no more fixes. Plan a move to a supported branch.`,
      ),
    );
  }
  if (verdict.unknown.length > 0) {
    body.append(
      el(
        'p',
        { class: 'hint' },
        `${plural(verdict.unknown.length, 'more advisory does', 'more advisories do')} not say which versions are affected: check ${verdict.unknown.length === 1 ? 'it' : 'them'} by hand.`,
      ),
    );
  }
  body.append(
    el(
      'p',
      { class: 'verdict-actions' },
      el(
        'a',
        { class: 'link-arrow', href: '#list' },
        `See the ${plural(n, 'advisory', 'advisories')}`,
      ),
      alerts,
    ),
  );
  return [
    verdictLine(
      'affected',
      '!',
      verdict.isBranch ? subject : code(verdict.input),
      ` is affected by ${plural(n, 'advisory', 'advisories')}`,
    ),
    body,
  ];
}

function markBranch(branch: string | null): void {
  for (const row of document.querySelectorAll<HTMLElement>('[data-branch-row]')) {
    const yours = branch !== null && row.dataset['branchRow'] === branch;
    row.classList.toggle('is-yours', yours);
    row.querySelector('[data-yours]')?.toggleAttribute('hidden', !yours);
    if (yours) row.hidden = false;
  }
}

export function startVersionCheck(): void {
  const section = document.querySelector<HTMLElement>('[data-check]');
  const form = section?.querySelector('form');
  const input = section?.querySelector<HTMLInputElement>('input[name="version"]');
  const result = section?.querySelector<HTMLElement>('[data-check-result]');
  if (!section || !form || !input || !result) return;
  let feed: Promise<CheckFeed> | null = null;
  const load = (): Promise<CheckFeed> =>
    (feed ??= fetch(section.dataset['feedUrl'] ?? '').then((r) =>
      r.ok ? (r.json() as Promise<CheckFeed>) : Promise.reject(new Error(r.statusText)),
    ));

  async function run(): Promise<void> {
    if (!input || !result || !section) return;
    result.hidden = false;
    try {
      const data = await load();
      const verdict = checkInstalled(data, input.value);
      input.setAttribute('aria-invalid', verdict.kind === 'invalid' ? 'true' : 'false');
      result.replaceChildren(...render(verdict, data, section));
      markBranch(verdict.kind === 'affected' ? (verdict.branch?.name ?? null) : null);
      if (verdict.kind !== 'invalid' && verdict.input !== '') {
        history.replaceState(null, '', `#check=${encodeURIComponent(verdict.input)}`);
      }
    } catch {
      result.replaceChildren(
        verdictLine(
          'unknown',
          '?',
          'The product data could not be loaded. Reload the page to try again.',
        ),
      );
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void run();
  });
  const shared = new URLSearchParams(location.hash.slice(1)).get('check');
  if (shared !== null && shared !== '') {
    input.value = shared.slice(0, 64);
    void run();
  }
}
