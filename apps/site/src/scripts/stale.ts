/** Shows the stale-feed notice when the last successful ingest is more than 24 hours old. */
const DAY_MS = 86_400_000;

export function startStaleNotice(now = Date.now()): void {
  for (const notice of document.querySelectorAll<HTMLElement>('[data-stale]')) {
    const generated = Date.parse(notice.dataset['stale'] ?? '');
    notice.hidden = !(Number.isFinite(generated) && now - generated > DAY_MS);
  }
}
