/** Marks the "On this page" link of the section being read. */
export function startRail(): void {
  const links = [...document.querySelectorAll<HTMLAnchorElement>('.rail a[href^="#"]')];
  const targets = links.flatMap((link) => {
    const el = document.getElementById(link.hash.slice(1));
    return el === null ? [] : [{ link, el: el.closest('section') ?? el }];
  });
  if (targets.length === 0 || !('IntersectionObserver' in window)) return;
  const visible = new Set<Element>();
  const mark = (): void => {
    const current = targets.find((t) => visible.has(t.el)) ?? null;
    if (current === null) return;
    for (const t of targets) {
      if (t === current) t.link.setAttribute('aria-current', 'true');
      else t.link.removeAttribute('aria-current');
    }
  };
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) visible.add(entry.target);
        else visible.delete(entry.target);
      }
      mark();
    },
    { rootMargin: '-80px 0px -55% 0px' },
  );
  for (const t of targets) observer.observe(t.el);
}
