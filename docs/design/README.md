# Site design

The website in `apps/site` follows an approved design: [brief.md](brief.md) says what it is for
and how it looks, [product.md](product.md) holds the product context it was written against.

- Tokens and component styles: `apps/site/src/styles/tokens.css` (colors for dark and light,
  type scale, spacing, radii and every shared component). Change a color or size there, not in a
  page.
- Site-only additions (search dialog, filter states, the products, category and sources pages):
  `apps/site/src/styles/site.css`. It uses the tokens only.
- Theme: dark by default, following the system setting; the toggle stores the choice in
  `localStorage` under `ad-theme`.
- Severity is always a text label plus a shape (`.sev[data-sev]`); color only supports it.
- Fonts: Geist and Geist Mono from `@fontsource/geist` and `@fontsource/geist-mono`, bundled
  and served with the site (latin subset), under the SIL Open Font License 1.1. The brief named
  Google Fonts; the site self-hosts them instead so no page makes a third-party request.
- Accessibility bar: text contrast at least 4.5:1, controls and shapes at least 3:1, no
  horizontal scroll at 320 px, every control keyboard reachable.
