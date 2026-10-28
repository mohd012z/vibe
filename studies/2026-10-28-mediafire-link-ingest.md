# MediaFire link ingest (v0.33) — mechanism + evidence (2026-10-28)

Anam's request: "vibe_ai can use and download file from link mediafire etc".
This note pins the verified mechanism so the resolver in
`gateway._url_mediafire_direct()` is never hand-waved later.

## FACT — how a MediaFire share link resolves to bytes (verified live)

Share URL shape: `https://www.mediafire.com/file/<qkey>/<Name>.apk/file`.

1. GET the share page (330 KB HTML, `text/html`). A browser-ish
   `User-Agent` is required (the bot's VibeBot UA works; the page also
   serves for plain curl).
2. The page embeds the real file link on the Download anchor:
   `<a class="input popsok" aria-label="Download file"
   href="https://download<NNNN>.mediafire.com/<encrypted-token>/<qkey>/<Name>.apk">`.
   The token is a per-page encrypted blob (base64-ish, ~170 chars) — NOT
   derivable from the key, so the page fetch is mandatory.
3. GET the CDN link directly: **no cookies, no session, no JS** — returns
   the real bytes. Verified on Pulse Player 4.0.0:
   `Content-Type: application/vnd.android.package-archive`, HTTP 200 (and
   206 for Range requests), 79,899,701 bytes.
   Evidence: `curl -r 0-2047` → 206 + correct Content-Type; full
   `/get` e2e through the gateway → sha256 `be5339eda9090d39da4e9e63aaaf7b28…`.

## Dead ends (do not retry)

- `https://www.mediafire.com/d/?key=<qkey>` → 404 (route retired).
- `https://www.mediafire.com/download/<qkey>` → 200 but a **waiting
  interstitial** HTML page (JS countdown → `download_repair.php?qkey=…&dkey=…`),
  no direct link in the HTML.
- `download_repair.php?qkey=…&dkey=…` → 200 HTML (35 KB), `window.location`
  only redirects back to the share page. The encrypted CDN token is only
  in the SHARE page.

## Design notes (why the code is shaped as it is)

- Resolver pattern mirrors v0.31 tmpfiles interstitials: fetch page →
  extract link → SSRF re-check on the extracted host (the CDN host is
  `download<NNNN>.mediafire.com` — public, but attacker-controlled pages
  must not point us at a private IP).
- **Filename fix**: the share URL ends in `/file`, so `_url_basename(url)`
  would be "file". `download_url()` now resolves FIRST and prefers the
  resolved link's filename when the original carried no extension.
- `download*.mediafire.com` URLs pass through without a page fetch
  (already direct).
- No-link page (deleted file, album/folder page) → honest RuntimeError,
  surfaced as `error: download failed (mediafire: …)`.

## Surface added (v0.33)

- `/get <url>` — sync download + evidence card (name/kind/size/sha256/path +
  next commands).
- `/apk <mediafire-share-url>`, `/analyze <url>`, etc. — all URL-accepting
  commands now work with MediaFire links (shared `download_url()` path).
- Bare pasted link in Telegram → auto-routed to `/apk <url>`
  (`telegram_runtime` poll loop).
- Home UI: new first section "🔗 Links" — `📥 Get Link` (callback → flow
  prompt) + `🔗 Upload Page` (native URL button → the gh-pages upload page
  for files too big even for link hosts).
- Registry L0 + deploy menu + HELP updated; `__version__` 0.33.0.

## "etc" (other hosts) — status

- Direct file URLs: work (plain GET path).
- tmpfiles.org: works (v0.31 interstitial resolver).
- MediaFire: works (this note).
- Generic HTML hosts: the honest contract is "give the DIRECT file URL";
  a future generic interstitial sniff can be added per-host as hosts are
  actually requested (evidence-first: no resolver for a host nobody uses).
