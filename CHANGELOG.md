# Changelog

All notable changes to crawlward are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-09-14

### Fixed

- **v4-mapped IPv6 addresses** (`::ffff:a.b.c.d`, how nginx dual-stack logs
  IPv4 clients) returned `null` from the IP parser, so legitimate vendor
  traffic failed `--verify` and was reported as spoofed. They now
  canonicalize onto the IPv4 table. NAT64 (`64:ff9b::…`), zone indexes
  (`fe80::1%eth0`) and full-form dotted quads also parse.
- **Zero-source-IP verification** rendered a misleading `0/0 — MIXED`
  verdict; it now says explicitly that the logs carry no client IPs.
- **`Applebot-Extended`** moved from `crawlers` to `controlTokens` — Apple's
  documentation states it "does not crawl webpages", making it a
  robots.txt-only token like `Google-Extended`.

### Changed

- Undated events are excluded while `--since`/`--until` is active;
  `--help` documents that date-only values mean UTC midnight.
- Peak-hour buckets get their own cap, so `peak/h` no longer understates on
  logs longer than ~7 months.
- Unmatched bot-like user agents are version-normalized (`Scrapy/2.11` and
  `Scrapy/2.12` merge into one bucket) with a bounded map.
- gzip is detected by magic bytes, so compressed rotations work under any
  filename.
- Registry v4; new *Scope* section in docs/crawlers.md documents the
  deliberate `Googlebot`/`Bingbot` exclusions.

## [0.2.0] — 2026-09-08

### Added

- **`--verify`**: checks claimed bot identities against vendors' published
  IP prefix lists (OpenAI, Anthropic, Perplexity, Common Crawl, Mistral;
  IPv4 + IPv6 CIDR matching) and flags spoofed identities.
- Apache combined log support with per-line auto-detection; client IPs from
  combined logs feed verification.
- Peak requests/hour per bot; `--since`/`--until` date filters; `--csv`
  output.
- Registry v3: `ranges` verification URLs as data; client IP tracked per
  bot.

## [0.1.0] — 2026-09-07

### Added

- Initial public release: streaming JSONL analyzer for Caddy/nginx logs,
  per-bot/vendor aggregation, bandwidth, top paths, HTTP status mix,
  robots.txt awareness, unmatched bot-like UA bucket, `--json` output.
- Signature registry (39 entries at launch) verified against official
  vendor documentation; `Bytespider` flagged unverified; `Google-Extended`
  documented as a control token that never appears in logs.
- 14 tests (`node:test`), CI on Node 18/20/22, MIT license.
