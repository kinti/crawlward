# crawlward

[![CI](https://github.com/kinti/crawlward/actions/workflows/ci.yml/badge.svg)](https://github.com/kinti/crawlward/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen)
![dependencies](https://img.shields.io/badge/dependencies-0-success)
[![GitHub release](https://img.shields.io/github/v/release/kinti/crawlward)](https://github.com/kinti/crawlward/releases)

**A watchdog for AI crawlers at your own origin — for everyone NOT on Cloudflare.**

Cloudflare launched pay-per-crawl and permission-by-default for AI crawlers.
That covers their customers. The rest of the web — self-hosted servers,
Caddy, nginx, cheap shared hosting — has no simple answer to:

- *Who* is actually hitting my site with AI crawlers?
- Do they *respect* my robots.txt — or just claim to?
- How much of my traffic and bandwidth do they eat?

crawlward answers those from data you already have: your access logs.

- **Classifies** requests from known AI crawlers (GPTBot, ClaudeBot,
  PerplexityBot, Bytespider, CCBot…) using a signature registry with
  sources in [`registry/crawlers.json`](registry/crawlers.json)
- **Aggregates** per bot / vendor / host / day: requests, bandwidth, top
  paths, HTTP status mix, robots.txt awareness
- **Flags** bot-like user agents that match no known signature — candidates
  for the registry, and often the most interesting finding
- **Zero dependencies.** One CLI, Node ≥ 18. Reads Caddy and nginx JSON
  access logs, plain or gzipped

## Quick start

```sh
git clone https://github.com/kinti/crawlward.git
cd crawlward
node src/analyze.mjs /var/log/caddy/*.log
```

Works the same with gzipped rotations:

```sh
node src/analyze.mjs /var/log/caddy/example.com.access.log*
```

Machine-readable output for pipelines and dashboards:

```sh
node src/analyze.mjs --json access.log > report.json
```

## Example output

```
# crawlward v0.1.0 — who really crawls
files: 2 · lines: 11 · parsed: 10 · unparsed: 1
AI-crawler requests: 8 (80.0% of parsed) · 161 KB served

## AI crawler requests, by bot
requests  share  served   days  hosts  bot · vendor — purpose
       3   37.5%   100 KB     2      1  GPTBot · OpenAI — training
       2   25.0%    10 KB     1      1  OAI-SearchBot · OpenAI — search index
       1   12.5%     0 KB     1      1  ClaudeBot · Anthropic — training

## What AI crawlers want most (top paths)
       2  /
       1  /robots.txt
       1  /posts/hello-world

## robots.txt awareness
GPTBot requested /robots.txt 1×
no /robots.txt request seen from: OAI-SearchBot, ClaudeBot (weak signal — crawlers may cache it)

## Bot-like user agents NOT in the registry
       1  Scrapy/2.11 (+https://scrapy.org)
```

## 1. Turn on JSON access logs

crawlward reads JSONL access logs. Ten minutes of setup:

- **Caddy**: [`caddy/README.md`](caddy/README.md) — `log { format json }` + rotation
- **nginx**: [`docs/nginx.md`](docs/nginx.md) — `log_format ... escape=json` + logrotate

The analyzer auto-detects both shapes (and common variants), tolerates
broken lines, and never needs the whole file in memory.

## The registry

[`registry/crawlers.json`](registry/crawlers.json) is the machine-readable
source of truth; [`docs/crawlers.md`](docs/crawlers.md) is the annotated
view with official documentation links and verification notes.

**Honest caveat:** a User-Agent string is free text. Anyone can claim to be
`GPTBot`. crawlward tells you *what claims to be* crawling you — not
cryptographic proof of identity. Verifying claimed identities via
reverse DNS (OpenAI, Anthropic and Perplexity publish IP ranges / verification
endpoints) is the top roadmap item.

## Reading the report — known traps

1. **UA strings are claims, not identity.** Treat registry hits as
   self-declared until reverse-DNS verification lands.
2. **robots.txt respect ≠ permission respect.** A bot can fetch `/robots.txt`
   once, cache it for weeks, and still be a good citizen — or ignore it
   silently. crawlward reports the signal; you judge the behavior.
3. **Absence of evidence isn't evidence of absence.** Zero hits from a vendor
   doesn't mean zero crawling: content can reach models via Common Crawl or
   client-side aggregators.

## Roadmap

- [ ] Reverse-DNS verification of claimed crawler identities
- [ ] robots.txt diffing: what *you* allow vs what *they* do
- [ ] HTML report output
- [ ] More log formats (Apache combined, Traefik, Caddy `console` format)

Registry additions and fixes are very welcome — please include the vendor's
official documentation URL in the PR.

## Status

v0.1.0 — young but tested (14 test cases, CI on Node 18/20/22). The
signature registry is verified against vendor documentation as of
September 2026; vendors rename and add bots often, so issues and PRs are
the maintenance model.

## License

[MIT](LICENSE)
