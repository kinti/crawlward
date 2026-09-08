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

- **Classifies** requests from 39 known AI crawlers (GPTBot, ClaudeBot,
  PerplexityBot, Bytespider, CCBot…) using a signature registry with
  sources in [`registry/crawlers.json`](registry/crawlers.json)
- **Verifies identities** (`--verify`): checks that requests claiming to be
  GPTBot etc. actually come from the vendor's published IP ranges — spoofed
  bot identities get caught
- **Aggregates** per bot / vendor / host / day: requests, bandwidth, top
  paths, HTTP status mix, peak requests/hour, robots.txt awareness
- **Flags** bot-like user agents that match no known signature — candidates
  for the registry, and often the most interesting finding
- **Zero dependencies.** One CLI, Node ≥ 18. Reads Caddy and nginx JSON
  access logs and Apache combined logs, plain or gzipped

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
node src/analyze.mjs --csv access.log > bots.csv
```

Narrow the window, and verify that claimed identities are real:

```sh
node src/analyze.mjs --since 2026-09-01 --verify /var/log/caddy/*.log
```

## Example output

```
# crawlward v0.2.0 — who really crawls
files: 3 · lines: 14 · parsed: 13 · unparsed: 1
AI-crawler requests: 10 (76.9% of parsed) · 187 KB served

## AI crawler requests, by bot
requests  share  served   days  peak/h  bot · vendor — purpose
       3   30.0%   100 KB     2       2  GPTBot · OpenAI — model training
       2   20.0%    10 KB     1       2  OAI-SearchBot · OpenAI — ChatGPT search index

## HTTP status of AI crawler requests
200: 9 · 404: 1

## Bot-like user agents NOT in the registry
       1  Scrapy/2.11 (+https://scrapy.org)

## Identity verification (--verify: claimed identity vs vendor IP ranges)
GPTBot                 1/1 source IP(s) OUTSIDE vendor ranges (21 prefixes) — treat claimed identity as spoofed
                       outside IP sample: 203.0.113.20
CCBot                  all 1 source IP(s) inside vendor ranges (5 prefixes) — identity consistent
Bytespider             vendor publishes no IP ranges — cannot verify
```

## 1. Turn on JSON access logs

crawlward reads JSONL access logs and Apache combined logs. Ten minutes of
setup:

- **Caddy**: [`caddy/README.md`](caddy/README.md) — `log { format json }` + rotation
- **nginx**: [`docs/nginx.md`](docs/nginx.md) — `log_format ... escape=json` + logrotate
- **Apache**: combined format works as-is, no config needed (client IP feeds
  `--verify`; for Caddy/nginx JSON it comes from `remote_ip`/`$remote_addr`)

The analyzer auto-detects the format per line, tolerates broken lines, and
never needs the whole file in memory.

## The registry

[`registry/crawlers.json`](registry/crawlers.json) is the machine-readable
source of truth; [`docs/crawlers.md`](docs/crawlers.md) is the annotated
view with official documentation links and verification notes.

**Honest caveat:** a User-Agent string is free text. Anyone can claim to be
`GPTBot`. That's why `--verify` exists: it checks the source IPs of
claimed-bot requests against the vendor's own published IP prefix lists
(OpenAI, Anthropic, Perplexity, Common Crawl and Mistral publish them). A
100% match means the identity is consistent with vendor infrastructure; a
0% match means you're almost certainly looking at a spoofed identity.

## Reading the report — known traps

1. **UA strings are claims; `--verify` checks them.** IP-prefix matching
   confirms the requests come from vendor infrastructure. It can still miss
   brand-new ranges (vendors add IPs constantly) — a MIXED result usually
   means new ranges, not fraud. Reverse-DNS (FCrDNS) is a useful complement
   for vendors that don't publish lists.
2. **robots.txt respect ≠ permission respect.** A bot can fetch `/robots.txt`
   once, cache it for weeks, and still be a good citizen — or ignore it
   silently. User-triggered fetchers (ChatGPT-User, Perplexity-User,
   meta-externalfetcher, Google-Agent…) bypass robots.txt by design.
   crawlward reports the signal; you judge the behavior.
3. **Absence of evidence isn't evidence of absence.** Zero hits from a vendor
   doesn't mean zero crawling: content can reach models via Common Crawl or
   client-side aggregators.
4. **`Google-Extended` will never appear in your logs.** It's a robots.txt
   control token with no HTTP user-agent of its own. Any report claiming
   "Google-Extended requests" is wrong.

## Roadmap

- [x] Identity verification against vendor-published IP ranges (`--verify`)
- [ ] robots.txt diffing: what *you* allow vs what *they* do
- [ ] HTML report output
- [ ] More log formats (Traefik, Caddy `console` format)
- [ ] FCrDNS verification as complement for vendors without prefix lists

Registry additions and fixes are very welcome — please include the vendor's
official documentation URL in the PR.

## Status

v0.2.0 — young but tested (27 test cases, CI on Node 18/20/22). The
signature registry is verified against vendor documentation as of
September 2026; vendors rename and add bots often, so issues and PRs are
the maintenance model.

## License

[MIT](LICENSE)
