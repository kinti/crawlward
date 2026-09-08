# AI crawler registry — annotated view

Source of truth: [`registry/crawlers.json`](../registry/crawlers.json)
(the analyzer reads the JSON, not this file).

**Verification status:** every entry below was checked against the vendor's
official documentation on **2026-09-07**. Vendors rename and add crawlers
often — treat any crawlward report as a snapshot and send PRs/issue with the
official doc URL when something changes.

## Crawlers (UA tokens you can see in access logs)

### OpenAI — <https://developers.openai.com/api/docs/bots>

| Token | Purpose | Notes |
|---|---|---|
| `GPTBot` | model training | honors robots.txt; publishes IP list |
| `OAI-SearchBot` | ChatGPT search index | honors robots.txt (~24h to react to changes) |
| `ChatGPT-User` | user-initiated fetch | robots.txt "may not apply" to user-initiated fetches |
| `OAI-AdsBot` | ChatGPT ads landing-page validation | newer token |

### Anthropic — <https://support.claude.com/en/articles/8896518>

| Token | Purpose | Notes |
|---|---|---|
| `ClaudeBot` | model training | full robots.txt support incl. crawl-delay; publishes IP list |
| `Claude-User` | user-initiated fetch | honors robots.txt |
| `Claude-SearchBot` | search index | honors robots.txt |

### Perplexity — <https://docs.perplexity.ai/guides/bots>

| Token | Purpose | Notes |
|---|---|---|
| `PerplexityBot` | search/answer index | honors robots.txt; publishes IP list |
| `Perplexity-User` | user-initiated fetch | docs: "generally ignores robots.txt rules" |

### Google — <https://developers.google.com/crawling/docs/crawlers-fetchers/>

Google's crawler docs moved out of the Search Central tree (the old
`google-crawlers` URL 404s). AI-relevant tokens:

| Token | Purpose | Notes |
|---|---|---|
| `GoogleOther` (+ `-Image`, `-Video`) | research/product crawling (unspecified) | honors robots.txt |
| `Google-CloudVertexBot` | owner-requested Vertex AI crawls | only crawls when requested |
| `Google-Agent` | agent navigation on Google infra | user-triggered: generally ignores robots.txt |
| `Google-GeminiNotebook` | Gemini Notebook sources | user-triggered; replaced `Google-NotebookLM` (until Aug 2026) |
| `Google-Read-Aloud` | text-to-speech | user-triggered |
| `Google-Safety` | abuse/safety crawling | documented as **ignoring robots.txt** |

### Apple — <https://support.apple.com/en-us/119829>

| Token | Purpose | Notes |
|---|---|---|
| `Applebot` | Siri/Spotlight; data may also train foundation models | honors robots.txt; no crawl-delay; reverse DNS `*.applebot.apple.com` |
| `Applebot-Extended` | opt-out for foundation-model training | blocking it does not affect Siri/Spotlight |

### Amazon — <https://developer.amazon.com/amazonbot>

| Token | Purpose | Notes |
|---|---|---|
| `Amazonbot` | Alexa/services; may train Amazon AI models | RFC 9309 compliant; no crawl-delay |
| `Amzn-SearchBot` | search (no generative-AI training) | honors robots.txt |
| `Amzn-User` | user-initiated (Alexa) | "may not follow all robots.txt directives" |

### Meta — <https://developers.facebook.com/documentation/sharing/webmasters/web-crawlers>

The wire UA strings are **lowercase** (`meta-externalagent/1.1`), even though
docs headings print them capitalized. crawlward matches case-insensitively.

| Token | Purpose | Notes |
|---|---|---|
| `meta-externalagent` | AI training / content indexing | honors robots.txt |
| `meta-externalfetcher` | user-initiated fetch (incl. agentic AI) | may bypass robots.txt |
| `meta-webindexer` | Meta AI search index | honors robots.txt |
| `meta-externalads` | advertising/business products | honors robots.txt |
| `FacebookBot` | legacy training crawler | no longer on Meta's current page; still seen in the wild |

### Others

| Token | Vendor | Purpose | Doc |
|---|---|---|---|
| `CCBot` | Common Crawl | open corpus (feeds many models) | [commoncrawl.org/ccbot](https://commoncrawl.org/ccbot) |
| `YouBot` | You.com | search index | [you.com/docs/youbot](https://you.com/docs/youbot) |
| `Diffbot`, `Diffbot-User` | Diffbot | knowledge graph (docs: not for AI training) | [diffbot.com robots FAQ](https://www.diffbot.com/docs/crawl/faq/robots-txt) |
| `MistralAI-User`, `MistralAI-Index`, `MistralAI-Training` | Mistral AI | user fetch / search index / training | [docs.mistral.ai/robots](https://docs.mistral.ai/robots) |
| `ImagesiftBot` | Hive | image intelligence | [imagesift.com/about](https://imagesift.com/about) |
| `DuckAssistBot` | DuckDuckGo | DuckAssist AI answers | [help pages](https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot) |
| `VelenPublicWebCrawler` | Velen | business datasets / ML | [velen.io](https://velen.io/) |
| `omgili` | Webz.io | web data service | [omgili.com/Crawler.html](https://omgili.com/Crawler.html) |

### Unverified — in the registry, clearly flagged

| Token | Vendor | Why unverified |
|---|---|---|
| `Bytespider` | ByteDance | No official ByteDance crawler documentation exists (as of 2026-09-07). Widely cited by third parties, common in logs, robots.txt compliance unconfirmed. |

## Control tokens (never appear in access logs)

| Token | What it actually is |
|---|---|
| `Google-Extended` | A robots.txt-only control token. Google states it "has no independent HTTP request user-agent string" — you will **never** see it in your logs. It governs whether Googlebot-crawled content may train Gemini/Vertex models. Listing it in a "who crawls me" report is a classic mistake. |

## Retired / gone

| Token | Status |
|---|---|
| `cohere-ai` | Cohere's crawler page (2026-09-07) states they do not currently crawl web content to train generative AI; the token is retired. |

## Identity verification files

These vendors publish official IP-prefix lists (Google-cloud-style
`{prefixes: [{ipv4Prefix|ipv6Prefix}]}` JSON). `crawlward --verify` fetches
them and checks whether requests claiming each identity come from that
vendor's infrastructure. The URLs live in the `ranges` field of
[`registry/crawlers.json`](../registry/crawlers.json).

| Bots covered | Prefix list |
|---|---|
| GPTBot | <https://openai.com/gptbot.json> |
| OAI-SearchBot | <https://openai.com/searchbot.json> |
| ChatGPT-User | <https://openai.com/chatgpt-user.json> |
| OAI-AdsBot | <https://openai.com/adsbot.json> |
| ClaudeBot, Claude-User, Claude-SearchBot | <https://claude.com/crawling/bots.json> (shared list) |
| PerplexityBot | <https://perplexity.com/perplexitybot.json> |
| Perplexity-User | <https://perplexity.com/perplexity-user.json> |
| CCBot | <https://index.commoncrawl.org/ccbot.json> |
| MistralAI-User | <https://mistral.ai/mistralai-user-ips.json> |
| MistralAI-Index | <https://mistral.ai/mistralai-index-ips.json> |

Vendors without a machine-readable list (Amazon publishes an HTML page,
Apple documents reverse-DNS `*.applebot.apple.com`) cannot be checked by
`--verify` yet; FCrDNS support is on the roadmap.

## Known analysis traps

1. **UA strings are claims, not identity.** Anything can claim to be
   `GPTBot`. Vendors that publish IP ranges or verification endpoints
   (OpenAI, Anthropic, Perplexity, Apple, Amazon, Common Crawl, You.com,
   Mistral) should be verified by reverse DNS before a report claims
   compliance — this is crawlward's top roadmap item.
2. **robots.txt respect ≠ permission respect.** User-triggered fetchers
   (ChatGPT-User, Perplexity-User, meta-externalfetcher, Google-Agent,
   Amzn-User…) explicitly bypass robots.txt by design. Log both claims and
   behavior separately.
3. **Absence of evidence:** zero hits from a vendor does not mean zero
   crawling (content may reach models via Common Crawl or client-side
   aggregators). Say so in the report.
