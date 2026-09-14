# Contributing to crawlward

Thanks for helping build a watchdog for AI crawlers! There are two kinds of
contributions that matter most here: **registry corrections** and **code**.

## Development setup

```sh
git clone https://github.com/kinti/crawlward.git
cd crawlward
npm test          # full suite (node:test) — zero dependencies to install
```

Requirements: Node ≥ 18. No `npm install` — the project has zero runtime
dependencies by design. Please keep it that way.

## Adding or fixing registry entries

The machine-readable registry [`registry/crawlers.json`](../registry/crawlers.json)
is the source of truth; [`docs/crawlers.md`](../docs/crawlers.md) must stay
in sync (update both, or note it in the PR).

Rules for registry PRs:

1. **Official documentation URL is mandatory** (`doc` field). Vendor blogs or
   third-party crawler directories are not sufficient — we link the vendor's
   own crawler/bots page.
2. **Exact token casing.** Use the token exactly as it appears on the wire
   (e.g. Meta's real UA strings are lowercase: `meta-externalagent/1.1`).
   Matching is case-insensitive, but the registry records the wire form.
3. **`verified: false` for anything without an official vendor page** (see
   `Bytespider`). We would rather list a crawler as unverified than guess.
4. **Don't add tokens that never appear in access logs.** Control-only
   tokens like `Google-Extended` (no HTTP user-agent of its own) belong in
   `controlTokens`, not `crawlers`.
5. Include a line from your own access logs (UA string only, redact IPs) if
   you're adding a bot you actually observed.
6. If the vendor publishes an official IP-prefix list (Google-cloud-style
   `{prefixes:[{ipv4Prefix|ipv6Prefix}]}` JSON), add its URL as `ranges` —
   it powers `crawlward --verify`. See the list in
   [`docs/crawlers.md`](../docs/crawlers.md).

## Reporting findings

Found a bot ignoring robots.txt? A surprising crawler ratio? Open an issue
with the **Crawler observation** template — real-world findings are the whole
point of the project. Redact any data that isn't yours to share.

## Pull requests

- One logical change per PR; rebase on `main` if needed.
- Run `npm test` before pushing. CI runs the suite on Node 18/20/22.
- New analyzer behavior needs a test. Bug fixes need a test that fails
  without the fix.
- Keep the zero-dependency, single-binary philosophy: no `npm install`,
  no build step.

## Releases

Maintainer-only: bump `version` in `package.json`, add the entry to
`CHANGELOG.md`, tag `vX.Y.Z`, push the tag, and publish a GitHub Release
with notes. The project follows [Semantic Versioning](https://semver.org/).
