# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on
<https://github.com/kinti/crawlward/security>, or contact the maintainer
directly if you prefer email.

You'll get an acknowledgment within 72 hours. We'll keep you informed of the
fix timeline and credit you in the release notes unless you prefer otherwise.

## Scope notes

crawlward is a local log-analysis CLI. The realistic risk areas are:

- **Log parsing** (malformed/hostile JSONL input) — the analyzer must never
  crash or misbehave on bad lines; tests cover this.
- **Sensitive data in reports** — reports contain hostnames, paths, and
  user agents from your logs. Anything you publish from a crawlward report
  is your responsibility; the tool will never send data anywhere.
