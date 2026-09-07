# Caddy access logs for crawlward

Goal: structured JSON access logs per site, rotated, feedable to
`src/analyze.mjs`. Paths below assume a standard Caddy install; adjust to
your setup.

```caddyfile
example.com {
	log {
		output file /var/log/caddy/example.com.access.log {
			roll_size 10MiB
			roll_keep 10
			roll_keep_for 720h
		}
		format json
	}
	...
}
```

Notes:

- `format json` writes one JSON object per line (JSONL) — that is what the
  analyzer expects.
- Caddy's default log fields already include everything crawlward needs:
  `req.headers.User-Agent`, `req.host`, `req.uri`, `ts`, `status`, `size`.
  No extra `log_append` required.
- Rotation matters: AI crawlers can be chatty. 10 MiB × 10 files per site is
  roughly 3–4 weeks of history at moderate traffic.

## Deploy checklist (per site)

1. Add the `log` block, then `caddy reload`.
2. Confirm the file appears and lines parse as JSON:
   `head -1 /var/log/caddy/example.com.access.log | python3 -m json.tool`.
3. Run the analyzer over the file: `crawlward /var/log/caddy/*.log`.

## Permissions tip

The log directory must be writable by the Caddy user. On systemd installs:

```sh
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy
```
