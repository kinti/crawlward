# nginx access logs for crawlward

nginx does not write JSON logs by default. Define a JSON log format and use
it per server block. The field names below (`time_local`, `request`, `status`,
`body_bytes_sent`, `http_user_agent`, `server_name`) are what crawlward
auto-detects; other common shapes (`time` as ISO8601, `msec`, `user_agent`,
`bytes_sent`) also work.

```nginx
http {
    log_format crawlward escape=json
        '{'
            '"time_local":"$time_local",'
            '"remote_addr":"$remote_addr",'
            '"request":"$request",'
            '"status":"$status",'
            '"body_bytes_sent":"$body_bytes_sent",'
            '"http_user_agent":"$http_user_agent",'
            '"server_name":"$server_name"'
        '}';

    access_log /var/log/nginx/example.net.access.log crawlward;
}
```

Notes:

- `escape=json` is essential — it escapes quotes so every line is valid JSON.
- `$time_local` looks like `07/Sep/2026:10:00:00 +0000`; the analyzer parses it.
- Rotation: use your distribution's logrotate (daily is fine). crawlward also
  reads `.gz` files directly, so `*.log.gz` archives can be analyzed in place:

  ```sh
  crawlward /var/log/nginx/example.net.access.log*
  ```

## Deploy checklist

1. Add the `log_format` block to `http {}`, reference it in your `server {}`.
2. `nginx -t && systemctl reload nginx`.
3. Verify: `head -1 /var/log/nginx/example.net.access.log | python3 -m json.tool`.
