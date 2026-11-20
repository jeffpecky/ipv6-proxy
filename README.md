# Prefixa — IPv6 rotation gateway

HTTP CONNECT + SOCKS5 on one port, outbound traffic rotated across a pool of /128 addresses from your IPv6 prefix.

## Install
```
curl -fsSL https://raw.githubusercontent.com/jeffpecky/ipv6-proxy/main/install.sh | sudo bash
```

## Upstream 429 relay signal

A TLS proxy cannot see an upstream `429` inside a CONNECT tunnel. Clients that
can (e.g. zen-proxy) report it out of band instead:

```
POST http://<host>:1080/__signal
Authorization: Bearer <signal_token>
Content-Type: application/json

{"clientId":"fltg","status":429,"model":"...","retryAfter":1}
```

A valid report returns `204 No Content` with `X-Rotated: <prefix>`. The proxy
username is pinned to one exit until a report condemns it; then the whole bucket
is retired, cooled for `signal_cooldown_minutes` (default 15), and a never-used
`/128` is minted in a non-cooling prefix and pinned to the client before the
response returns. That guarantees the retry's new CONNECT cannot reuse an
address whose quota is already spent. With a routed HE `/48`, the installer
carves `/64` buckets from it (8 by default, `POOL_48_PREFIX_COUNT`) so rotation
stays inside the `/48`. Repeat reports for a bucket already cooling still mint
a fresh exit. Multiple clients need distinct proxy usernames.

`signal_token` defaults to `PROXY_PASS` in the installer and can be set through
`SIGNAL_TOKEN` in `install.env`. The signal count is exposed at `/api/stats`.

## Layout
```
main.go                 proxy + web API
web/index.html          control panel (embedded in the binary)
web/assets/             brand kit: mark.svg, logo.svg, favicon.svg/.ico, apple-touch + PWA icons
install.sh              installer (uses `go install`)
```

## Rebranding
Name and colors live in `web/index.html` (`<title>`, `.brand`, `--grad`) and `web/assets/*.svg`.
Gradient: `#22d3ee → #6366f1 → #a855f7`. The mark is a hexagon (the "6") holding "::" (IPv6 shorthand).
