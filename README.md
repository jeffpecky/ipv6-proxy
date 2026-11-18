# Prefixa — IPv6 rotation gateway

HTTP CONNECT + SOCKS5 on one port, outbound traffic rotated across a pool of /128 addresses from your IPv6 prefix.

## Install
```
curl -fsSL https://raw.githubusercontent.com/jeffpecky/ipv6-proxy/main/install.sh | sudo bash
```

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
