#!/bin/bash
# Prefixa IPv6 Gateway v7.6 installer
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/jeffpecky/ipv6-proxy/main/install.sh | sudo bash
#
# The proxy itself is built with `go install` from the repo (index.html is embedded in the binary).

REPO="${REPO:-github.com/jeffpecky/ipv6-proxy}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="/opt/ipv6-proxy"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
export PATH=/usr/local/go/bin:$PATH
PURGE_INSTALL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_success(){ echo -e "${GREEN}[OK] $1${NC}"; }
print_error(){ echo -e "${RED}[ERROR] $1${NC}"; }
print_warning(){ echo -e "${YELLOW}[WARNING] $1${NC}"; }
print_info(){ echo -e "${BLUE}[INFO] $1${NC}"; }

web_port_open(){
  local port="$1"
  [ -n "$port" ] || return 1
  timeout 3 bash -c ":</dev/tcp/127.0.0.1/$port" >/dev/null 2>&1
}

wait_web_port(){
  local port="$1" max_wait="${2:-180}" waited=0
  while [ $waited -lt $max_wait ]; do
    if web_port_open "$port"; then return 0; fi
    if [ $((waited % 10)) -eq 0 ]; then
      print_info "Waiting for web panel port ${port} to be ready... (${waited}/${max_wait} sec)"
    fi
    sleep 2
    waited=$((waited+2))
  done
  return 1
}

handle_apt_locks(){
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ $waited -ge 60 ]; then
      print_warning "Timed out waiting for package manager lock, attempting cleanup"
      killall apt apt-get dpkg unattended-upgr 2>/dev/null || true
      rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* /var/lib/dpkg/lock-frontend
      dpkg --configure -a 2>/dev/null || true
      return
    fi
    sleep 2; waited=$((waited+2))
  done
}

main(){
  if [ "$(id -u)" -ne 0 ]; then print_error "Root privileges required, please use sudo"; exit 1; fi

  echo "============================================="
  echo "=== Prefixa IPv6 Gateway v7.6 ==="
  echo "============================================="

  if [ -x "$INSTALL_DIR/ipv6-proxy" ] && [ -f /etc/systemd/system/ipv6-proxy.service ]; then
    print_info "IPv6 proxy is already installed, checking web panel"
    systemctl daemon-reload
    systemctl enable ipv6-proxy >/dev/null 2>&1 || true
    PROXY_PORT=$(grep -oP '"port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo 1080)
    WEB_PORT=$(grep -oP '"web_port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo 8080)
    if systemctl is-active --quiet ipv6-proxy; then
      print_info "Service is running"
    else
      print_info "Service is not running, starting it"
      systemctl start ipv6-proxy >/dev/null 2>&1 || true
    fi
    if ! wait_web_port "$WEB_PORT" 60; then
      print_warning "Web panel port ${WEB_PORT} is not responding, trying to restart the service"
      systemctl restart ipv6-proxy >/dev/null 2>&1 || true
      wait_web_port "$WEB_PORT" 120 || true
    fi
    IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-IP")
    if web_port_open "$WEB_PORT"; then print_success "Web panel is healthy"; else print_warning "Web panel is still unreachable"; fi
    echo "Current web panel: http://${IP}:${WEB_PORT}"
    echo "Current HTTP proxy: http://proxy:proxy@${IP}:${PROXY_PORT}"
    echo "Current SOCKS5 proxy: socks5://proxy:proxy@${IP}:${PROXY_PORT}"
    if [ -t 0 ]; then
      echo ""
      echo "Choose an action:"
      echo "  1) Skip installation, keep the existing service"
      echo "  2) Update/reinstall, keep the existing config file"
      echo "  3) Uninstall then install, delete old program and config and reconfigure"
      echo "  4) Exit"
      read -r -p "Enter choice (default 1): " INSTALL_CHOICE
      INSTALL_CHOICE=${INSTALL_CHOICE:-1}
    else
      INSTALL_CHOICE=1
    fi
    case "$INSTALL_CHOICE" in
      1) print_success "Installation skipped"; exit 0 ;;
      2) print_warning "Update/reinstall selected, $INSTALL_DIR/config.json will be kept" ;;
      3) print_warning "Uninstall then install selected, $INSTALL_DIR and old config will be deleted"; PURGE_INSTALL=1 ;;
      4) print_info "Exited"; exit 0 ;;
      *) print_warning "Invalid choice, skipping installation by default"; exit 0 ;;
    esac
  fi

  print_info "Cleaning up old service"
  systemctl stop ipv6-proxy.service >/dev/null 2>&1 || true
  systemctl disable ipv6-proxy.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/ipv6-proxy.service
  if [ "$PURGE_INSTALL" = "1" ]; then rm -rf "$INSTALL_DIR"; fi
  systemctl daemon-reload

  print_info "Installing dependencies and Go"
  if command -v wget >/dev/null 2>&1 && command -v git >/dev/null 2>&1 && command -v update-ca-certificates >/dev/null 2>&1; then
    print_info "System dependencies already present, skipping apt install"
  else
    handle_apt_locks
    apt-get update >/dev/null 2>&1 || apt-get update --fix-missing >/dev/null 2>&1 || true
    apt-get install -y wget git ca-certificates >/dev/null 2>&1 || { print_error "Failed to install dependencies"; exit 1; }
  fi
  if [ ! -x /usr/local/go/bin/go ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
    rm -rf /usr/local/go
    wget -q "$GO_URL" -O "/tmp/$GO_TAR" || { print_error "Failed to download Go"; exit 1; }
    tar -C /usr/local -xzf "/tmp/$GO_TAR" && rm -f "/tmp/$GO_TAR"
  else
    print_info "Go $GO_VERSION already present, skipping download"
  fi

  print_info "Building ${REPO}@${VERSION} with go install"
  mkdir -p "$INSTALL_DIR"
  if ping -c 1 -W 1 goproxy.cn >/dev/null 2>&1; then export GOPROXY=https://goproxy.cn,direct; fi
  GOBIN="$INSTALL_DIR" CGO_ENABLED=0 go install -ldflags "-s -w" "${REPO}@${VERSION}" || { print_error "go install failed"; exit 1; }
  # go names the binary after the last path element of the repo
  BIN_NAME="$(basename "${REPO%%@*}")"
  if [ "$BIN_NAME" != "ipv6-proxy" ] && [ -f "$INSTALL_DIR/$BIN_NAME" ]; then mv -f "$INSTALL_DIR/$BIN_NAME" "$INSTALL_DIR/ipv6-proxy"; fi
  [ -x "$INSTALL_DIR/ipv6-proxy" ] || { print_error "Binary not found after build"; exit 1; }
  print_success "Build complete"

  cat >/etc/systemd/system/ipv6-proxy.service <<SERVICEEOF
[Unit]
Description=Prefixa IPv6 Gateway v7.6
After=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ipv6-proxy
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
Restart=always
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
SERVICEEOF
  systemctl daemon-reload

  print_info "Tuning system"
  sysctl -w net.ipv6.neigh.default.gc_thresh1=2048 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.neigh.default.gc_thresh2=4096 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.neigh.default.gc_thresh3=10000 >/dev/null 2>&1 || true
  sysctl -w net.core.somaxconn=8192 >/dev/null 2>&1 || true
  ulimit -n 65535 2>/dev/null || true

  cd "$INSTALL_DIR" || exit 1
  if [ ! -f config.json ]; then ./ipv6-proxy || exit 1; fi
  PROXY_PORT=$(grep -oP '"port"\s*:\s*"\K[^"]+' config.json 2>/dev/null || echo 1080)
  WEB_PORT=$(grep -oP '"web_port"\s*:\s*"\K[^"]+' config.json 2>/dev/null || echo 8080)
  if command -v ufw >/dev/null 2>&1; then ufw allow "${PROXY_PORT}/tcp" >/dev/null 2>&1 || true; ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true; fi
  systemctl enable ipv6-proxy >/dev/null 2>&1
  systemctl restart ipv6-proxy
  if systemctl is-active --quiet ipv6-proxy; then
    print_success "Service started successfully"
    if wait_web_port "$WEB_PORT" 180; then
      print_success "Web panel port ${WEB_PORT} is healthy"
    else
      print_warning "Service started, but web panel port ${WEB_PORT} is not responding"
      echo "Check logs: journalctl -u ipv6-proxy -n 80 --no-pager"
      echo "Check listening ports: ss -lntp | grep ${WEB_PORT}"
    fi
  else
    print_warning "Service may have failed to start, check systemctl status ipv6-proxy"
    echo "Check logs: journalctl -u ipv6-proxy -n 80 --no-pager"
  fi
  IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-IP")
  echo "Web panel: http://${IP}:${WEB_PORT}"
  echo "HTTP proxy: http://proxy:proxy@${IP}:${PROXY_PORT}"
  echo "SOCKS5 proxy: socks5://proxy:proxy@${IP}:${PROXY_PORT}"
  echo "Config file: $INSTALL_DIR/config.json"
}

# Whole script is parsed before this line runs, so giving main a terminal as stdin
# keeps the interactive prompts working under `curl ... | bash`.
if [ -r /dev/tty ]; then main "$@" </dev/tty; else main "$@"; fi
