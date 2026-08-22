#!/bin/sh
set -e

REPO="wave-cl/sqns"
INSTALL_DIR="${SQNS_INSTALL_DIR:-}"
SERVER_MODE=false

for arg in "$@"; do
    case "$arg" in
        --server) SERVER_MODE=true ;;
    esac
done

info() { printf "  \033[1m%s\033[0m\n" "$1"; }
err()  { printf "  \033[31merror:\033[0m %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="darwin" ;;
    *)      err "unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  TARGET="x86_64-linux-gnu" ;;
    aarch64|arm64) TARGET="aarch64-linux-gnu" ;;
    *)             err "unsupported architecture: $ARCH" ;;
esac

if [ "$OS_NAME" = "darwin" ]; then
    case "$ARCH" in
        x86_64|amd64)  TARGET="x86_64-apple-darwin" ;;
        aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
    esac
fi

# Determine install directory
if [ -n "$INSTALL_DIR" ]; then
    BIN_DIR="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    err "curl or wget required"
fi

info "Fetching latest release..."
LATEST=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -z "$LATEST" ] && err "could not determine latest version"
info "Latest version: $LATEST"

URL="https://github.com/$REPO/releases/download/$LATEST/sqns-${LATEST}-${TARGET}.tar.gz"
info "Downloading sqns $LATEST for $TARGET..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch "$URL" > "$TMPDIR/sqns.tar.gz" || err "download failed — no release for $TARGET?"

info "Installing to $BIN_DIR..."
mkdir -p "$BIN_DIR"
tar -xzf "$TMPDIR/sqns.tar.gz" -C "$BIN_DIR"

if ! "$BIN_DIR/sqns" --version >/dev/null 2>&1; then
    err "installation failed — sqns not executable"
fi

VERSION=$("$BIN_DIR/sqns" --version 2>&1 || echo "unknown")
info "Installed: $VERSION"

# PATH setup for non-root installs
if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            SHELL_NAME=$(basename "$SHELL" 2>/dev/null || echo "unknown")
            case "$SHELL_NAME" in
                bash)
                    RC="$HOME/.bashrc"
                    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                zsh)
                    RC="$HOME/.zshrc"
                    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                fish)
                    RC="$HOME/.config/fish/config.fish"
                    mkdir -p "$(dirname "$RC")"
                    echo 'fish_add_path ~/.local/bin' >> "$RC"
                    info "Added ~/.local/bin to PATH in $RC"
                    ;;
                *)
                    info "Add $BIN_DIR to your PATH"
                    ;;
            esac
            info "Restart your shell or run: export PATH=\"$BIN_DIR:\$PATH\""
            ;;
    esac
fi

if [ "$SERVER_MODE" = true ]; then
    info "Setting up the sqnsd server..."

    [ "$(id -u)" -ne 0 ] && err "--server requires root"
    [ "$OS_NAME" != "linux" ] && err "--server is only supported on Linux"

    mkdir -p /etc/sqns
    chmod 755 /etc/sqns
    mkdir -p /var/lib/sqns
    chmod 700 /var/lib/sqns

    if [ -f /etc/sqns/sqnsd.key ]; then
        info "Server key already exists, keeping it"
    else
        info "Generating the server key..."
        "$BIN_DIR/sqnsd" keygen --out /etc/sqns/sqnsd.key >/dev/null
        info "Server key generated"
    fi

    if [ -f /etc/sqns/sqnsd.toml ]; then
        info "Config already exists, skipping"
    else
        info "Writing default config to /etc/sqns/sqnsd.toml..."
        cat > /etc/sqns/sqnsd.toml << 'CONF'
# sqnsd configuration. See the README for every option.

listen = "[::]:5300"
key_file = "/etc/sqns/sqnsd.key"
state_file = "/var/lib/sqns/records.db"

# Replication peers, as sqc://host:port/<base58 key>. Peering is not mutual:
# list this server on the other side too.
peers = []

# Base58 client keys allowed to connect at all. Empty means anyone holding this
# server's public key may connect.
allowed_clients = []

# Answer anti-entropy pulls, which hand the caller the whole record set. Peers
# need this; a public-facing server that should only answer point lookups can
# turn it off.
allow_sync = true

sync_interval_secs = 60
persist_interval_secs = 30
CONF
        chmod 644 /etc/sqns/sqnsd.toml
    fi

    if command -v systemctl >/dev/null 2>&1; then
        info "Installing the systemd service..."
        cat > /etc/systemd/system/sqnsd.service << 'SVC'
[Unit]
Description=sqns server daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sqnsd --config /etc/sqns/sqnsd.toml
Restart=on-failure
RestartSec=2
StateDirectory=sqns

[Install]
WantedBy=multi-user.target
SVC
        chmod 644 /etc/systemd/system/sqnsd.service
        systemctl daemon-reload
        systemctl enable sqnsd

        if systemctl is-active sqnsd >/dev/null 2>&1; then
            info "Restarting sqnsd..."
            systemctl restart sqnsd
        else
            info "Starting sqnsd..."
            systemctl start sqnsd
        fi

        sleep 1
        if systemctl is-active sqnsd >/dev/null 2>&1; then
            info "sqnsd is running"
        else
            err "sqnsd failed to start — check: journalctl -u sqnsd"
        fi
    else
        info "systemd not found — skipping service installation"
        info "Start manually: sqnsd --config /etc/sqns/sqnsd.toml"
    fi

    PUBKEY=$("$BIN_DIR/sqnsd" --key-file /etc/sqns/sqnsd.key --show-pubkey 2>/dev/null)
    HOSTNAME="$(curl -4 -fsSL -m 3 https://api.ipify.org 2>/dev/null || curl -4 -fsSL -m 3 https://ifconfig.me 2>/dev/null || hostname -f 2>/dev/null || hostname)"
    printf "\n"
    info "Server public key:"
    printf "  %s\n\n" "$PUBKEY"
    info "Clients reach it with:"
    printf "  export SQNS_SERVER=sqc://%s:5300/%s\n\n" "$HOSTNAME" "$PUBKEY"
    info "Or put that address in ~/.sqns/config, one per line."
    printf "\n"
else
    printf "\n"
    info "Getting started:"
    printf "  Point at a server:  export SQNS_SERVER=sqc://host:5300/<server key>\n"
    printf "                      (or list it in ~/.sqns/config, one per line)\n\n"
    printf "  1. sqns keygen --identity            # your identity key — keep it offline\n"
    printf "  2. sqns keygen                       # a service key for this node\n"
    printf "  3. sqns delegate                     # the identity issues it authority\n"
    printf "  4. sqns publish -e 198.51.100.4:443  # publish where you can be reached\n\n"
    info "Then, from anywhere:"
    printf "  sqns resolve <service key>\n\n"
    info "Server setup:"
    printf "  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh -s -- --server\n\n" "$REPO"
fi
