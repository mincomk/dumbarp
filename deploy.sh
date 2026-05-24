#!/usr/bin/env bash
# Build, package, and deploy dumbarpd to a Debian server over SSH.
#
# Usage:
#   ./deploy.sh user@host           # ssh target
#   DUMBARP_HOST=user@host ./deploy.sh
set -euo pipefail

HOST="${1:-${DUMBARP_HOST:-}}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 <user@host>   (or set DUMBARP_HOST)" >&2
    exit 1
fi

TARGET="x86_64-unknown-linux-musl"
PKG="dumbarpd"

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "==> Building release binary ($TARGET)"
cargo build -p "$PKG" --release --target "$TARGET"

echo "==> Packaging .deb"
cargo deb -p "$PKG" --no-build --target "$TARGET"

DEB=$(ls -t "target/$TARGET/debian/"dumbarpd_*.deb | head -1)
echo "==> Built: $DEB"

REMOTE="/tmp/$(basename "$DEB")"
echo "==> Uploading to $HOST:$REMOTE"
scp "$DEB" "$HOST:$REMOTE"

echo "==> Installing on $HOST"
ssh -t "$HOST" "sudo apt-get install -y --reinstall $REMOTE && rm -f $REMOTE && sudo systemctl status dumbarpd --no-pager -l"

cat <<EOF

==> Done.

Next steps on $HOST:
  sudo nano /etc/dumbarpd.toml         # set auth_token and ifaces
  sudo systemctl restart dumbarpd
  sudo journalctl -u dumbarpd -f       # tail logs

API:
  curl -s http://<host>:1028/health
  curl -s -H "Authorization: Bearer <token>" http://<host>:1028/interfaces
EOF
