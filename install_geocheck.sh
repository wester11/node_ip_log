#!/usr/bin/env bash
# Install the optional geocheck binary used only for full manual/rare audits.
# This deliberately does not execute a remote launcher: version, URL and
# SHA-256 are pinned here and a failed optional download never breaks the node
# management channel.
set -u
set -o pipefail
umask 077

APP_DIR=${APP_DIR:-/opt/void-node-agent}
VERSION=v0.3.0
BASE_URL="https://github.com/remnawave/geocheck/releases/download/${VERSION}"

case "$(uname -m 2>/dev/null || true)" in
    x86_64|amd64)
        ARCHIVE=geocheck_linux_amd64.tar.gz
        EXPECTED_SHA256=eca33bbee3c2c3ea7ade85f9a61ef4c7471a8334eb8f0a715e844aef865307d9
        ;;
    aarch64|arm64)
        ARCHIVE=geocheck_linux_arm64.tar.gz
        EXPECTED_SHA256=1badce683fd901b4052a78b833d536b851cf1f5952d82bc985c875e37a153267
        ;;
    *)
        echo "[VOID] geocheck skipped: unsupported architecture" >&2
        exit 0
        ;;
esac

TARGET_DIR="$APP_DIR/bin"
TARGET="$TARGET_DIR/geocheck"
if [[ -x "$TARGET" ]] && "$TARGET" --help >/dev/null 2>&1; then
    exit 0
fi

WORK_DIR=$(mktemp -d /tmp/void-geocheck.XXXXXX) || exit 0
cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT INT TERM

if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 90 "$BASE_URL/$ARCHIVE" -o "$WORK_DIR/$ARCHIVE" || {
        echo "[VOID] geocheck skipped: download failed" >&2; exit 0; }
elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$WORK_DIR/$ARCHIVE" "$BASE_URL/$ARCHIVE" || {
        echo "[VOID] geocheck skipped: download failed" >&2; exit 0; }
else
    echo "[VOID] geocheck skipped: curl or wget is unavailable" >&2
    exit 0
fi

actual=$(sha256sum "$WORK_DIR/$ARCHIVE" | awk '{print $1}')
if [[ "$actual" != "$EXPECTED_SHA256" ]]; then
    echo "[VOID] geocheck skipped: checksum mismatch" >&2
    exit 0
fi
tar -xzf "$WORK_DIR/$ARCHIVE" -C "$WORK_DIR" || { echo "[VOID] geocheck skipped: archive error" >&2; exit 0; }
BINARY=$(find "$WORK_DIR" -type f -name geocheck -print -quit)
if [[ -z "$BINARY" ]]; then
    echo "[VOID] geocheck skipped: binary not found" >&2
    exit 0
fi
install -d -o root -g root -m 755 "$TARGET_DIR"
install -o root -g root -m 755 "$BINARY" "$TARGET"
echo "[VOID] geocheck ${VERSION} installed for full node audits"
