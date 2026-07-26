#!/usr/bin/env sh
set -eu

REPO_URL=${HEADERPROOF_REPO_URL:-https://github.com/TayfurYldz/headerproof.git}

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-/opt/headerproof}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-/usr/local/bin}
else
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-"$HOME/.local/share/headerproof"}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-"$HOME/.local/bin"}
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)
TMP_DIR=""

if [ -f "$SCRIPT_DIR/header_active_scan.py" ] && [ -f "$SCRIPT_DIR/file_safety.py" ]; then
    SRC_DIR=$SCRIPT_DIR
else
    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: git is required when install.sh is run outside a clone." >&2
        exit 1
    fi
    TMP_DIR="${TMPDIR:-/tmp}/headerproof-install.$$"
    git clone --depth 1 "$REPO_URL" "$TMP_DIR"
    SRC_DIR=$TMP_DIR
fi

mkdir -p "$INSTALL_DIR" "$BIN_DIR"

cp "$SRC_DIR/header_active_scan.py" "$INSTALL_DIR/header_active_scan.py"
cp "$SRC_DIR/file_safety.py" "$INSTALL_DIR/file_safety.py"
cp "$SRC_DIR/headerproof" "$INSTALL_DIR/headerproof"
cp "$SRC_DIR/README.md" "$INSTALL_DIR/README.md"
cp "$SRC_DIR/LICENSE" "$INSTALL_DIR/LICENSE"
cp "$SRC_DIR/CHANGELOG.md" "$INSTALL_DIR/CHANGELOG.md"
cp "$SRC_DIR/pyproject.toml" "$INSTALL_DIR/pyproject.toml"

if [ -d "$SRC_DIR/examples" ]; then
    mkdir -p "$INSTALL_DIR/examples"
    cp "$SRC_DIR"/examples/* "$INSTALL_DIR/examples/" 2>/dev/null || true
fi

LAUNCHER="$BIN_DIR/headerproof"
TMP_LAUNCHER="$LAUNCHER.tmp.$$"
{
    printf '%s\n' '#!/usr/bin/env sh'
    printf 'exec python3 "%s/header_active_scan.py" "$@"\n' "$INSTALL_DIR"
} > "$TMP_LAUNCHER"
chmod 755 "$TMP_LAUNCHER"
mv "$TMP_LAUNCHER" "$LAUNCHER"
chmod 755 "$INSTALL_DIR/header_active_scan.py" "$INSTALL_DIR/headerproof" 2>/dev/null || true

if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
fi

echo "HeaderProof installed."
echo "Command: headerproof -i urls.txt --concurrency 16"
echo "Binary:  $LAUNCHER"
echo "Files:   $INSTALL_DIR"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "NOTE: $BIN_DIR is not in PATH. Add it or run: $LAUNCHER -i urls.txt --concurrency 16" ;;
esac
