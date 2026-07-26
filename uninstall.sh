#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-/opt/headerproof}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-/usr/local/bin}
else
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-"$HOME/.local/share/headerproof"}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-"$HOME/.local/bin"}
fi

case "$INSTALL_DIR" in
    ""|"/"|"$HOME"|"/home"|"/opt"|"/usr"|"/usr/local"|"/usr/local/bin"|"$BIN_DIR")
        echo "ERROR: refusing unsafe HeaderProof install directory: $INSTALL_DIR" >&2
        exit 1
        ;;
    *headerproof*) ;;
    *)
        echo "ERROR: refusing to remove non-HeaderProof-looking directory: $INSTALL_DIR" >&2
        echo "Set HEADERPROOF_INSTALL_DIR to the exact HeaderProof install directory." >&2
        exit 1
        ;;
esac

rm -f "$BIN_DIR/headerproof"
rm -rf "$INSTALL_DIR"

echo "HeaderProof removed from $BIN_DIR/headerproof and $INSTALL_DIR"
