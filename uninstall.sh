#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-/opt/headerproof}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-/usr/local/bin}
else
    INSTALL_DIR=${HEADERPROOF_INSTALL_DIR:-"$HOME/.local/share/headerproof"}
    BIN_DIR=${HEADERPROOF_BIN_DIR:-"$HOME/.local/bin"}
fi

rm -f "$BIN_DIR/headerproof"
rm -rf "$INSTALL_DIR"

echo "HeaderProof removed from $BIN_DIR/headerproof and $INSTALL_DIR"
