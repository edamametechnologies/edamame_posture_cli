#!/bin/bash
set -e

BINARY_SRC="${1:-./target/release/edamame_posture}"
VERSION=$(grep '^version =' ./Cargo.toml | awk '{print $3}' | tr -d '"')
TARGET="./target/pkg"
ROOT="usr/local/bin"

rm -rf "$TARGET/ROOT/"
mkdir -p "$TARGET/ROOT/$ROOT"

cp "$BINARY_SRC" "$TARGET/ROOT/$ROOT/edamame_posture"

codesign --timestamp --options=runtime \
  --entitlements ./macos/edamame_posture.entitlements \
  -i com.edamametechnologies.edamame-posture \
  -s "Developer ID Application: Edamame Technologies (WSL782B48J)" \
  -v "$TARGET/ROOT/$ROOT"/edamame_posture

cd "$TARGET"
mkdir -p pkg
pkgbuild --identifier com.edamametechnologies.edamame-posture --root ./ROOT/ --version "$VERSION" pkg/edamame-posture-unsigned.pkg
productsign --sign WSL782B48J pkg/edamame-posture-unsigned.pkg edamame-posture.pkg
