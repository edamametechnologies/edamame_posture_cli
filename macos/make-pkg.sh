#!/bin/bash
set -e

BINARY_SRC=""
PROVISIONING_PROFILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --provisioning-profile) PROVISIONING_PROFILE="$2"; shift 2 ;;
    -*) echo "Unknown option: $1" >&2; exit 1 ;;
    *) BINARY_SRC="$1"; shift ;;
  esac
done
BINARY_SRC="${BINARY_SRC:-./target/release/edamame_posture}"

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

# Embed the ES provisioning profile so AMFI can authorize the entitlement at runtime.
# Without the profile, macOS kills the binary with SIGKILL (signal 9).
if [ -n "$PROVISIONING_PROFILE" ] && [ -f "$PROVISIONING_PROFILE" ]; then
  PROFILE_DIR="$TARGET/ROOT/Library/MobileDevice/Provisioning Profiles"
  mkdir -p "$PROFILE_DIR"
  cp "$PROVISIONING_PROFILE" "$PROFILE_DIR/EDAMAME_Posture.provisionprofile"
  echo "Provisioning profile embedded in package"
else
  echo "No provisioning profile provided -- package will not include ES authorization"
fi

cd "$TARGET"
mkdir -p pkg
pkgbuild --identifier com.edamametechnologies.edamame-posture --root ./ROOT/ --version "$VERSION" pkg/edamame-posture-unsigned.pkg
productsign --sign WSL782B48J pkg/edamame-posture-unsigned.pkg edamame-posture.pkg
