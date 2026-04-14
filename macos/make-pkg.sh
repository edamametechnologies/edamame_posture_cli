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
INSTALL_ROOT="$TARGET/ROOT"
BUNDLE_ROOT="Library/Application Support/EDAMAME/EDAMAME-Posture"
APP_NAME="EDAMAME Posture"
APP_DIR="$INSTALL_ROOT/$BUNDLE_ROOT/edamame_posture.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
EXECUTABLE_NAME="edamame_posture"
EXECUTABLE_PATH="$MACOS_DIR/$EXECUTABLE_NAME"
BUNDLE_IDENTIFIER="com.edamametechnologies.edamame-posture"

rm -rf "$INSTALL_ROOT"
mkdir -p "$MACOS_DIR"

cp "$BINARY_SRC" "$EXECUTABLE_PATH"
chmod 755 "$EXECUTABLE_PATH"

cat > "$CONTENTS_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>$EXECUTABLE_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_IDENTIFIER</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>LSBackgroundOnly</key>
  <true/>
</dict>
</plist>
EOF
printf 'APPL????' > "$CONTENTS_DIR/PkgInfo"

# Restricted entitlements like Endpoint Security must be authorized by an
# embedded provisioning profile inside an app-like bundle. A loose Mach-O in
# /usr/local/bin will still be killed by AMFI even when installed from a pkg.
if [ -n "$PROVISIONING_PROFILE" ] && [ -f "$PROVISIONING_PROFILE" ]; then
  cp "$PROVISIONING_PROFILE" "$CONTENTS_DIR/embedded.provisionprofile"
  echo "Provisioning profile embedded in bundle"
else
  echo "No provisioning profile provided -- bundle will not include ES authorization"
fi

codesign --force --timestamp --options=runtime \
  --entitlements ./macos/edamame_posture.entitlements \
  -i "$BUNDLE_IDENTIFIER" \
  -s "Developer ID Application: Edamame Technologies (WSL782B48J)" \
  -v "$APP_DIR"

rm -rf "$TARGET/scripts"
mkdir -p "$TARGET/scripts"
cp ./macos/postinstall "$TARGET/scripts/"
chmod 755 "$TARGET/scripts/postinstall"

pkgbuild --analyze --root ./ROOT/ "$TARGET/components.plist"
plutil -replace 0.BundleIsRelocatable -bool NO "$TARGET/components.plist"

cd "$TARGET"
mkdir -p pkg
pkgbuild \
  --identifier "$BUNDLE_IDENTIFIER" \
  --root ./ROOT/ \
  --component-plist ./components.plist \
  --scripts ./scripts \
  --version "$VERSION" \
  pkg/edamame-posture-unsigned.pkg
productsign --sign WSL782B48J pkg/edamame-posture-unsigned.pkg edamame-posture.pkg
