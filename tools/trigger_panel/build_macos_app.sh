#!/usr/bin/env bash
# Build a double-clickable macOS .app that embeds its own Python runtime
# (plus tests/security/triggers). Recipients do not need Python installed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PANEL_DIR="$(cd "$(dirname "$0")" && pwd)"
TRIGGERS_SRC="$ROOT/tests/security/triggers"
DIST_DIR="${1:-$PANEL_DIR/dist}"
APP_NAME="EDAMAME Trigger Panel"
APP_DIR="$DIST_DIR/$APP_NAME.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
PYTHON_VERSION="${EDAMAME_EMBED_PYTHON_VERSION:-3.11}"
# Release tag being built (asset name), e.g. 2.0.7; "dev" for a local build.
VERSION="${EDAMAME_PANEL_VERSION:-dev}"
# Optional Developer ID Application identity; CI sets it to produce a signed,
# notarizable app. Unset -> ad-hoc ("-") signing for a local build.
SIGN_IDENTITY="${EDAMAME_CODESIGN_IDENTITY:--}"
# Optional notarytool keychain profile; CI sets it to notarize and staple.
NOTARIZE_PROFILE="${EDAMAME_NOTARIZE_PROFILE:-}"
# Prefer the machine arch over a Rosetta shell's uname (which reports x86_64).
if [[ -n "${EDAMAME_EMBED_ARCH:-}" ]]; then
  ARCH="$EDAMAME_EMBED_ARCH"
elif [[ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == "1" ]]; then
  ARCH="arm64"
else
  ARCH="$(uname -m)"
fi

if [[ ! -f "$TRIGGERS_SRC/cleanup.py" ]]; then
  echo "Missing triggers at $TRIGGERS_SRC" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to fetch a relocatable CPython (https://github.com/astral-sh/uv)" >&2
  exit 1
fi

echo "Installing relocatable CPython ${PYTHON_VERSION} for ${ARCH}..."
# Pin the download/find to the target arch even when this shell is Rosetta x86_64.
UV_PYTHON_INSTALL_ARGS=()
case "$ARCH" in
  arm64|aarch64) UV_PYTHON_INSTALL_ARGS=(--python-platform aarch64-apple-darwin) ;;
  x86_64|amd64) UV_PYTHON_INSTALL_ARGS=(--python-platform x86_64-apple-darwin) ;;
esac
# uv python install does not take --python-platform on all versions; fall back.
if uv python install "$PYTHON_VERSION" "${UV_PYTHON_INSTALL_ARGS[@]}" >/dev/null 2>&1; then
  :
else
  uv python install "$PYTHON_VERSION" >/dev/null
fi

PY_BIN="$(uv python find "$PYTHON_VERSION" 2>/dev/null || true)"
if [[ -z "$PY_BIN" || ! -x "$PY_BIN" ]]; then
  # Prefer an already-installed matching standalone tree under uv's python dir.
  UV_PY_DIR="${UV_PYTHON_INSTALL_DIR:-$HOME/.local/share/uv/python}"
  shopt -s nullglob
  matches=("$UV_PY_DIR"/cpython-${PYTHON_VERSION}*-macos-"$ARCH"-none)
  if [[ "$ARCH" == "arm64" ]]; then
    matches+=("$UV_PY_DIR"/cpython-${PYTHON_VERSION}*-macos-aarch64-none)
  fi
  shopt -u nullglob
  if [[ ${#matches[@]} -eq 0 ]]; then
    echo "No CPython ${PYTHON_VERSION} for ${ARCH} found under $UV_PY_DIR" >&2
    exit 1
  fi
  PY_HOME="$(cd "${matches[0]}" && pwd)"
  PY_BIN="$PY_HOME/bin/python3"
else
  PY_HOME="$(cd "$(dirname "$PY_BIN")/.." && pwd)"
fi

# If uv find returned a non-standalone (Homebrew/Frameworks) interpreter, prefer
# a relocatable uv-managed tree for bundling.
case "$PY_HOME" in
  */.local/share/uv/python/*) ;;
  *)
    UV_PY_DIR="${UV_PYTHON_INSTALL_DIR:-$HOME/.local/share/uv/python}"
    shopt -s nullglob
    matches=("$UV_PY_DIR"/cpython-${PYTHON_VERSION}*-macos-"$ARCH"-none)
    if [[ "$ARCH" == "arm64" ]]; then
      matches+=("$UV_PY_DIR"/cpython-${PYTHON_VERSION}*-macos-aarch64-none)
    fi
    shopt -u nullglob
    if [[ ${#matches[@]} -gt 0 ]]; then
      PY_HOME="$(cd "${matches[0]}" && pwd)"
      PY_BIN="$PY_HOME/bin/python3"
    fi
    ;;
esac
echo "Using Python home: $PY_HOME"
if [[ ! -x "$PY_HOME/bin/python3" ]]; then
  echo "Could not resolve Python home from $PY_BIN" >&2
  exit 1
fi
if ! "$PY_HOME/bin/python3" -c "import tkinter" >/dev/null 2>&1; then
  echo "Embedded Python at $PY_HOME has no tkinter; pick another version." >&2
  exit 1
fi

echo "Assembling $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$MACOS" "$RESOURCES/triggers" "$RESOURCES/python"

rsync -a \
  --delete \
  --exclude 'BUILD' \
  --exclude 'include' \
  --exclude 'share' \
  --exclude 'lib/python*/test' \
  --exclude 'lib/python*/idlelib' \
  --exclude 'lib/python*/turtledemo' \
  --exclude 'lib/python*/ensurepip' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$PY_HOME/" "$RESOURCES/python/"

# Normalize the launcher name so the app always calls bin/python3.
if [[ ! -e "$RESOURCES/python/bin/python3" ]]; then
  shopt -s nullglob
  for candidate in "$RESOURCES/python/bin"/python3.*; do
    [[ -x "$candidate" ]] || continue
    ln -sf "$(basename "$candidate")" "$RESOURCES/python/bin/python3"
    break
  done
  shopt -u nullglob
fi
if [[ ! -x "$RESOURCES/python/bin/python3" ]]; then
  echo "Failed to create Resources/python/bin/python3" >&2
  exit 1
fi

cp "$PANEL_DIR/app.py" "$RESOURCES/app.py"
rsync -a \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  "$TRIGGERS_SRC/" "$RESOURCES/triggers/"

# The dylib id is an absolute path on the build machine. Point it at the
# copy that ships inside the app so another Mac can load it.
install_name_tool -id @rpath/libpython3.11.dylib \
  "$RESOURCES/python/lib/libpython3.11.dylib"

cc -Os -mmacosx-version-min=12.0 -arch "$ARCH" \
  -o "$MACOS/EDAMAME Trigger Panel" \
  "$PANEL_DIR/launcher.c"
chmod +x "$RESOURCES/python/bin/"python* 2>/dev/null || true

# Exercise the runtime before sealing the bundle. Bytecode written afterward
# would invalidate the signature.
export PYTHONDONTWRITEBYTECODE=1
"$RESOURCES/python/bin/python3.11" - <<'PY'
import pathlib, tkinter, sys
assert pathlib.Path(sys.executable).is_file()
import tkinter as tk
print(f"embedded python ok: {sys.version.split()[0]} tk={tk.TkVersion}")
PY

xattr -cr "$APP_DIR" 2>/dev/null || true

# Info.plist must be in place BEFORE signing: codesign seals it into
# CodeResources, and a notarized Developer ID app rejects a plist written
# afterwards.
cat > "$CONTENTS/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>EDAMAME Trigger Panel</string>
  <key>CFBundleIdentifier</key>
  <string>com.edamame.trigger-panel</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>EDAMAME Trigger Panel</string>
  <key>CFBundleDisplayName</key>
  <string>EDAMAME Trigger Panel</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.2</string>
  <key>CFBundleVersion</key>
  <string>3</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

# Sign nested Mach-O files first, then the bundle. With a Developer ID
# identity (CI) use the hardened runtime + a secure timestamp so the app can
# be notarized; otherwise ad-hoc ("-") so a locally built app still launches.
# An unsigned shell-script app is rejected on a Mac that did not build it.
SIGN_ARGS=(--force --sign "$SIGN_IDENTITY")
if [[ "$SIGN_IDENTITY" != "-" ]]; then
  SIGN_ARGS+=(--options runtime --timestamp)
fi
find "$APP_DIR" -type f -print0 | while IFS= read -r -d '' candidate; do
  if file "$candidate" | grep -q 'Mach-O'; then
    codesign "${SIGN_ARGS[@]}" "$candidate" >/dev/null 2>&1
  fi
done
codesign "${SIGN_ARGS[@]}" "$MACOS/EDAMAME Trigger Panel"
codesign "${SIGN_ARGS[@]}" "$APP_DIR"

EDAMAME_TRIGGER_PANEL_CHECK=1 "$MACOS/EDAMAME Trigger Panel"
codesign --verify --deep --strict "$APP_DIR"
echo "codesign ok"

ZIP_NAME="edamame-trigger-panel-macos-${ARCH}-${VERSION}.zip"
ZIP_PATH="$DIST_DIR/$ZIP_NAME"
rm -f "$ZIP_PATH"
ditto -c -k --sequesterRsrc --keepParent "$APP_DIR" "$ZIP_PATH"

# Notarize the zipped app, then staple the ticket into the .app and rebuild
# the zip so Gatekeeper accepts it offline too. Only runs when CI provides a
# notarytool keychain profile.
if [[ -n "$NOTARIZE_PROFILE" ]]; then
  echo "Submitting $ZIP_NAME for notarization (profile: $NOTARIZE_PROFILE)..."
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARIZE_PROFILE" --wait
  xcrun stapler staple "$APP_DIR"
  xcrun stapler validate "$APP_DIR"
  rm -f "$ZIP_PATH"
  ditto -c -k --sequesterRsrc --keepParent "$APP_DIR" "$ZIP_PATH"
  echo "notarized and stapled"
fi

SIZE="$(du -sh "$APP_DIR" | awk '{print $1}')"
echo "Built: $APP_DIR ($SIZE, $ARCH)"
echo "Zip:   $ZIP_PATH"
echo "Open:  open \"$APP_DIR\""
# Final line: the artifact path (consumed by CI).
echo "ARTIFACT=$ZIP_PATH"
