#!/usr/bin/env bash
# Build a self-contained Linux bundle of the EDAMAME Trigger Panel that embeds
# its own standalone CPython (fetched with uv) plus a copy of
# tests/security/triggers and a run.sh launcher. Recipients do not need Python
# installed. The bundled interpreter's path is not a macOS .app, so triggers
# run under it directly. No code signing on Linux.
#
# Usage: build_linux.sh [OUTPUT_DIR]
#   EDAMAME_EMBED_PYTHON_VERSION  embedded CPython version (default 3.11)
#   EDAMAME_PANEL_VERSION         asset version in the file name (default dev)
# Prints "ARTIFACT=<path>" with the produced .tar.gz path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PANEL_DIR="$(cd "$(dirname "$0")" && pwd)"
TRIGGERS_SRC="$ROOT/tests/security/triggers"
DIST_DIR="${1:-$PANEL_DIR/dist}"
PYTHON_VERSION="${EDAMAME_EMBED_PYTHON_VERSION:-3.11}"
VERSION="${EDAMAME_PANEL_VERSION:-dev}"
APP_NAME="edamame-trigger-panel"
BUNDLE_DIR="$DIST_DIR/$APP_NAME"

if [[ ! -f "$TRIGGERS_SRC/cleanup.py" ]]; then
  echo "Missing triggers at $TRIGGERS_SRC" >&2
  exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to fetch a relocatable CPython (https://github.com/astral-sh/uv)" >&2
  exit 1
fi

export UV_PYTHON_PREFERENCE=only-managed
echo "Installing relocatable CPython ${PYTHON_VERSION} (x86_64)..."
uv python install "$PYTHON_VERSION"

PY_BIN="$(uv python find "$PYTHON_VERSION" 2>/dev/null || true)"
if [[ -z "$PY_BIN" || ! -x "$PY_BIN" ]]; then
  echo "Could not resolve CPython ${PYTHON_VERSION} via uv" >&2
  exit 1
fi
PY_HOME="$(cd "$(dirname "$PY_BIN")/.." && pwd)"
echo "Using Python home: $PY_HOME"
if [[ ! -x "$PY_HOME/bin/python3" ]]; then
  echo "Could not resolve Python home from $PY_BIN" >&2
  exit 1
fi
if ! "$PY_HOME/bin/python3" -c "import tkinter" >/dev/null 2>&1; then
  echo "Embedded Python at $PY_HOME has no tkinter; pick another version." >&2
  exit 1
fi

echo "Assembling $BUNDLE_DIR"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR/python" "$BUNDLE_DIR/triggers"

rsync -a \
  --exclude 'include' \
  --exclude 'share' \
  --exclude 'lib/python*/test' \
  --exclude 'lib/python*/idlelib' \
  --exclude 'lib/python*/turtledemo' \
  --exclude 'lib/python*/ensurepip' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$PY_HOME/" "$BUNDLE_DIR/python/"

if [[ ! -x "$BUNDLE_DIR/python/bin/python3" ]]; then
  echo "Failed to assemble python/bin/python3" >&2
  exit 1
fi

cp "$PANEL_DIR/app.py" "$BUNDLE_DIR/app.py"
cp "$PANEL_DIR/run_linux.sh" "$BUNDLE_DIR/run.sh"
chmod +x "$BUNDLE_DIR/run.sh"
rsync -a \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  "$TRIGGERS_SRC/" "$BUNDLE_DIR/triggers/"

# Exercise the embedded runtime before sealing.
"$BUNDLE_DIR/python/bin/python3" - <<'PY'
import tkinter, sys
print(f"embedded python ok: {sys.version.split()[0]} tk={tkinter.TkVersion}")
PY

TAR_NAME="edamame-trigger-panel-linux-x64-${VERSION}.tar.gz"
TAR_PATH="$DIST_DIR/$TAR_NAME"
rm -f "$TAR_PATH"
tar -C "$DIST_DIR" -czf "$TAR_PATH" "$APP_NAME"

SIZE="$(du -sh "$BUNDLE_DIR" | awk '{print $1}')"
echo "Built: $BUNDLE_DIR ($SIZE)"
echo "Tar:   $TAR_PATH"
echo "ARTIFACT=$TAR_PATH"
