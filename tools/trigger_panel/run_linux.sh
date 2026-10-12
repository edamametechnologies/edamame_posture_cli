#!/usr/bin/env bash
# Launcher for the Linux bundle of the EDAMAME Trigger Panel. Shipped inside
# the bundle as run.sh; execs the bundled CPython on app.py. The interpreter
# path is not a macOS .app, so triggers run under it directly.
set -euo pipefail

here="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export EDAMAME_TRIGGERS_DIR="$here/triggers"
export PYTHONNOUSERSITE=1

py="$here/python/bin/python3"
if [[ ! -x "$py" ]]; then
  echo "The Python runtime shipped inside this bundle is missing ($py)." >&2
  echo "You do not need to install Python; download the bundle again." >&2
  exit 1
fi

# Standalone CPython ships its own Tcl/Tk under python/lib.
for tcl in "$here"/python/lib/tcl*; do
  [[ -d "$tcl" ]] && export TCL_LIBRARY="$tcl"
done
for tk in "$here"/python/lib/tk*; do
  [[ -d "$tk" ]] && export TK_LIBRARY="$tk"
done

exec "$py" "$here/app.py" "$@"
