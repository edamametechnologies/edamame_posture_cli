# EDAMAME Trigger Panel

A small, self-contained GUI for starting and stopping the EDAMAME security
demo triggers under `tests/security/triggers/`, and for running their
`cleanup.py`. **For authorized local detection testing only.**

The panel is a convenience wrapper: it runs the same trigger scripts the
security test suite uses, so you can watch EDAMAME react to them on your own
machine. It changes nothing about how detection works and makes no network
connections of its own.

Each download bundles its own Python runtime, so you do **not** need Python
installed. The bundle also carries a copy of the trigger scripts.

## What it does

- Lists every `trigger_*.py` with a Start / Stop button and a live status.
- Starts a trigger under the bundled interpreter with the agent type and
  state directory the triggers expect for your platform.
- **Agent type selector** (`openclaw`, `cursor`, `claude_code`,
  `claude_desktop`, `codex`, `hermes`): sets the identity the triggers use to
  derive their state directory and file-name prefixes, so you can simulate
  different agents.
- **Run cleanup**: stops running triggers and removes the files they created
  for the selected agent type (`cleanup.py`).

You need a **running EDAMAME** to observe anything: either the EDAMAME
Security app, or the `edamame-posture` daemon with protection enabled. The
panel only produces the activity; EDAMAME is what detects it.

## Download

Latest version:

| Platform | Download | SHA-256 |
|---|---|---|
| macOS (Apple silicon) | [edamame-trigger-panel-macos-arm64-latest.zip](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-macos-arm64-latest.zip) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-macos-arm64-latest.zip.sha256) |
| Windows (x64) | [edamame-trigger-panel-windows-x64-latest.zip](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-windows-x64-latest.zip) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-windows-x64-latest.zip.sha256) |
| Linux (x64) | [edamame-trigger-panel-linux-x64-latest.tar.gz](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-linux-x64-latest.tar.gz) | [.sha256](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/edamame-trigger-panel-linux-x64-latest.tar.gz.sha256) |

[`LATEST`](https://edamame.s3.eu-west-1.amazonaws.com/trigger-panel/LATEST)
holds the version these links serve. To check a download, run
`shasum -a 256 -c <file>.sha256` in the folder holding both files.

A specific version is attached to each
[release of this repository](https://github.com/edamametechnologies/edamame_posture_cli/releases)
(the same release page as `edamame-posture`), as
`edamame-trigger-panel-<platform>-<version>.zip` (`.tar.gz` on Linux), with
`trigger-panel-SHA256SUMS-<version>.txt` listing the SHA-256 of each bundle.

## Opening it

### macOS

The app is signed with EDAMAME's Developer ID and notarized by Apple, so
Gatekeeper accepts it. Unzip and double-click **EDAMAME Trigger Panel.app**.
If macOS still hesitates on first launch (for example after copying between
machines), right-click the app and choose **Open**, then **Open** in the
dialog.

### Windows

The launcher is Authenticode-signed by EDAMAME. Unzip the folder and run
**EDAMAME Trigger Panel.exe**. If SmartScreen shows a "Windows protected your
PC" notice, choose **More info -> Run anyway**. Keep the folder intact; the
launcher expects `python\` and `triggers\` beside it.

### Linux

Extract the archive and run the launcher:

```sh
tar xf edamame-trigger-panel-linux-x64-<version>.tar.gz
./edamame-trigger-panel/run.sh
```

A graphical session with Tk support is required (the bundle ships its own
Tcl/Tk).

## Notes

- The panel passes an explicit `--state-dir` to every trigger and to
  `cleanup.py`, computed to match
  `tests/security/triggers/_common.py::state_dir_for` for your OS
  (`%TEMP%\edamame_<agent>_demo` on Windows, `/tmp/edamame_<agent>_demo`
  elsewhere). Always run **Run cleanup** when you are done so no demo files
  are left behind.
- On macOS the bundled interpreter is copied out of the `.app` before it
  launches a trigger. A process running from inside a `.app` touching your
  home directory would be treated as an application reading its own files, and
  the findings the triggers are meant to raise would not appear. On Windows
  and Linux the bundled interpreter is used in place.

## Building locally (developers)

The CI workflow `.github/workflows/trigger_panel.yml` builds and signs the
bundles. To build an (unsigned) bundle on your own machine you need
[`uv`](https://github.com/astral-sh/uv):

```sh
tools/trigger_panel/build_macos_app.sh   out_dir   # macOS
tools/trigger_panel/build_linux.sh       out_dir   # Linux
pwsh tools/trigger_panel/build_windows.ps1 -DistDir out_dir   # Windows
```

Each script embeds a standalone CPython (version
`EDAMAME_EMBED_PYTHON_VERSION`, default 3.11), copies in the triggers, and
prints the produced artifact path as `ARTIFACT=...`.
