#!/usr/bin/env bash
# Function-level tests for the service-conf merge in install.sh and the conf
# parser in linux/edamame_posture_daemon.sh. No root, no network, no package
# manager: runs on macOS and Linux with plain bash.
#
#   bash tests/installer/install_conf_test.sh
#
# Covers the 2.0.1 regressions: the agentic mode and the LLM key must reach
# the service conf, survive re-runs (with the same, fewer or no options), be
# written 0600, never be printed, and be handed to the daemon at start.
# 2.0.2: the PIN reaches the daemon through EDAMAME_PIN, never argv; the
# llm_model / llm_base_url keys; agentic_mode "off"; confs written before a
# key existed read it as its default.
#
# The CONFIG_* / SUDO assignments are read by the sourced install.sh functions.
# shellcheck disable=SC2034

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/install.sh"
WRAPPER="$REPO_ROOT/linux/edamame_posture_daemon.sh"
PACKAGED_CONF="$REPO_ROOT/linux/edamame_posture.conf"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   - %s\n' "$1"; }
not_ok() { FAIL=$((FAIL + 1)); printf 'FAIL - %s\n' "$1"; }
assert_eq() {
    if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1 (expected [$3], got [$2])"; fi
}

file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}
file_mtime() {
    stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1"
}

# Load the installer's functions only (the lib guard stops before argument
# parsing and every side effect).
# shellcheck disable=SC1090
EDAMAME_INSTALL_SH_LIB=1 . "$INSTALL_SH"
set +e
SUDO=""

reset_run() {
    CONFIG_USER=""; CONFIG_DOMAIN=""; CONFIG_PIN=""; CONFIG_DEVICE_ID=""
    CONFIG_AGENTIC_MODE="disabled"; CONFIG_AGENTIC_MODE_SET="false"
    CONFIG_AGENTIC_PROVIDER=""; CONFIG_AGENTIC_PROVIDER_SET="false"
    CONFIG_AGENTIC_INTERVAL="3600"; CONFIG_AGENTIC_INTERVAL_SET="false"
    CONFIG_LLM_API_KEY=""; CONFIG_LLM_BASE_URL=""; CONFIG_LLM_MODEL=""
    CONFIG_SLACK_BOT_TOKEN=""; CONFIG_SLACK_ACTIONS_CHANNEL=""; CONFIG_SLACK_ESCALATIONS_CHANNEL=""
    CONFIG_NETWORK_SET="false"
    CONFIG_START_LANSCAN="false"; CONFIG_START_CAPTURE="false"; CONFIG_WHITELIST=""
    CONFIG_FAIL_ON_WHITELIST="false"; CONFIG_FAIL_ON_BLACKLIST="false"; CONFIG_FAIL_ON_FINDINGS="false"
    CONFIG_CANCEL_ON_VIOLATION="false"; CONFIG_INCLUDE_LOCAL_TRAFFIC="false"
}

# One configure pass: merge over $1, write it back 0600.
run_configure() {
    resolve_service_conf "$1"
    render_service_conf > "$WORK/render.tmp"
    write_service_conf "$WORK/render.tmp" "$1"
}

KEY='edm_live_TESTKEY_0123456789'
CONF="$WORK/edamame_posture.conf"

# --- 1. fresh apt install: packaged conf + --agentic-mode analyze + key ----
cp "$PACKAGED_CONF" "$CONF"
chmod 644 "$CONF"
assert_eq "packaged conf: inline comment is not read as the device id" \
    "$(conf_yaml_value "$CONF" edamame_device_id)" ""
assert_eq "packaged conf: unquoted-with-comment value parsed" \
    "$(conf_yaml_value "$CONF" start_lanscan)" "false"
reset_run
CONFIG_AGENTIC_MODE="analyze"; CONFIG_AGENTIC_MODE_SET="true"
CONFIG_AGENTIC_PROVIDER="edamame"; CONFIG_AGENTIC_PROVIDER_SET="true"
CONFIG_LLM_API_KEY="$KEY"
if service_conf_requested; then ok "agentic request counts as configuration"; else not_ok "agentic request counts as configuration"; fi
run_configure "$CONF"
assert_eq "fresh: agentic_mode persisted" "$(conf_yaml_value "$CONF" agentic_mode)" "analyze"
assert_eq "fresh: agentic_provider persisted" "$(conf_yaml_value "$CONF" agentic_provider)" "edamame"
assert_eq "fresh: llm_api_key persisted" "$(conf_yaml_value "$CONF" llm_api_key)" "$KEY"
assert_eq "fresh: agentic change detected" "$SVC_AGENTIC_CHANGED" "true"
assert_eq "fresh: conf tightened to 0600" "$(file_mode "$CONF")" "600"
assert_eq "fresh: single llm_api_key entry" "$(grep -c '^llm_api_key:' "$CONF")" "1"
assert_eq "fresh: single agentic_mode entry" "$(grep -c '^agentic_mode:' "$CONF")" "1"

# --- 2. same args again: idempotent, untouched, no restart trigger --------
cp "$CONF" "$WORK/before"
touch -t 202001010000 "$CONF"
MTIME_BEFORE="$(file_mtime "$CONF")"
run_configure "$CONF"
assert_eq "re-run same args: no agentic change" "$SVC_AGENTIC_CHANGED" "false"
assert_eq "re-run same args: conf left untouched" "$CONF_CHANGED" "false"
assert_eq "re-run same args: mtime unchanged" "$(file_mtime "$CONF")" "$MTIME_BEFORE"
if cmp -s "$CONF" "$WORK/before"; then ok "re-run same args: byte-identical"; else not_ok "re-run same args: byte-identical"; fi

# --- 3. no args at all: nothing requested, nothing wiped ------------------
reset_run
if service_conf_requested; then not_ok "no-arg run requests nothing"; else ok "no-arg run requests nothing"; fi
run_configure "$CONF"
assert_eq "no-arg run: agentic_mode kept" "$(conf_yaml_value "$CONF" agentic_mode)" "analyze"
assert_eq "no-arg run: key kept" "$(conf_yaml_value "$CONF" llm_api_key)" "$KEY"
assert_eq "no-arg run: no agentic change" "$SVC_AGENTIC_CHANGED" "false"

# --- 4. credentials only: agentic mode and key survive --------------------
reset_run
CONFIG_USER="runner"; CONFIG_DOMAIN="example.com"; CONFIG_PIN="123456"; CONFIG_DEVICE_ID="ci-1"
run_configure "$CONF"
assert_eq "creds-only run: user written" "$(conf_yaml_value "$CONF" edamame_user)" "runner"
assert_eq "creds-only run: agentic_mode kept" "$(conf_yaml_value "$CONF" agentic_mode)" "analyze"
assert_eq "creds-only run: provider kept" "$(conf_yaml_value "$CONF" agentic_provider)" "edamame"
assert_eq "creds-only run: key kept" "$(conf_yaml_value "$CONF" llm_api_key)" "$KEY"
assert_eq "creds-only run: no agentic change" "$SVC_AGENTIC_CHANGED" "false"

# --- 5. agentic-only reconfigure keeps the Hub credentials ----------------
reset_run
CONFIG_AGENTIC_MODE="auto"; CONFIG_AGENTIC_MODE_SET="true"
run_configure "$CONF"
assert_eq "agentic-only run: mode updated" "$(conf_yaml_value "$CONF" agentic_mode)" "auto"
assert_eq "agentic-only run: change detected" "$SVC_AGENTIC_CHANGED" "true"
assert_eq "agentic-only run: user kept" "$(conf_yaml_value "$CONF" edamame_user)" "runner"
assert_eq "agentic-only run: pin kept" "$(conf_yaml_value "$CONF" edamame_pin)" "123456"
assert_eq "agentic-only run: device id kept" "$(conf_yaml_value "$CONF" edamame_device_id)" "ci-1"

# --- 6. provider routing: a Claude key goes to claude_api_key -------------
reset_run
CONFIG_AGENTIC_PROVIDER="claude"; CONFIG_AGENTIC_PROVIDER_SET="true"
CONFIG_LLM_API_KEY="sk-ant-TEST"
run_configure "$CONF"
assert_eq "claude: key in claude slot" "$(conf_yaml_value "$CONF" claude_api_key)" "sk-ant-TEST"
assert_eq "claude: portal slot untouched" "$(conf_yaml_value "$CONF" llm_api_key)" "$KEY"
reset_run
CONFIG_AGENTIC_PROVIDER="none"; CONFIG_AGENTIC_PROVIDER_SET="true"
resolve_service_conf "$CONF"
assert_eq "provider 'none' normalises to empty" "$SVC_AGENTIC_PROVIDER" ""

# --- 7. awkward key: escaping round-trips and stays stable ----------------
AWK_CONF="$WORK/awkward.conf"
AWK_KEY='k\e"y #not-a-comment'
reset_run
CONFIG_AGENTIC_MODE="analyze"; CONFIG_AGENTIC_MODE_SET="true"
CONFIG_LLM_API_KEY="$AWK_KEY"
run_configure "$AWK_CONF"
assert_eq "new conf created 0600" "$(file_mode "$AWK_CONF")" "600"
assert_eq "escaped key reads back" "$(conf_yaml_value "$AWK_CONF" llm_api_key)" "$AWK_KEY"
cp "$AWK_CONF" "$WORK/awk_before"
reset_run
run_configure "$AWK_CONF"
if cmp -s "$AWK_CONF" "$WORK/awk_before"; then ok "escaped key stable across re-runs"; else not_ok "escaped key stable across re-runs"; fi

# --- 8. operator-set notification keys survive a rewrite ------------------
NOTIF_CONF="$WORK/notif.conf"
cp "$PACKAGED_CONF" "$NOTIF_CONF"
sed 's/^notification_telegram_chat_id: ""/notification_telegram_chat_id: "4242"/' "$NOTIF_CONF" > "$NOTIF_CONF.new" && mv "$NOTIF_CONF.new" "$NOTIF_CONF"
reset_run
CONFIG_AGENTIC_MODE="analyze"; CONFIG_AGENTIC_MODE_SET="true"
run_configure "$NOTIF_CONF"
assert_eq "notification key kept" "$(conf_yaml_value "$NOTIF_CONF" notification_telegram_chat_id)" "4242"
if service_conf_agentic_without_credential; then ok "agentic without credential flagged"; else not_ok "agentic without credential flagged"; fi

# --- 9. the daemon wrapper hands mode/provider/key to the binary ----------
STUB="$WORK/edamame_posture_stub"
cat > "$STUB" <<'EOF'
#!/bin/sh
printf 'ARGS:%s\n' "$*"
if [ "${EDAMAME_LLM_API_KEY:-}" = "$EXPECTED_KEY" ]; then echo "ENV_KEY:match"; else echo "ENV_KEY:mismatch"; fi
EOF
chmod +x "$STUB"
reset_run
CONFIG_AGENTIC_MODE="analyze"; CONFIG_AGENTIC_MODE_SET="true"
CONFIG_AGENTIC_PROVIDER="edamame"; CONFIG_AGENTIC_PROVIDER_SET="true"
CONFIG_AGENTIC_INTERVAL="600"; CONFIG_AGENTIC_INTERVAL_SET="true"
CONFIG_LLM_API_KEY="$AWK_KEY"
run_configure "$AWK_CONF"
WRAP_OUT="$(env -u EDAMAME_LLM_API_KEY EXPECTED_KEY="$AWK_KEY" EDAMAME_POSTURE_CONF="$AWK_CONF" \
    EDAMAME_POSTURE_BIN="$STUB" sh "$WRAPPER" 2>&1)"
case "$WRAP_OUT" in
    *"--agentic-mode analyze --agentic-provider edamame --agentic-interval 600"*) ok "wrapper passes agentic args" ;;
    *) not_ok "wrapper passes agentic args: $WRAP_OUT" ;;
esac
case "$WRAP_OUT" in
    *"ENV_KEY:match"*) ok "wrapper exports the exact key to the daemon" ;;
    *) not_ok "wrapper exports the exact key to the daemon" ;;
esac
case "$WRAP_OUT" in
    *"k\\e"*|*"not-a-comment"*) not_ok "wrapper never prints the key" ;;
    *) ok "wrapper never prints the key" ;;
esac

# --- 10. 2.0.2: PIN in the environment, llm_model / llm_base_url, off -------
STUB2="$WORK/edamame_posture_stub2"
cat > "$STUB2" <<'EOF'
#!/bin/sh
printf 'ARGS:%s\n' "$*"
if [ "${EDAMAME_PIN:-}" = "$EXPECTED_PIN" ]; then echo "ENV_PIN:match"; else echo "ENV_PIN:mismatch"; fi
printf 'ENV_MODEL:%s\n' "${EDAMAME_LLM_MODEL:-<unset>}"
printf 'ENV_BASE_URL:%s\n' "${EDAMAME_LLM_BASE_URL:-<unset>}"
EOF
chmod +x "$STUB2"
PIN_CONF="$WORK/pin.conf"
reset_run
CONFIG_USER="runner"; CONFIG_DOMAIN="example.com"; CONFIG_PIN="424242"
CONFIG_AGENTIC_MODE="analyze"; CONFIG_AGENTIC_MODE_SET="true"
CONFIG_AGENTIC_PROVIDER="openai"; CONFIG_AGENTIC_PROVIDER_SET="true"
CONFIG_LLM_API_KEY="sk-TESTKEY"; CONFIG_LLM_MODEL="gpt-test"; CONFIG_LLM_BASE_URL="https://gw.example/v1"
run_configure "$PIN_CONF"
assert_eq "llm_model persisted" "$(conf_yaml_value "$PIN_CONF" llm_model)" "gpt-test"
assert_eq "llm_base_url persisted for openai" "$(conf_yaml_value "$PIN_CONF" llm_base_url)" "https://gw.example/v1"
assert_eq "openai key in openai slot" "$(conf_yaml_value "$PIN_CONF" openai_api_key)" "sk-TESTKEY"
reset_run
run_configure "$PIN_CONF"
assert_eq "no-arg re-run keeps llm_model" "$(conf_yaml_value "$PIN_CONF" llm_model)" "gpt-test"
assert_eq "no-arg re-run keeps llm_base_url" "$(conf_yaml_value "$PIN_CONF" llm_base_url)" "https://gw.example/v1"
assert_eq "no-arg re-run: no agentic change" "$SVC_AGENTIC_CHANGED" "false"
reset_run
CONFIG_LLM_MODEL="gpt-other"
run_configure "$PIN_CONF"
assert_eq "model change is an agentic change" "$SVC_AGENTIC_CHANGED" "true"
WRAP_OUT="$(env -u EDAMAME_PIN -u EDAMAME_LLM_MODEL -u EDAMAME_LLM_BASE_URL EXPECTED_PIN="424242" \
    EDAMAME_POSTURE_CONF="$PIN_CONF" EDAMAME_POSTURE_BIN="$STUB2" sh "$WRAPPER" 2>&1)"
case "$WRAP_OUT" in
    *"--pin"*|*"424242"*) not_ok "wrapper keeps the PIN off argv and out of its output: $WRAP_OUT" ;;
    *) ok "wrapper keeps the PIN off argv and out of its output" ;;
esac
case "$WRAP_OUT" in
    *"ENV_PIN:match"*) ok "wrapper hands the PIN over in EDAMAME_PIN" ;;
    *) not_ok "wrapper hands the PIN over in EDAMAME_PIN: $WRAP_OUT" ;;
esac
case "$WRAP_OUT" in
    *"--user runner --domain example.com"*) ok "wrapper still passes user and domain" ;;
    *) not_ok "wrapper still passes user and domain: $WRAP_OUT" ;;
esac
case "$WRAP_OUT" in
    *"ENV_MODEL:gpt-other"*) ok "wrapper exports llm_model" ;;
    *) not_ok "wrapper exports llm_model: $WRAP_OUT" ;;
esac
case "$WRAP_OUT" in
    *"ENV_BASE_URL:https://gw.example/v1"*) ok "wrapper exports llm_base_url for openai" ;;
    *) not_ok "wrapper exports llm_base_url for openai: $WRAP_OUT" ;;
esac

# A conf written before llm_model / llm_base_url existed (the packaged one,
# which an upgrade never rewrites): the keys read as empty, the wrapper starts
# with the provider defaults.
OLD_CONF="$WORK/old.conf"
cp "$PACKAGED_CONF" "$OLD_CONF"
assert_eq "packaged conf has no llm_model key" "$(grep -c '^llm_model:' "$OLD_CONF")" "0"
sed 's/^agentic_mode: "disabled"/agentic_mode: "analyze"/; s/^openai_api_key: ""/openai_api_key: "sk-OLD"/' "$OLD_CONF" > "$OLD_CONF.new" && mv "$OLD_CONF.new" "$OLD_CONF"
WRAP_OUT="$(env -u EDAMAME_PIN -u EDAMAME_LLM_MODEL -u EDAMAME_LLM_BASE_URL EXPECTED_PIN="" \
    EDAMAME_POSTURE_CONF="$OLD_CONF" EDAMAME_POSTURE_BIN="$STUB2" sh "$WRAPPER" 2>&1)"
case "$WRAP_OUT" in
    *"--agentic-provider openai"*"ENV_MODEL:<unset>"*"ENV_BASE_URL:<unset>"*) ok "missing keys fall back to defaults" ;;
    *) not_ok "missing keys fall back to defaults: $WRAP_OUT" ;;
esac
reset_run
resolve_service_conf "$OLD_CONF"
assert_eq "resolve: missing llm_model reads empty" "$SVC_LLM_MODEL" ""
assert_eq "resolve: missing llm_base_url reads empty" "$SVC_LLM_BASE_URL" ""

# agentic_mode off: passed to the daemon with no provider or credential,
# never flagged as "agentic without credential", never a reason to start one.
OFF_CONF="$WORK/off.conf"
reset_run
CONFIG_AGENTIC_MODE="off"; CONFIG_AGENTIC_MODE_SET="true"
run_configure "$OFF_CONF"
assert_eq "off persisted" "$(conf_yaml_value "$OFF_CONF" agentic_mode)" "off"
if service_conf_agentic_without_credential; then not_ok "off is not agentic-without-credential"; else ok "off is not agentic-without-credential"; fi
if agentic_requested; then not_ok "off does not request a daemon"; else ok "off does not request a daemon"; fi
WRAP_OUT="$(env -u EDAMAME_PIN EXPECTED_PIN="" EDAMAME_POSTURE_CONF="$OFF_CONF" EDAMAME_POSTURE_BIN="$STUB2" sh "$WRAPPER" 2>&1)"
case "$WRAP_OUT" in
    *"--agentic-mode off"*) ok "wrapper passes --agentic-mode off" ;;
    *) not_ok "wrapper passes --agentic-mode off: $WRAP_OUT" ;;
esac
case "$WRAP_OUT" in
    *WARNING*) not_ok "off warns about a missing credential: $WRAP_OUT" ;;
    *) ok "off needs no credential" ;;
esac

# read_pin_file: first line, digits only; warns when group/world readable.
PIN_FILE="$WORK/pin"
printf ' 135790 \nsecond line\n' > "$PIN_FILE"; chmod 600 "$PIN_FILE"
assert_eq "pin file read" "$(read_pin_file "$PIN_FILE" 2>/dev/null)" "135790"
assert_eq "0600 pin file: no warning" "$(read_pin_file "$PIN_FILE" 2>&1 >/dev/null)" ""
chmod 644 "$PIN_FILE"
case "$(read_pin_file "$PIN_FILE" 2>&1 >/dev/null)" in
    *"accessible to other accounts"*) ok "world-readable pin file warns" ;;
    *) not_ok "world-readable pin file warns" ;;
esac
printf 'abc\n' > "$PIN_FILE"
if read_pin_file "$PIN_FILE" >/dev/null 2>&1; then not_ok "non-digit pin file rejected"; else ok "non-digit pin file rejected"; fi
if read_pin_file "$WORK/missing" >/dev/null 2>&1; then not_ok "missing pin file rejected"; else ok "missing pin file rejected"; fi

# --- 11. the installer never prints the key or the PIN --------------------
# Every place install.sh logs a credential-bearing variable would show up as
# an info/warn/error/echo line interpolating one of them.
LEAKS="$(grep -nE '^[[:space:]]*(info|warn|error|echo|printf)[[:space:]].*\$\{?(CONFIG_LLM_API_KEY|SVC_(LLM|CLAUDE|OPENAI)_API_KEY|ESC_[A-Z_]*API_KEY|EDAMAME_LLM_API_KEY|CONFIG_PIN|SVC_PIN|EDAMAME_PIN)' "$INSTALL_SH")"
if [ -z "$LEAKS" ]; then ok "install.sh logs no API key or PIN variable"; else not_ok "install.sh logs an API key or PIN variable: $LEAKS"; fi
# The only allowed --pin on argv is the fallback for a binary that cannot read
# EDAMAME_PIN (pre-2.0.2), guarded by binary_reads_pin_env on the line above.
PIN_ARGV="$(grep -nE -B1 -- '--pin "\$' "$INSTALL_SH" | grep -vE 'binary_reads_pin_env|--$' | grep -E -- '--pin "\$' | grep -vE 'set -- "\$@" --pin "\$CONFIG_PIN"')"
PIN_ARGV_GUARDED="$(grep -nE -B1 -- 'set -- "\$@" --pin "\$CONFIG_PIN"' "$INSTALL_SH" | grep -c 'binary_reads_pin_env')"
if [ -z "$PIN_ARGV" ] && [ "$PIN_ARGV_GUARDED" = "1" ]; then ok "install.sh puts the PIN on a command line only for a binary that cannot read EDAMAME_PIN"; else not_ok "install.sh puts the PIN on a command line: [$PIN_ARGV] guarded=[$PIN_ARGV_GUARDED]"; fi
WRAP_ARGV="$(grep -nE -- '--pin ' "$WRAPPER")"
if [ -z "$WRAP_ARGV" ]; then ok "wrapper never puts the PIN on a command line"; else not_ok "wrapper puts the PIN on a command line: $WRAP_ARGV"; fi

# --- The PIN reaches a pre-2.0.2 binary on argv (2026-09-28 regression) ---
# The posture action runs this raw-main installer against the latest RELEASE.
# A binary without --pin-file ignores EDAMAME_PIN, so it must get --pin.
cat > "$WORK/posture_old" <<'STUB'
#!/bin/sh
printf '%s\n' "Usage: edamame_posture start [OPTIONS]" "  -p, --pin <PIN>  PIN [default: \"\"]"
STUB
cat > "$WORK/posture_new" <<'STUB'
#!/bin/sh
printf '%s\n' "Usage: edamame_posture start [OPTIONS]" "  -p, --pin <PIN>  PIN" "      --pin-file <PATH>  Read the PIN from this file"
STUB
chmod +x "$WORK/posture_old" "$WORK/posture_new"
if binary_reads_pin_env "$WORK/posture_old"; then
    not_ok "a binary without --pin-file is not trusted to read EDAMAME_PIN"
else
    ok "a binary without --pin-file is not trusted to read EDAMAME_PIN"
fi
if binary_reads_pin_env "$WORK/posture_new"; then
    ok "a binary with --pin-file reads EDAMAME_PIN"
else
    not_ok "a binary with --pin-file reads EDAMAME_PIN"
fi
if [ -n "${EDAMAME_POSTURE_OLD_BINARY:-}" ] && [ -x "$EDAMAME_POSTURE_OLD_BINARY" ]; then
    if binary_reads_pin_env "$EDAMAME_POSTURE_OLD_BINARY"; then
        not_ok "the released pre-2.0.2 binary gets the PIN on argv ($EDAMAME_POSTURE_OLD_BINARY)"
    else
        ok "the released pre-2.0.2 binary gets the PIN on argv ($EDAMAME_POSTURE_OLD_BINARY)"
    fi
fi

# --- An upgrade keeps a locally written conf (2.0.1 -> 2.0.2, 2026-09-29) ---
# dpkg's conffile prompt read EOF on a host whose conf an earlier run wrote,
# the upgrade failed, the rollback purged the conf with the credentials in it
# and the binary fallback was verified through dash's stale path cache.
# apt-get and dpkg are stand-in executables first on PATH: dash rejects a
# function named apt-get ("Bad function name"), which stopped this file there.
APT_ARGS_LOG="$WORK/apt_args"
MOCK_BIN="$WORK/mock_bin"
mkdir -p "$MOCK_BIN"
# shellcheck disable=SC2016 # expanded by the stand-ins, not here
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$APT_ARGS_LOG"\n' > "$MOCK_BIN/apt-get"
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$*" in *--purge*) rm -f "$SERVICE_CONF_PATH" ;; esac\nexit 0\n' > "$MOCK_BIN/dpkg"
chmod +x "$MOCK_BIN/apt-get" "$MOCK_BIN/dpkg"
export APT_ARGS_LOG SERVICE_CONF_PATH
SAVED_PATH="$PATH"
PATH="$MOCK_BIN:$PATH"
: > "$APT_ARGS_LOG"
apt_install_posture_package
case "$(cat "$APT_ARGS_LOG")" in
    *"install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold edamame-posture"*)
        ok "the package install keeps a locally modified conf without prompting" ;;
    *) not_ok "the package install keeps a locally modified conf without prompting (got: $(cat "$APT_ARGS_LOG"))" ;;
esac

SERVICE_CONF_PATH="$WORK/rollback.conf"
printf 'edamame_user: "runner"\nedamame_pin: "1234567"\n' > "$SERVICE_CONF_PATH"
chmod 600 "$SERVICE_CONF_PATH"
rollback_broken_deb_package > /dev/null 2>&1
assert_eq "the rollback keeps the conf the purge deleted" \
    "$(cat "$SERVICE_CONF_PATH" 2>/dev/null)" "$(printf 'edamame_user: "runner"\nedamame_pin: "1234567"')"
assert_eq "the kept conf stays 0600" "$(file_mode "$SERVICE_CONF_PATH")" "600"
assert_eq "the rollback leaves no copy behind" \
    "$(find "$WORK" -name 'rollback.conf.rollback.*' | wc -l | tr -d ' ')" "0"
rm -f "$SERVICE_CONF_PATH"
rollback_broken_deb_package > /dev/null 2>&1
if [ -e "$SERVICE_CONF_PATH" ]; then
    not_ok "the rollback creates no conf when there was none"
else
    ok "the rollback creates no conf when there was none"
fi
PATH="$SAVED_PATH"

if command -v dash >/dev/null 2>&1; then
    mkdir -p "$WORK/usr_bin" "$WORK/usr_local_bin"
    printf '#!/bin/sh\necho old\n' > "$WORK/usr_bin/edamame_posture"
    printf '#!/bin/sh\necho new\n' > "$WORK/usr_local_bin/edamame_posture"
    chmod +x "$WORK/usr_bin/edamame_posture" "$WORK/usr_local_bin/edamame_posture"
    resolved=$(PATH="$WORK/usr_bin:$WORK/usr_local_bin:/usr/bin:/bin" dash -c '
        command -v edamame_posture >/dev/null
        rm -f "'"$WORK"'/usr_bin/edamame_posture"
        hash -r 2>/dev/null || true
        command -v edamame_posture')
    assert_eq "dash resolves the binary again after the purged path is gone" \
        "$resolved" "$WORK/usr_local_bin/edamame_posture"
    grep -q '^hash -r 2>/dev/null || true$' "$INSTALL_SH" \
        && ok "the verification clears the shell's command cache" \
        || not_ok "the verification clears the shell's command cache"
fi

# --- macOS installs the PKG only (2.0.3) -----------------------------------
# The raw macOS binary carries the Endpoint Security entitlement without the
# provisioning profile only the PKG's bundle embeds: macOS kills it at launch
# (exit 137, run 36508531168). --force-binary installs the PKG, --debug-build
# the debug PKG, and nothing falls back to a raw binary.
assert_eq "release PKG asset name" "$(macos_pkg_name 2.0.3)" "edamame-posture-macos-2.0.3.pkg"
assert_eq "debug PKG asset name" "$(macos_pkg_name 2.0.3 debug)" "edamame-posture-macos-2.0.3-debug.pkg"
# The posture action passes --debug-build on macOS only to an installer that
# names the debug PKG; keep the string it looks for.
if grep -q -- '-debug.pkg' "$INSTALL_SH"; then
    ok "install.sh carries the -debug.pkg marker the posture action probes"
else
    not_ok "install.sh carries the -debug.pkg marker the posture action probes"
fi

PKG_LOG="$WORK/pkg_calls"
# Stand-ins for what install_macos_via_pkg calls (invoked through it).
# shellcheck disable=SC2329
fetch_latest_release_tag() { LATEST_RELEASE_TAG_PRIMARY="2.0.3"; LATEST_RELEASE_TAG_SECONDARY="2.0.2"; return 0; }
# shellcheck disable=SC2329
download_file() {
    printf 'download %s\n' "$1" >> "$PKG_LOG"
    case "$1" in
        *"${PKG_MISSING:-no-such-asset}"*) return 1 ;;
    esac
    printf 'pkg' > "$2"
}
# shellcheck disable=SC2329
installer() { printf 'installer %s\n' "$*" >> "$PKG_LOG"; return "${INSTALLER_RC:-0}"; }
SUDO=""
reset_pkg() { : > "$PKG_LOG"; INSTALL_METHOD=""; BINARY_PATH=""; PKG_MISSING=""; INSTALLER_RC=0; }

reset_pkg
install_macos_via_pkg debug > /dev/null 2>&1
rc=$?
assert_eq "debug PKG: installs" "$rc" "0"
case "$(cat "$PKG_LOG")" in
    *"download https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v2.0.3/edamame-posture-macos-2.0.3-debug.pkg"*"installer -verboseR -pkg "*" -target /"*)
        ok "debug PKG: the latest release's debug PKG goes to installer" ;;
    *) not_ok "debug PKG: the latest release's debug PKG goes to installer ($(cat "$PKG_LOG"))" ;;
esac
assert_eq "debug PKG: install method" "$INSTALL_METHOD" "pkg"
assert_eq "debug PKG: binary is the bundle link" "$BINARY_PATH" "/usr/local/bin/edamame_posture"

reset_pkg
install_macos_via_pkg > /dev/null 2>&1
case "$(cat "$PKG_LOG")" in
    *"/v2.0.3/edamame-posture-macos-2.0.3.pkg"*) ok "release PKG: the latest release's PKG" ;;
    *) not_ok "release PKG: the latest release's PKG ($(cat "$PKG_LOG"))" ;;
esac
case "$(cat "$PKG_LOG")" in
    *"-debug.pkg"*) not_ok "release PKG: never the debug PKG" ;;
    *) ok "release PKG: never the debug PKG" ;;
esac

reset_pkg
PKG_MISSING="macos-2.0.3-debug.pkg"
install_macos_via_pkg debug > /dev/null 2>&1
case "$(cat "$PKG_LOG")" in
    *"/v2.0.2/edamame-posture-macos-2.0.2-debug.pkg"*) ok "debug PKG missing from the latest release: the previous release's debug PKG" ;;
    *) not_ok "debug PKG missing from the latest release: the previous release's debug PKG ($(cat "$PKG_LOG"))" ;;
esac

reset_pkg
PKG_MISSING="edamame-posture-macos-"
if install_macos_via_pkg debug > /dev/null 2>&1; then
    not_ok "no debug PKG anywhere: the install fails"
else
    ok "no debug PKG anywhere: the install fails"
fi
case "$(cat "$PKG_LOG")" in
    *universal-apple-darwin*|*"installer "*) not_ok "no debug PKG anywhere: no raw binary, no installer run ($(cat "$PKG_LOG"))" ;;
    *) ok "no debug PKG anywhere: no raw binary, no installer run" ;;
esac

reset_pkg
INSTALLER_RC=1
if install_macos_via_pkg > /dev/null 2>&1; then
    not_ok "a failing installer is a failed install"
else
    ok "a failing installer is a failed install"
fi
assert_eq "a failing installer sets no install method" "$INSTALL_METHOD" ""

# There is no raw macOS binary to prepare: asking for one stops with a reason.
PREP_OUT="$( (prepare_binary_artifact macos "") 2>&1)"
PREP_RC=$?
if [ "$PREP_RC" -ne 0 ] && printf '%s' "$PREP_OUT" | grep -q "PKG only"; then
    ok "no raw macOS binary: prepare_binary_artifact refuses with a reason"
else
    not_ok "no raw macOS binary: prepare_binary_artifact refuses with a reason (rc=$PREP_RC: $PREP_OUT)"
fi
FAIL_OUT="$( (macos_install_failed "the debug PKG (--debug-build)") 2>&1)"
FAIL_RC=$?
case "$FAIL_RC:$FAIL_OUT" in
    1:*"Could not install the debug PKG (--debug-build) on macOS"*"provisioning profile"*) ok "a failed macOS install explains why there is no binary fallback" ;;
    *) not_ok "a failed macOS install explains why there is no binary fallback (rc=$FAIL_RC: $FAIL_OUT)" ;;
esac
unset -f fetch_latest_release_tag download_file installer

# Only the PKG's bundle binary, or the /usr/local/bin link to it, is the PKG.
MACOS_PKG_BINARY="$WORK/bundle/edamame_posture"
mkdir -p "$WORK/bundle" "$WORK/bin"
printf '#!/bin/sh\n' > "$MACOS_PKG_BINARY"; chmod +x "$MACOS_PKG_BINARY"
ln -s "$MACOS_PKG_BINARY" "$WORK/bin/edamame_posture"
printf '#!/bin/sh\n' > "$WORK/bin/edamame_posture_raw"
if macos_binary_is_from_pkg "$WORK/bin/edamame_posture"; then ok "the /usr/local/bin link into the bundle is the PKG"; else not_ok "the /usr/local/bin link into the bundle is the PKG"; fi
if macos_binary_is_from_pkg "$MACOS_PKG_BINARY"; then ok "the bundle binary is the PKG"; else not_ok "the bundle binary is the PKG"; fi
if macos_binary_is_from_pkg "$WORK/bin/edamame_posture_raw"; then not_ok "a raw binary is not the PKG"; else ok "a raw binary is not the PKG"; fi
rm -f "$MACOS_PKG_BINARY"
if macos_binary_is_from_pkg "$WORK/bin/edamame_posture"; then not_ok "a dangling link is not the PKG"; else ok "a dangling link is not the PKG"; fi

# --- No fallback version (2.0.3) -------------------------------------------
# When the latest release could not be determined, a binary install used to
# install a hardcoded 1.3.18 behind a warning (and did the same when the
# latest release's binary would not download). It now stops and names what
# did not answer. A stand-in curl first on PATH plays GitHub: the releases/
# latest redirect (MOCK_REDIRECT: 302:<tag>, an HTTP status, or 000 for no
# network), the API (MOCK_API: ok, a status, 000) and the release downloads,
# which answer for any version except those in MOCK_MISSING -- 1.3.18
# included, so an install of it would show.
# The stand-ins above replaced some installer functions: load them again.
# shellcheck disable=SC1090
EDAMAME_INSTALL_SH_LIB=1 . "$INSTALL_SH"
set +e
NET_BIN="$WORK/net_bin"
MOCK_LOG="$WORK/net_calls"
mkdir -p "$NET_BIN"
cat > "$NET_BIN/curl" <<'STUB'
#!/bin/sh
# Stand-in curl for install.sh's GitHub calls.
url=""; out=""; fmt=""; fail=false
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -w) fmt="$2"; shift 2 ;;
        -H|--connect-timeout|--max-time|--proto) shift 2 ;;
        --*) shift ;;
        -*) case "$1" in *f*) fail=true ;; esac; shift ;;
        *) url="$1"; shift ;;
    esac
done
echo "curl $url" >> "$MOCK_LOG"
status=""; body=""; location=""
case "$url" in
    https://github.com/*/releases/latest)
        case "$MOCK_REDIRECT" in
            302:*) status=302; location="https://github.com/edamametechnologies/edamame_posture_cli/releases/tag/${MOCK_REDIRECT#302:}" ;;
            *) status="$MOCK_REDIRECT" ;;
        esac ;;
    https://api.github.com/*)
        status="$MOCK_API"
        [ "$status" = "ok" ] && { status=200; body='[
  {
    "tag_name": "v2.0.3",
    "name": "Release v2.0.3"
  },
  {
    "tag_name": "v2.0.2",
    "name": "Release v2.0.2"
  }
]'; } ;;
    https://github.com/*/releases/download/v*)
        version="${url#*/releases/download/v}"; version="${version%%/*}"
        status=200
        for missing in $MOCK_MISSING; do
            [ "$missing" = "$version" ] && status=404
        done
        [ "$status" = 200 ] && body="$(printf '#!/bin/sh\necho "edamame_posture %s"' "$version")" ;;
    *) status=000 ;;
esac
if [ "$status" = "000" ]; then
    [ -n "$fmt" ] && printf '000'
    exit 6
fi
if [ -n "$location" ] || [ -z "$body" ]; then
    headers="$(printf 'HTTP/2 %s\r\n' "$status")"
    [ -n "$location" ] && headers="$(printf '%s\nlocation: %s\r' "$headers" "$location")"
    [ -n "$out" ] && printf '%s\n' "$headers" > "$out"
fi
if [ "$fail" = true ] && [ "$status" -ge 400 ]; then
    exit 22
fi
if [ -n "$body" ]; then
    if [ -n "$out" ]; then printf '%s\n' "$body" > "$out"; else printf '%s\n' "$body"; fi
fi
[ -n "$fmt" ] && printf '%s' "$status"
exit 0
STUB
chmod +x "$NET_BIN/curl"
export MOCK_LOG MOCK_REDIRECT MOCK_API MOCK_MISSING
NET_SAVED_PATH="$PATH"
PATH="$NET_BIN:$PATH"

# One binary install (or a macOS PKG install) in a subshell: an `error` exits
# only the subshell. NET_RC is its exit status, NET_OUT its output.
net_run() {
    : > "$MOCK_LOG"
    rm -rf "$WORK/net_inst"
    mkdir -p "$WORK/net_inst"
    NET_OUT="$(
        INSTALL_DIR="$WORK/net_inst"; PLATFORM=linux; LINUX_ARCH_NORMALIZED=x86_64
        CONFIG_DEBUG_BUILD=false; SUDO=""; INSTALL_METHOD=""; GITHUB_TOKEN=""
        LATEST_RELEASE_TAG_PRIMARY=""; LATEST_RELEASE_TAG_SECONDARY=""; GITHUB_RELEASES_RESPONSE=""
        "$@"
        rc=$?
        printf 'RC=%s BINARY_INSTALL_ERROR=%s MACOS_PKG_ERROR=%s\n' "$rc" "${BINARY_INSTALL_ERROR:-}" "${MACOS_PKG_ERROR:-}"
        exit "$rc"
    )"
    NET_RC=$?
}
downloads() { grep -c '/releases/download/' "$MOCK_LOG"; }
installed_version() { sh "$WORK/net_inst/edamame_posture" 2>/dev/null; }

MOCK_REDIRECT="302:v2.0.3"; MOCK_API=ok; MOCK_MISSING=""
net_run install_binary_release linux gnu
assert_eq "latest release: installs" "$NET_RC" "0"
assert_eq "latest release: the latest binary" "$(installed_version)" "edamame_posture 2.0.3"

MOCK_REDIRECT="302:v2.0.3"; MOCK_API=403; MOCK_MISSING=""
net_run install_binary_release linux gnu
assert_eq "API refused (403), the redirect answers: installs the latest" "$(installed_version)" "edamame_posture 2.0.3"

MOCK_REDIRECT="302:v2.0.3"; MOCK_API=ok; MOCK_MISSING="2.0.3"
net_run install_binary_release linux gnu
assert_eq "latest binary missing (404), the API named the previous release: installs it" "$(installed_version)" "edamame_posture 2.0.2"

for case_spec in "404:404:answered HTTP 404" "403:403:answered HTTP 403" "000:000:did not answer (no network, or a proxy or firewall refused the connection)"; do
    MOCK_REDIRECT="${case_spec%%:*}"; rest="${case_spec#*:}"; MOCK_API="${rest%%:*}"; want="${rest#*:}"; MOCK_MISSING=""
    net_run install_binary_release linux gnu
    assert_eq "lookup $MOCK_REDIRECT: the install stops" "$NET_RC" "1"
    case "$NET_OUT" in
        *"[ERROR]"*"Could not determine the latest EDAMAME Posture release: https://github.com/edamametechnologies/edamame_posture_cli/releases/latest ${want}, and the GitHub API (api.github.com) returned no release."*"no option to pin a version"*"/releases."*)
            ok "lookup $MOCK_REDIRECT: the message names what did not answer" ;;
        *) not_ok "lookup $MOCK_REDIRECT: the message names what did not answer: $NET_OUT" ;;
    esac
    assert_eq "lookup $MOCK_REDIRECT: no download, 1.3.18 or other" "$(downloads)" "0"
    assert_eq "lookup $MOCK_REDIRECT: nothing installed" "$(installed_version)" ""
done
case "$(cat "$MOCK_LOG")" in
    *"curl https://github.com/edamametechnologies/edamame_posture_cli/releases/latest"*"curl https://api.github.com/repos/edamametechnologies/edamame_posture_cli/releases"*) ok "the lookup tried the redirect and the API" ;;
    *) not_ok "the lookup tried the redirect and the API: $(cat "$MOCK_LOG")" ;;
esac

# The regression itself: the lookup does not answer while the downloads
# would, 1.3.18 included. The old installer installed 1.3.18 with exit 0.
MOCK_REDIRECT="000"; MOCK_API="000"; MOCK_MISSING=""
net_run install_binary_release linux gnu
assert_eq "no lookup, downloads available: the install stops" "$NET_RC" "1"
if grep -q '1\.3\.18' "$MOCK_LOG"; then not_ok "no lookup: 1.3.18 is never fetched"; else ok "no lookup: 1.3.18 is never fetched"; fi

MOCK_REDIRECT="302:v2.0.3"; MOCK_API=403; MOCK_MISSING="2.0.3"
net_run install_binary_release linux gnu
assert_eq "latest binary missing, no previous release known: the install stops" "$NET_RC" "1"
case "$NET_OUT" in
    *"[ERROR]"*"Failed to download EDAMAME Posture 2.0.3 from https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v2.0.3/edamame_posture-2.0.3-x86_64-unknown-linux-gnu."*)
        ok "latest binary missing: the message names the URL" ;;
    *) not_ok "latest binary missing: the message names the URL: $NET_OUT" ;;
esac
if grep -q '1\.3\.18' "$MOCK_LOG"; then not_ok "latest binary missing: 1.3.18 is never fetched"; else ok "latest binary missing: 1.3.18 is never fetched"; fi

MOCK_REDIRECT="302:v2.0.3"; MOCK_API=ok; MOCK_MISSING="2.0.3 2.0.2"
net_run install_binary_release linux gnu
case "$NET_RC:$NET_OUT" in
    1:*"Failed to download EDAMAME Posture 2.0.3 from "*", or the previous release from https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v2.0.2/"*)
        ok "latest and previous binaries missing: stops naming both URLs" ;;
    *) not_ok "latest and previous binaries missing: stops naming both URLs (rc=$NET_RC): $NET_OUT" ;;
esac

# Windows falls back to Chocolatey, which needs no version: the binary step
# warns and returns 1 instead of stopping the installer.
MOCK_REDIRECT="000"; MOCK_API="000"; MOCK_MISSING=""
net_run install_binary_release windows "" fallback
case "$NET_RC:$NET_OUT" in
    1:*"[WARN]"*"Could not determine the latest EDAMAME Posture release"*"RC=1 BINARY_INSTALL_ERROR=Could not determine the latest EDAMAME Posture release"*)
        ok "fallback mode: warns and returns 1 for the package manager to try" ;;
    *) not_ok "fallback mode: warns and returns 1 for the package manager to try (rc=$NET_RC): $NET_OUT" ;;
esac
case "$NET_OUT" in
    *"[ERROR]"*) not_ok "fallback mode: no [ERROR]" ;;
    *) ok "fallback mode: no [ERROR]" ;;
esac

# Keeping an installed binary needs no version: the lookup failure is
# reported to the caller, which does not stop.
net_run prepare_binary_artifact linux gnu
case "$NET_RC:$NET_OUT" in
    1:*"RC=1 "*) ok "prepare_binary_artifact returns 1 on a failed lookup, without stopping" ;;
    *) not_ok "prepare_binary_artifact returns 1 on a failed lookup, without stopping (rc=$NET_RC): $NET_OUT" ;;
esac

# The macOS PKG: the same lookup failure is named, and no PKG of an older
# hardcoded release is tried.
# shellcheck disable=SC2329 # invoked by install_macos_via_pkg
installer() { printf 'installer %s\n' "$*" >> "$MOCK_LOG"; return 0; }
MOCK_REDIRECT="403"; MOCK_API="403"; MOCK_MISSING=""
net_run install_macos_via_pkg
case "$NET_RC:$NET_OUT" in
    1:*"MACOS_PKG_ERROR=Could not determine the latest EDAMAME Posture release: https://github.com/edamametechnologies/edamame_posture_cli/releases/latest answered HTTP 403"*)
        ok "macOS PKG: a failed lookup is named" ;;
    *) not_ok "macOS PKG: a failed lookup is named (rc=$NET_RC): $NET_OUT" ;;
esac
MOCK_REDIRECT="302:v2.0.3"; MOCK_API=403; MOCK_MISSING="2.0.3"
net_run install_macos_via_pkg
case "$NET_RC:$(downloads):$NET_OUT" in
    1:1:*"MACOS_PKG_ERROR=No .pkg could be downloaded (tried https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v2.0.3/edamame-posture-macos-2.0.3.pkg)."*)
        ok "macOS PKG: only the latest release's PKG is tried when no previous one is known" ;;
    *) not_ok "macOS PKG: only the latest release's PKG is tried when no previous one is known (rc=$NET_RC): $(cat "$MOCK_LOG") $NET_OUT" ;;
esac
# --- The release digest parser is POSIX awk (2.0.3) -------------------------
# get_asset_digest_from_json runs here under every awk found (awk, gawk,
# mawk, busybox awk, original-awk), on the real v2.0.2 release JSON in
# fixtures/, pretty-printed and compact.
FIXTURES="$REPO_ROOT/tests/installer/fixtures"
REAL_JSON="$(cat "$FIXTURES/release-v2.0.2-excerpt.json")"
COMPACT_JSON="$(printf '%s' "$REAL_JSON" | tr -d '\n' | sed 's/:  */:/g; s/,  */,/g; s/{  */{/g; s/\[  */[/g; s/  *}/}/g; s/  *]/]/g')"
AWK_SHIMS="$WORK/awk_shims"
AWK_SAVED_PATH="$PATH"
awk_count=0
for impl in awk gawk mawk "busybox awk" original-awk nawk; do
    # shellcheck disable=SC2086 # "busybox awk" is two words
    set -- $impl
    command -v "$1" >/dev/null 2>&1 || continue
    [ "$impl" = "busybox awk" ] && { busybox awk 'BEGIN{}' 2>/dev/null || continue; }
    shim="$AWK_SHIMS/$(printf '%s' "$impl" | tr ' ' '_')"
    mkdir -p "$shim"
    printf '#!/bin/sh\nexec %s %s "$@"\n' "$(command -v "$1")" "${2:-}" > "$shim/awk"
    chmod +x "$shim/awk"
    PATH="$shim:$AWK_SAVED_PATH"
    awk_count=$((awk_count + 1))
    for json_label in pretty compact; do
        json="$REAL_JSON"; [ "$json_label" = compact ] && json="$COMPACT_JSON"
        assert_eq "$impl, $json_label v2.0.2 JSON: the linux-gnu digest" \
            "$(get_asset_digest_from_json "$json" edamame_posture-2.0.2-x86_64-unknown-linux-gnu)" \
            "fd301bbbcbd53736a0005753039e414e86589642c5547a52b54cd48ccce3d5e3"
        assert_eq "$impl, $json_label v2.0.2 JSON: its -debug sibling is another asset" \
            "$(get_asset_digest_from_json "$json" edamame_posture-2.0.2-x86_64-unknown-linux-gnu-debug)" \
            "b1e48d8f92815734e3659e30ff81d9f6c31af30c35a66a2708c133f04785a2cf"
        assert_eq "$impl, $json_label v2.0.2 JSON: the PKG digest" \
            "$(get_asset_digest_from_json "$json" edamame-posture-macos-2.0.2.pkg)" \
            "0f09ae4118d5671aa720d1b46ea9016e6d4d06d541910f742a789fc8d1ab6277"
        if get_asset_digest_from_json "$json" edamame_posture-2.0.2-no-such-target >/dev/null; then
            not_ok "$impl, $json_label v2.0.2 JSON: an unlisted asset has no digest"
        else
            ok "$impl, $json_label v2.0.2 JSON: an unlisted asset has no digest"
        fi
    done
done
PATH="$AWK_SAVED_PATH"
if [ "$awk_count" -ge 1 ]; then ok "the digest parser ran under $awk_count awk implementation(s)"; else not_ok "no awk found for the digest parser"; fi


unset -f installer
PATH="$NET_SAVED_PATH"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
