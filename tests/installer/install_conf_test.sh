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
    CONFIG_LLM_API_KEY=""; CONFIG_LLM_BASE_URL=""
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

# --- 10. the installer never prints the key -------------------------------
# Every place install.sh logs a credential-bearing variable would show up as
# an info/warn/error/echo line interpolating one of them.
LEAKS="$(grep -nE '^[[:space:]]*(info|warn|error|echo|printf)[[:space:]].*\$\{?(CONFIG_LLM_API_KEY|SVC_(LLM|CLAUDE|OPENAI)_API_KEY|ESC_[A-Z_]*API_KEY|EDAMAME_LLM_API_KEY)' "$INSTALL_SH")"
if [ -z "$LEAKS" ]; then ok "install.sh logs no API key variable"; else not_ok "install.sh logs an API key variable: $LEAKS"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
