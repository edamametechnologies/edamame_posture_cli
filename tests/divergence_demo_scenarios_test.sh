#!/bin/bash
set -eo pipefail

# Scripted integration test for 4 executive demo divergence scenarios.
# This intentionally avoids MCP and drives everything through edamame_posture CLI.

scenario1_result="PENDING"
scenario2_result="PENDING"
scenario3_result="PENDING"
scenario4_result="PENDING"

INJECT_PIDS=()
TMP_DIR=""

cleanup() {
    local exit_status=$?

    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" || true
    fi

    for pid in "${INJECT_PIDS[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done

    if [[ -n "${SUDO_CMD:-}" ]]; then
        $SUDO_CMD "$BINARY_PATH" divergence-stop >/dev/null 2>&1 || true
        $SUDO_CMD "$BINARY_PATH" divergence-clear-model >/dev/null 2>&1 || true
        $SUDO_CMD "$BINARY_PATH" stop >/dev/null 2>&1 || true
    else
        "$BINARY_PATH" divergence-stop >/dev/null 2>&1 || true
        "$BINARY_PATH" divergence-clear-model >/dev/null 2>&1 || true
        "$BINARY_PATH" stop >/dev/null 2>&1 || true
    fi

    echo ""
    echo "--- Divergence Demo Scenario Test Summary ---"
    echo "  Scenario 1 (CVE-2026-24763 / tmp lineage): $scenario1_result"
    echo "  Scenario 2 (VirusTotal class / credential exfil): $scenario2_result"
    echo "  Scenario 3 (CVE-2026-25253 / token exfil): $scenario3_result"
    echo "  Scenario 4 (STRIKE class / exposed gateway binding): $scenario4_result"
    if [[ $exit_status -eq 0 ]]; then
        echo "Result: PASS"
    else
        echo "Result: FAIL (exit code: $exit_status)"
    fi
}

trap cleanup EXIT

run_posture() {
    if [[ -n "$SUDO_CMD" ]]; then
        $SUDO_CMD "$BINARY_PATH" "$@"
    else
        "$BINARY_PATH" "$@"
    fi
}

stop_active_injections() {
    for pid in "${INJECT_PIDS[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    INJECT_PIDS=()
    sleep 3
}

wait_for_background_ready() {
    local attempts=12
    local i=0
    while [[ $i -lt $attempts ]]; do
        if run_posture status >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
        i=$((i + 1))
    done
    return 1
}

get_verdict_json() {
    run_posture divergence-get-verdict 2>/dev/null || echo "{}"
}

get_verdict_timestamp() {
    local verdict_json="$1"
    python3 -c '
import json
import sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
ts = data.get("timestamp", "") if isinstance(data, dict) else ""
print(ts if isinstance(ts, str) else "")
' <<<"$verdict_json"
}

poll_for_new_divergence() {
    local scenario_name="$1"
    local previous_ts="$2"
    local timeout_secs="${3:-240}"
    local step_secs=10
    local elapsed=0
    local latest_json="{}"

    echo "Waiting for divergence verdict for $scenario_name (timeout=${timeout_secs}s)..."

    while [[ $elapsed -lt $timeout_secs ]]; do
        latest_json="$(get_verdict_json)"

        local match
        match="$(
            python3 - "$previous_ts" "$latest_json" <<'PY'
import json
import sys

previous = sys.argv[1]
raw = sys.argv[2]
try:
    data = json.loads(raw)
except Exception:
    print("NO_MATCH")
    raise SystemExit(0)

if not isinstance(data, dict):
    print("NO_MATCH")
    raise SystemExit(0)

ts = data.get("timestamp")
verdict = data.get("verdict")
normalized_verdict = verdict.lower() if isinstance(verdict, str) else ""
if isinstance(ts, str) and ts and ts != previous and normalized_verdict == "divergence":
    print("MATCH")
else:
    print("NO_MATCH")
PY
        )"

        if [[ "$match" == "MATCH" ]]; then
            echo "Divergence detected for $scenario_name."
            return 0
        fi

        sleep "$step_secs"
        elapsed=$((elapsed + step_secs))
    done

    echo "Timed out waiting for divergence in $scenario_name."
    echo "Latest verdict payload:"
    echo "$latest_json"
    return 1
}

start_tmp_lineage_injection() {
    local script_path="$TMP_DIR/inject_tmp_lineage.sh"
    cat > "$script_path" <<'EOF'
#!/bin/bash
while true; do
  curl -s -o /dev/null -m 5 https://1.0.0.1 2>/dev/null || true
  sleep 3
done
EOF
    chmod +x "$script_path"
    nohup "$script_path" >/dev/null 2>&1 &
    INJECT_PIDS+=("$!")
}

start_credential_exfil_injection() {
    local cred_file="$HOME/.ssh/divergence_demo_cred"
    mkdir -p "$HOME/.ssh"
    echo "demo-credential-sentinel" > "$cred_file"

    nohup python3 - <<'PY' >/dev/null 2>&1 &
import os
import ssl
import socket
import time

cred = os.path.expanduser("~/.ssh/divergence_demo_cred")
while True:
    try:
        with open(cred, "r", encoding="utf-8") as _:
            pass
        ctx = ssl.create_default_context()
        sock = socket.create_connection(("1.1.1.1", 443), timeout=8)
        tls = ctx.wrap_socket(sock, server_hostname="one.one.one.one")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        tls.recv(1024)
        tls.close()
    except Exception:
        pass
    time.sleep(5)
PY
    INJECT_PIDS+=("$!")
}

start_token_exfil_injection() {
    local token_file="$HOME/.edamame_psk"
    local marker_file="$HOME/.ssh/exec_demo_exfil_token"
    mkdir -p "$HOME/.ssh"
    echo "demo-gateway-token" > "$token_file"
    echo "demo-token-marker" > "$marker_file"

    nohup python3 - <<'PY' >/dev/null 2>&1 &
import os
import ssl
import socket
import time

files = [os.path.expanduser("~/.edamame_psk"), os.path.expanduser("~/.ssh/exec_demo_exfil_token")]
while True:
    try:
        for path in files:
            with open(path, "r", encoding="utf-8") as _:
                pass
        ctx = ssl.create_default_context()
        sock = socket.create_connection(("1.0.0.1", 443), timeout=8)
        tls = ctx.wrap_socket(sock, server_hostname="one.one.one.one")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        tls.recv(1024)
        tls.close()
    except Exception:
        pass
    time.sleep(5)
PY
    INJECT_PIDS+=("$!")
}

start_gateway_exposure_injection() {
    nohup python3 -m http.server 18789 --bind 0.0.0.0 >/dev/null 2>&1 &
    INJECT_PIDS+=("$!")

    nohup bash -c 'while true; do curl -s -o /dev/null -m 5 https://1.0.0.1 2>/dev/null || true; sleep 3; done' >/dev/null 2>&1 &
    INJECT_PIDS+=("$!")
}

echo "--- Running divergence demo scenarios test (CLI only, no MCP) ---"

FOUND_BINARY="$(find ./target -type f \( -name edamame_posture -o -name edamame_posture.exe \) -print -quit 2>/dev/null)"
if [[ -z "$FOUND_BINARY" ]]; then
    echo "Error: edamame_posture binary not found under ./target"
    exit 1
fi

BINARY_PATH="${BINARY_PATH:-$FOUND_BINARY}"
RUNNER_OS="${RUNNER_OS:-$(uname)}"
SUDO_CMD="${SUDO_CMD:-sudo -E}"

if [[ "$RUNNER_OS" == "windows" || "$OS" == "Windows_NT" || "$OS" == "MINGW"* || "$OS" == "CYGWIN"* ]]; then
    echo "This test is only supported on Linux/macOS currently."
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    SUDO_CMD=""
fi

TMP_DIR="$(mktemp -d)"
MODEL_FILE="$TMP_DIR/behavioral_model.json"

echo "Using binary: $BINARY_PATH"
echo "Using temporary directory: $TMP_DIR"

echo "Stopping any existing background posture process..."
run_posture stop >/dev/null 2>&1 || true
sleep 2

echo "Starting posture background process (disconnected, with scan + capture)..."
set +e
start_output="$(run_posture background-start-disconnected --network-scan --packet-capture --agentic-mode disabled 2>&1)"
start_exit=$?
set -e
if [[ $start_exit -ne 0 ]]; then
    if [[ "$start_output" == *"Core services are already running."* ]]; then
        echo "Background core already running, reusing existing service."
    else
        echo "$start_output"
        echo "Failed to start background posture process."
        exit 1
    fi
fi

if ! wait_for_background_ready; then
    echo "Background posture process did not become ready."
    exit 1
fi

echo "Preparing baseline behavioral model..."
python3 - "$MODEL_FILE" <<'PY'
import datetime
import json
import sys

out_path = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
end = now + datetime.timedelta(minutes=20)
model = {
    "window_start": now.isoformat().replace("+00:00", "Z"),
    "window_end": end.isoformat().replace("+00:00", "Z"),
    "predictions": [
        {
            "session_key": "demo-baseline-001",
            "action": "Routine posture checks",
            "tools_called": ["get_score", "get_sessions"],
            "expected_traffic": ["api.openai.com:443"],
            "expected_sensitive_files": [],
            "expected_lan_devices": [],
            "expected_local_open_ports": [],
            "expected_process_paths": [],
            "expected_parent_paths": [],
            "expected_open_files": [],
            "expected_l7_protocols": [],
            "expected_system_config": [],
            "not_expected_traffic": ["1.0.0.1:443", "1.1.1.1:443"],
            "not_expected_sensitive_files": ["~/.ssh/", "~/.edamame_psk"],
            "not_expected_lan_devices": [],
            "not_expected_local_open_ports": [18789],
            "not_expected_process_paths": ["/tmp/", "/var/tmp/", "/dev/shm/"],
            "not_expected_parent_paths": ["/tmp/", "/var/tmp/", "/dev/shm/"],
            "not_expected_open_files": ["~/.ssh/", "~/.edamame_psk"],
            "not_expected_l7_protocols": [],
            "not_expected_system_config": []
        }
    ],
    "version": "3.0",
    "hash": "",
    "ingested_at": now.isoformat().replace("+00:00", "Z")
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(model, f)
PY

run_posture divergence-clear-model >/dev/null 2>&1 || true
run_posture divergence-upsert-model-from-file "$MODEL_FILE"
run_posture divergence-start 30

echo "Waiting for model settling window..."
sleep 70

prev_json="$(get_verdict_json)"
prev_ts="$(get_verdict_timestamp "$prev_json")"

echo "Scenario 1: CVE-2026-24763 lineage mismatch (/tmp spawn)"
stop_active_injections
start_tmp_lineage_injection
sleep 20
if poll_for_new_divergence "scenario1-cve-2026-24763" "$prev_ts" 240; then
    scenario1_result="PASS"
else
    scenario1_result="FAIL"
    exit 1
fi
stop_active_injections
prev_json="$(get_verdict_json)"
prev_ts="$(get_verdict_timestamp "$prev_json")"

echo "Scenario 2: VirusTotal class credential exfil"
stop_active_injections
start_credential_exfil_injection
sleep 20
if poll_for_new_divergence "scenario2-credential-exfil" "$prev_ts" 240; then
    scenario2_result="PASS"
else
    scenario2_result="FAIL"
    exit 1
fi
stop_active_injections
prev_json="$(get_verdict_json)"
prev_ts="$(get_verdict_timestamp "$prev_json")"

echo "Scenario 3: CVE-2026-25253 token exfil"
stop_active_injections
start_token_exfil_injection
sleep 20
if poll_for_new_divergence "scenario3-cve-2026-25253" "$prev_ts" 240; then
    scenario3_result="PASS"
else
    scenario3_result="FAIL"
    exit 1
fi
stop_active_injections
prev_json="$(get_verdict_json)"
prev_ts="$(get_verdict_timestamp "$prev_json")"

echo "Scenario 4: STRIKE class gateway exposure (0.0.0.0 bind)"
stop_active_injections
start_gateway_exposure_injection
sleep 20
if poll_for_new_divergence "scenario4-strike-gateway-exposure" "$prev_ts" 300; then
    scenario4_result="PASS"
else
    scenario4_result="FAIL"
    exit 1
fi
stop_active_injections

echo "All 4 divergence demo scenarios detected as DIVERGENCE."
