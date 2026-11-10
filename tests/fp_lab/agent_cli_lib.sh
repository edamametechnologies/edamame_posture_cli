# agent_cli_lib.sh -- bash functions deploy_owned_posture.sh (Linux) and
# deploy_owned_posture_macos.sh ship to the lab host in front of their remote
# scripts, after the pins of agent_versions.env (CLAUDE_CODE_NPM_VERSION,
# CODEX_NPM_VERSION). Nothing runs at load; bash 3.2 (macOS) is enough. The
# Windows leg has the same functions in PowerShell (PS_LIB).

# agent_versions: path and version of each lab agent CLI on the lab PATH,
# beside its pin (what `record` and the summary read).
agent_versions() {
  for pair in "claude:$CLAUDE_CODE_NPM_VERSION" "codex:$CODEX_NPM_VERSION"; do
    t=${pair%%:*}; pin=${pair#*:}
    if command -v "$t" >/dev/null 2>&1; then
      echo "$t: $(command -v "$t") version: $("$t" --version 2>&1 | head -n 1) (pin $pin)"
    else
      echo "$t: not installed (pin $pin)"
    fi
  done
}

# npm_user_prefix: the user-level npm prefix every pinned CLI goes to; its
# bin directory is the first entry of the lab PATH, so a Homebrew or native
# install of the same CLI elsewhere is shadowed for the window, never
# upgraded or removed (it is the host's own).
npm_user_prefix() {
  [ "$(npm config get prefix 2>/dev/null)" = "$HOME/.npm-global" ] || npm config set prefix "$HOME/.npm-global"
  echo "$HOME/.npm-global"
}

# npm_install_pin <bin> <package> <version>: install exactly that version
# into the user prefix unless it already answers there.
npm_install_pin() {
  bin="$1"; pkg="$2"; pin="$3"
  prefix=$(npm_user_prefix)
  have=$("$prefix/bin/$bin" --version 2>/dev/null | head -n 1)
  case "$have" in
    *"$pin"*) echo "$bin $pin already installed ($prefix/bin/$bin)"; return 0 ;;
  esac
  echo "installing $pkg@$pin into $prefix"
  npm install -g "$pkg@$pin" 2>&1 | tail -n 2
  "$prefix/bin/$bin" --version 2>/dev/null | head -n 1 | grep -q "$pin" \
    || { echo "$bin: $pkg@$pin did not install"; return 1; }
}

# verify_agent_pins: the CLIs the lab PATH resolves answer with the pinned
# versions (another install first on PATH would drive the window instead).
verify_agent_pins() {
  rc=0
  for pair in "claude:$CLAUDE_CODE_NPM_VERSION" "codex:$CODEX_NPM_VERSION"; do
    t=${pair%%:*}; pin=${pair#*:}
    v=$("$t" --version 2>&1 | head -n 1)
    case "$v" in *"$pin"*) ;; *) echo "$t on PATH answers '$v', not the pin $pin"; rc=1 ;; esac
  done
  return $rc
}

# with_timeout <secs> <command...>: coreutils timeout where it exists (Linux,
# Homebrew coreutils), else a pending alarm that survives exec (perl ships
# with macOS). The command's own status, 124 / 142 when it ran out of time.
with_timeout() {
  secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else perl -e 'alarm shift @ARGV; exec @ARGV' "$secs" "$@"; fi
}

# probe_one <claude|codex> <dir>: one non-interactive turn in <dir>, launched
# the way the lab launches the CLI for a case, so the probe fails where the
# cases would and nowhere else: the command line and environment of
# tests/e2e/agent_harness.py (drive_claude_code, drive_codex), the arguments
# run_fp_lab.py's drive_agent_case adds to a first request (--output-format
# json and its default --model sonnet for Claude Code), and only the agent's
# own credential, as the runner's provider_env leaves it. A probe that ran
# the CLIs its own way reported a failure the cases did not have: Codex
# without CODEX_API_KEY took the stored ChatGPT login or sent no credential
# and answered 401 on two hosts while every Codex case passed (2026-11-10).
# Runs in a subshell: the keys of the owner-only providers.env live there
# only and are never printed. Status: the CLI's own (124 / 142 when it ran
# out of time), 96 when providers.env holds no key for the agent.
probe_one() (
  set -a; . "$HOME/fp-lab/secrets/providers.env"; set +a
  prompt="reply with the word ready"
  cd "$2" || exit 1
  case "$1" in
    claude)
      # Amazon Bedrock or the Anthropic API (agent_harness.claude_code_on_bedrock).
      case "${CLAUDE_CODE_USE_BEDROCK:-}" in
        ""|0|false) keyvar=ANTHROPIC_API_KEY; key=${ANTHROPIC_API_KEY:-}; unset AWS_BEARER_TOKEN_BEDROCK ;;
        *) keyvar=AWS_BEARER_TOKEN_BEDROCK; key=${AWS_BEARER_TOKEN_BEDROCK:-}; unset ANTHROPIC_API_KEY ;;
      esac
      [ -n "$key" ] || { echo "no $keyvar in providers.env"; exit 96; }
      unset OPENAI_API_KEY CODEX_API_KEY
      export IS_SANDBOX=1 BASH_DEFAULT_TIMEOUT_MS=200000 BASH_MAX_TIMEOUT_MS=200000 DISABLE_AUTOUPDATER=1
      # The prompt on standard input, as the driver sends it.
      with_timeout 90 claude -p --dangerously-skip-permissions --output-format json --model sonnet <<< "$prompt"
      ;;
    codex)
      [ -n "${OPENAI_API_KEY:-}" ] || { echo "no OPENAI_API_KEY in providers.env"; exit 96; }
      unset ANTHROPIC_API_KEY AWS_BEARER_TOKEN_BEDROCK
      # Both names, as the driver sets them: the Codex CLI reads CODEX_API_KEY.
      export CODEX_API_KEY="$OPENAI_API_KEY"
      # The runner's own standard input is /dev/null, and Codex inherits it.
      with_timeout 90 codex exec --sandbox danger-full-access --skip-git-repo-check -C "$2" "$prompt" < /dev/null
      ;;
    *) echo "probe_one: unknown agent $1"; exit 1 ;;
  esac
)

# probe_agents: each lab agent answers a one-turn, non-interactive prompt
# within 90 s with the provider keys of the window, or this returns 1 (the
# `agents` step fails there, instead of ten cases ending in SKIP when a CLI
# stops answering mid-window). One line per agent says which it was:
#   <agent> probe: ready                 the CLI answered as a case would see it
#   <agent> probe: FAILED (exit N): ...  launched as a case launches it, no answer
#   <agent> probe: NOT RUN (...)         no key in providers.env (run `keys`):
#                                        the lab would plan no case for the agent
# The probe's own transcript lands in a throwaway directory under the lab root.
probe_agents() {
  dir=$(mktemp -d "$HOME/fp-lab/probe.XXXXXX"); rc=0
  for t in claude codex; do
    out=$(probe_one "$t" "$dir" 2>&1) && st=0 || st=$?
    # The whole word, read without a pipe: "already" is not an answer, and a
    # reader that stops at its first match must not fail the writer.
    if [ "$st" -eq 0 ] && grep -qiw ready <<< "$out"; then
      echo "$t probe: ready"
    elif [ "$st" -eq 96 ]; then
      echo "$t probe: NOT RUN ($(printf '%s' "$out" | tail -n 1 | cut -c1-200)): run keys first"; rc=1
    else
      echo "$t probe: FAILED (exit $st): $(printf '%s' "$out" | tail -n 3 | cut -c1-300 | tr '\n' ' ')"; rc=1
    fi
  done
  rm -rf "$dir"
  return $rc
}
