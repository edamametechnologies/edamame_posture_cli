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

# probe_agents: each lab agent answers a one-turn, non-interactive prompt
# within 90 s with the provider keys of the window, or this returns 1 (the
# `agents` step fails there, instead of ten cases ending in SKIP when a CLI
# stops answering mid-window). The keys are read from the owner-only
# providers.env for the probe only and never printed; the probe's own
# transcript lands in a throwaway directory under the lab root.
probe_agents() {
  set -a; . "$HOME/fp-lab/secrets/providers.env"; set +a
  export DISABLE_AUTOUPDATER=1
  dir=$(mktemp -d "$HOME/fp-lab/probe.XXXXXX"); rc=0
  for t in claude codex; do
    case "$t" in
      claude) out=$(cd "$dir" && with_timeout 90 claude -p "reply with the word ready" --max-turns 1 --output-format text 2>&1) && st=0 || st=$? ;;
      codex)  out=$(cd "$dir" && with_timeout 90 codex exec --skip-git-repo-check -C "$dir" "reply with the word ready" 2>&1) && st=0 || st=$? ;;
    esac
    if [ "$st" -eq 0 ] && printf '%s' "$out" | grep -qi ready; then
      echo "$t probe: ready"
    else
      echo "$t probe: FAILED (exit $st): $(printf '%s' "$out" | tail -n 3 | cut -c1-200 | tr '\n' ' ')"; rc=1
    fi
  done
  rm -rf "$dir"
  unset ANTHROPIC_API_KEY OPENAI_API_KEY CURSOR_API_KEY AWS_BEARER_TOKEN_BEDROCK
  return $rc
}
