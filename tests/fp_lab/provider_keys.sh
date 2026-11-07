#!/usr/bin/env bash
# The agents' provider credentials as KEY=value lines, for the deploy
# scripts' `keys` step, which writes them to an owner-only file on the host
# and never echoes them. Usage: provider_keys.sh <secrets dir> <env file>...
# (the files to take ANTHROPIC_API_KEY, OPENAI_API_KEY and CURSOR_API_KEY
# from).
#
# FP_LAB_CLAUDE_BEDROCK=1: Claude Code reaches Anthropic's models through
# Amazon Bedrock with the Bedrock API key of bedrock.env instead of
# claude.env's Anthropic API key (Frank, 2026-11-07: the lab's Anthropic
# credit ran out). FP_LAB_BEDROCK_REGION (eu-west-1), FP_LAB_BEDROCK_SONNET
# and FP_LAB_BEDROCK_HAIKU (the EU inference profiles the runner's
# `--model sonnet` and Claude Code's small model resolve to) override it.
set -euo pipefail
secrets=$1
shift
files=()
for name in "$@"; do
  if [[ "${FP_LAB_CLAUDE_BEDROCK:-0}" == 1 && "$name" == claude.env ]]; then
    continue
  fi
  [[ -f "$secrets/$name" ]] || { echo "missing $secrets/$name" >&2; exit 1; }
  files+=("$secrets/$name")
done
if [[ "${FP_LAB_CLAUDE_BEDROCK:-0}" == 1 ]]; then
  key=$(sed -nE 's/^(export )?EDAMAME_BEDROCK_API_KEY=//p' "$secrets/bedrock.env" | head -n 1)
  [[ -n "$key" ]] || { echo "no EDAMAME_BEDROCK_API_KEY in $secrets/bedrock.env" >&2; exit 1; }
  echo "CLAUDE_CODE_USE_BEDROCK=1"
  echo "AWS_REGION=${FP_LAB_BEDROCK_REGION:-eu-west-1}"
  echo "ANTHROPIC_DEFAULT_SONNET_MODEL=${FP_LAB_BEDROCK_SONNET:-eu.anthropic.claude-sonnet-5-5}"
  echo "ANTHROPIC_DEFAULT_HAIKU_MODEL=${FP_LAB_BEDROCK_HAIKU:-eu.anthropic.claude-haiku-5-5}"
  echo "AWS_BEARER_TOKEN_BEDROCK=$key"
fi
if ((${#files[@]})); then
  grep -hE '^(export )?(ANTHROPIC_API_KEY|OPENAI_API_KEY|CURSOR_API_KEY)=' "${files[@]}" | sed 's/^export //'
fi
