#!/usr/bin/env bash
# Publish SHA256SUMS and its Sigstore signature on a GitHub release.
#
# Usage: release_checksums.sh <owner/repo> <tag> [--allow-replaced] [--no-sign] [--dry-run]
#
# SHA256SUMS lists every asset of the release (except SHA256SUMS itself and
# its signature) in `sha256sum` format, sorted by name. Digests come from the
# `digest` field GitHub computes at upload; an asset without one is downloaded
# and hashed. The file is signed keyless with cosign (Sigstore public-good
# instance, identity = the workflow running this script) into
# SHA256SUMS.sigstore.json, and both files are uploaded with --clobber.
#
# Re-runs are safe: when the release gained assets, the file is regenerated;
# when nothing changed, nothing is uploaded. An asset whose digest changed
# since the previous SHA256SUMS (an asset replaced after publication) is
# published with its new digest and the script exits 1 so the release owner
# sees it, unless --allow-replaced (repos whose release workflows upload with
# --clobber on purpose).
#
# Requirements: gh + jq, GH_TOKEN with contents:write on <owner/repo>;
# cosign and an Actions OIDC token (permissions: id-token: write) unless
# --no-sign.
#
# This file is kept identical in edamame_posture, edamame_cli,
# edamame_helper and edamame_app (.github/scripts/release_checksums.sh).
set -euo pipefail

usage() {
  sed -n '2,4p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[ $# -ge 2 ] || usage
REPO="$1"
TAG="$2"
shift 2
ALLOW_REPLACED=false
SIGN=true
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --allow-replaced) ALLOW_REPLACED=true ;;
    --no-sign) SIGN=false ;;
    --dry-run) DRY_RUN=true ;;
    *) usage ;;
  esac
done

SUMS=SHA256SUMS
BUNDLE=SHA256SUMS.sigstore.json

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A release workflow that failed before creating the release triggers this
# too: nothing to do then. Only a real 404 means that. Any other failure (the
# org IP allow list refusing a hosted runner, an expired token, a 5xx) exits
# 1: reading it as "no release" left all of 2.0.2 without SHA256SUMS behind
# green runs.
if ! RELEASE_ID="$(gh api "repos/${REPO}/releases/tags/${TAG}" --jq '.id' 2>&1)"; then
  case "$RELEASE_ID" in
    *"HTTP 404"*)
      echo "::notice::Release ${TAG} not found in ${REPO}; nothing to checksum."
      exit 0
      ;;
  esac
  echo "ERROR: looking up release ${TAG} of ${REPO} failed: ${RELEASE_ID}" >&2
  exit 1
fi
if ! printf '%s' "$RELEASE_ID" | grep -Eq '^[0-9]+$'; then
  echo "ERROR: unexpected release id '${RELEASE_ID}' for ${TAG} of ${REPO}" >&2
  exit 1
fi

# name<TAB>digest (digest may be empty on assets uploaded before GitHub
# started computing it).
gh api --paginate "repos/${REPO}/releases/${RELEASE_ID}/assets?per_page=100" \
  --jq '.[] | [.name, (.digest // "")] | @tsv' > "$WORK/assets.tsv"

: > "$WORK/new.unsorted"
while IFS="$(printf '\t')" read -r name digest; do
  case "$name" in
    "$SUMS"|"$BUNDLE") continue ;;
  esac
  case "$digest" in
    sha256:*)
      hex="${digest#sha256:}"
      ;;
    *)
      echo "No server digest for ${name}; downloading to hash it"
      mkdir -p "$WORK/dl"
      gh release download "$TAG" --repo "$REPO" --pattern "$name" --dir "$WORK/dl" --clobber
      hex="$(sha256_of "$WORK/dl/$name")"
      rm -f "$WORK/dl/$name"
      ;;
  esac
  if ! printf '%s' "$hex" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "ERROR: unexpected digest '${digest}' for ${name}" >&2
    exit 1
  fi
  printf '%s  %s\n' "$hex" "$name" >> "$WORK/new.unsorted"
done < "$WORK/assets.tsv"

if [ ! -s "$WORK/new.unsorted" ]; then
  echo "ERROR: release ${TAG} of ${REPO} has no assets to checksum" >&2
  exit 1
fi
LC_ALL=C sort -k2 "$WORK/new.unsorted" > "$WORK/$SUMS"

# Compare with the published file, if any. The asset list above says whether
# there is one: a failed download of a listed SHA256SUMS exits 1, it is not
# "nothing published yet" (read that way, it skipped the replaced-asset check
# below and published the new digests with exit 0).
REPLACED=""
if awk -F '\t' -v n="$SUMS" '$1 == n { found = 1 } END { exit !found }' "$WORK/assets.tsv"; then
  gh release download "$TAG" --repo "$REPO" --pattern "$SUMS" --dir "$WORK/old" >/dev/null
  if cmp -s "$WORK/old/$SUMS" "$WORK/$SUMS"; then
    echo "${SUMS} on ${REPO}@${TAG} is already up to date ($(wc -l < "$WORK/$SUMS" | tr -d ' ') assets)."
    exit 0
  fi
  REPLACED="$(awk 'NR==FNR { old[$2]=$1; next } ($2 in old) && old[$2] != $1 { print $2 }' \
    "$WORK/old/$SUMS" "$WORK/$SUMS")"
  REMOVED="$(awk 'NR==FNR { cur[$2]=1; next } !($2 in cur) { print $2 }' \
    "$WORK/$SUMS" "$WORK/old/$SUMS")"
  if [ -n "$REMOVED" ]; then
    echo "::warning::Assets listed in the previous ${SUMS} are no longer on the release: $(echo "$REMOVED" | tr '\n' ' ')"
  fi
fi

echo "New ${SUMS}:"
cat "$WORK/$SUMS"

if [ "$DRY_RUN" = true ]; then
  echo "Dry run: nothing signed or uploaded."
  exit 0
fi

FILES=("$WORK/$SUMS")
if [ "$SIGN" = true ]; then
  (cd "$WORK" && cosign sign-blob --yes --bundle "$BUNDLE" "$SUMS")
  # Check the signature we are about to publish against the identity users
  # are told to expect (the running workflow, GitHub Actions issuer).
  if [ -n "${GITHUB_WORKFLOW_REF:-}" ]; then
    (cd "$WORK" && cosign verify-blob --bundle "$BUNDLE" \
      --certificate-identity "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_WORKFLOW_REF}" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$SUMS")
  fi
  FILES+=("$WORK/$BUNDLE")
fi

gh release upload "$TAG" "${FILES[@]}" --repo "$REPO" --clobber
echo "Published ${SUMS}$([ "$SIGN" = true ] && echo " and ${BUNDLE}") on ${REPO}@${TAG}."

if [ -n "$REPLACED" ]; then
  echo "::error::Assets replaced after their checksum was published (new digests are now in ${SUMS}): $(echo "$REPLACED" | tr '\n' ' ')"
  if [ "$ALLOW_REPLACED" != true ]; then
    exit 1
  fi
fi
