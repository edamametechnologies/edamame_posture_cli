#!/usr/bin/env bash
# Look up a GitHub release for the release workflows, failing closed.
#
# Usage:
#   release_lookup.sh release <owner/repo> <tag>
#       Prints GITHUB_OUTPUT lines: exists=true, id=<id>, upload_url=<url>;
#       or exists=false when GitHub answers HTTP 404 for the tag.
#   release_lookup.sh assets <owner/repo> <tag>
#       Prints the names of the release's assets, one per line. The release
#       must exist: a 404 is an error here too.
#
# Any other failure exits 1: the org IP allow list refusing a hosted runner
# (HTTP 403), an expired token, a 5xx, no network. Reading those as "no
# release" or "not published yet" makes a workflow create a release that
# exists or re-upload, with overwrite, an asset whose checksum is already
# published (the 1.8.0 Chocolatey failure); release_checksums.sh reads its
# lookup the same way.
#
# Requirements: gh, GH_TOKEN (or GITHUB_TOKEN) with read access to the repo.
set -euo pipefail

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[ $# -eq 3 ] || usage
MODE="$1"
REPO="$2"
TAG="$3"
case "$MODE" in
  release|assets) ;;
  *) usage ;;
esac

ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

# id<TAB>upload_url of the release, or exit: 3 on a definite 404, 1 otherwise.
lookup_release() {
  local out
  if ! out="$(gh api "repos/${REPO}/releases/tags/${TAG}" --jq '[.id, .upload_url] | @tsv' 2>"$ERR")"; then
    if grep -q 'HTTP 404' "$ERR"; then
      return 3
    fi
    echo "ERROR: looking up release ${TAG} of ${REPO} failed: $(tr '\n' ' ' < "$ERR")" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

set +e
LINE="$(lookup_release)"
RC=$?
set -e
if [ "$RC" -eq 3 ]; then
  if [ "$MODE" = release ]; then
    echo "::notice::Release ${TAG} not found in ${REPO} (HTTP 404)." >&2
    echo "exists=false"
    exit 0
  fi
  echo "ERROR: release ${TAG} of ${REPO} not found (HTTP 404); cannot list its assets" >&2
  exit 1
fi
[ "$RC" -eq 0 ] || exit 1

ID="${LINE%%$'\t'*}"
UPLOAD_URL="${LINE#*$'\t'}"
if ! printf '%s' "$ID" | grep -Eq '^[0-9]+$'; then
  echo "ERROR: unexpected release id '${ID}' for ${TAG} of ${REPO}" >&2
  exit 1
fi

if [ "$MODE" = release ]; then
  case "$UPLOAD_URL" in
    https://uploads.github.com/*) ;;
    *)
      echo "ERROR: unexpected upload URL '${UPLOAD_URL}' for ${TAG} of ${REPO}" >&2
      exit 1
      ;;
  esac
  echo "exists=true"
  echo "id=${ID}"
  echo "upload_url=${UPLOAD_URL}"
  exit 0
fi

if ! gh api --paginate "repos/${REPO}/releases/${ID}/assets?per_page=100" --jq '.[].name' 2>"$ERR"; then
  echo "ERROR: listing the assets of release ${TAG} of ${REPO} failed: $(tr '\n' ' ' < "$ERR")" >&2
  exit 1
fi
