#!/usr/bin/env bash
# Resolve the notes of a posture GitHub release (edamame_posture_cli).
#
# Usage: release_notes.sh <version> <output file> [--generic]
#
# Writes the release body for v<version> to <output file>:
#   - release_notes/<version>.md of this checkout when it exists and is not
#     blank;
#   - the one-line generic text "Bug fixes" when it does not and --generic
#     was given (release_all.sh --generic-release-notes, the release
#     workflows' generic_release_notes input): for emergencies, not a default;
#   - otherwise nothing: exit 1 with the reason. A release is never
#     published with an empty body.
# What the notes may say (users and administrators, no vulnerability or
# detection details): edamame_rules/_shared/release-notes.mdc.
set -euo pipefail

GENERIC="Bug fixes"

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

[ $# -ge 2 ] && [ $# -le 3 ] || usage
VERSION="$1"
OUT="$2"
GENERIC_OK=false
if [ $# -eq 3 ]; then
  [ "$3" = "--generic" ] || usage
  GENERIC_OK=true
fi
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
  echo "release notes: '$VERSION' is not an X.Y.Z version" >&2
  exit 2
}

NOTES="release_notes/${VERSION}.md"
if [ -f "$NOTES" ] && grep -q '[^[:space:]]' "$NOTES"; then
  cp "$NOTES" "$OUT"
  echo "release notes: ${NOTES} ($(wc -l < "$NOTES" | tr -d ' ') lines)" >&2
  exit 0
fi
if [ "$GENERIC_OK" = true ]; then
  printf '%s\n' "$GENERIC" > "$OUT"
  echo "release notes: ${NOTES} is missing or blank; publishing the generic text (\"${GENERIC}\") as asked" >&2
  exit 0
fi
echo "release notes refused: ${NOTES} is missing or blank. Write the user-facing notes of v${VERSION} there (edamame_rules/_shared/release-notes.mdc), or dispatch with generic_release_notes=true (release_all.sh --generic-release-notes) to publish \"${GENERIC}\"." >&2
exit 1
