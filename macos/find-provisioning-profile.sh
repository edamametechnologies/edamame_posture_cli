#!/bin/bash
# Find an installed provisioning profile by app identifier.
# Usage: find-provisioning-profile.sh <app_identifier>
# Returns the path to the matching .provisionprofile file.
set -e

APP_ID="$1"
if [ -z "$APP_ID" ]; then
  echo "Usage: $0 <app_identifier>" >&2
  exit 1
fi

PROFILE_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
if [ ! -d "$PROFILE_DIR" ]; then
  echo "No provisioning profiles directory found" >&2
  exit 1
fi

for profile in "$PROFILE_DIR"/*.provisionprofile; do
  [ -f "$profile" ] || continue
  if security cms -D -i "$profile" 2>/dev/null | grep -q "$APP_ID"; then
    echo "$profile"
    exit 0
  fi
done

echo "No provisioning profile found for $APP_ID" >&2
echo "Run 'fastlane dev' to fetch it, or download from Apple Developer portal" >&2
exit 1
