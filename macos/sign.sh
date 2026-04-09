#!/bin/bash
set -e

APP_PATH="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find provisioning profile with ES entitlement
PROV_PROFILE=$("$SCRIPT_DIR/find-provisioning-profile.sh" "com.edamametechnologies.edamame-posture" 2>/dev/null || true)

codesign --timestamp --options=runtime \
  --entitlements "$SCRIPT_DIR/edamame_posture.entitlements" \
  -i com.edamametechnologies.edamame-posture \
  -s "Developer ID Application: Edamame Technologies (WSL782B48J)" \
  -v "$APP_PATH"
