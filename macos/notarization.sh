#!/bin/zsh
set -e

# Notarizes a signed installer package, staples the ticket into it and checks
# the staple. The file is modified in place: copy or upload it only after this
# script succeeded. Credentials: the "Edamame" notarytool keychain profile.

APP_PATH="$1"

if [ ! -f "$APP_PATH" ]; then
  echo "Error: no such file: $APP_PATH"
  exit 1
fi

# Perform multiple attempts as this command sometimes fails
attempt=1
until sub=$(xcrun notarytool submit "$APP_PATH" --keychain-profile "Edamame"); do
  if [ "$attempt" -ge 5 ]; then
    echo "Failed to submit notarization request after $attempt attempts"
    exit 1
  fi
  echo "Failed to submit notarization request, retrying in 5 seconds"
  attempt=$((attempt + 1))
  sleep 5
done

id=$(echo "$sub" | awk '$1 == "id:" { print $2 }' | head -n1)
echo "$sub"
if [ -z "$id" ]; then
  echo "Notarization failed: no submission id in the notarytool output"
  exit 1
fi
echo "Success requesting notarization for id $id"

# Only "Accepted" is a success. "Invalid" used to be the only failure, so a
# "Rejected" verdict, a wait that ended "In Progress" or output this script
# could not parse all read as "Notarization succeeded".
wait_rc=0
wai=$(xcrun notarytool wait "$id" --keychain-profile "Edamame") || wait_rc=$?
stat=$(echo "$wai" | awk '$1 == "status:" { $1 = ""; sub(/^ +/, ""); print }' | tail -n1)
echo "$wai"
if [ "$wait_rc" -ne 0 ] || [ "$stat" != "Accepted" ]; then
  xcrun notarytool log "$id" --keychain-profile "Edamame" || true
  echo "Notarization failed (status: ${stat:-none}, notarytool wait exit code: $wait_rc)"
  exit 1
fi
echo "Notarization accepted"

# Staple the ticket so Gatekeeper accepts the package offline as well. Apple
# can take a moment to serve a fresh ticket, so a failed staple is retried.
attempt=1
until xcrun stapler staple "$APP_PATH"; do
  if [ "$attempt" -ge 5 ]; then
    echo "Stapling failed after $attempt attempts"
    exit 1
  fi
  echo "Stapling failed, retrying in $((attempt * 15)) seconds"
  sleep $((attempt * 15))
  attempt=$((attempt + 1))
done
# The validate looks the ticket up in Apple's ticket service again; that
# lookup can drop ("The network connection was lost", stapler exit 68) right
# after a staple that succeeded (posture tests.yml 41676079466, 2026-11-03),
# so it gets the staple's retries.
attempt=1
until xcrun stapler validate "$APP_PATH"; do
  if [ "$attempt" -ge 5 ]; then
    echo "Validation of the stapled ticket failed after $attempt attempts"
    exit 1
  fi
  echo "Validation failed, retrying in $((attempt * 15)) seconds"
  sleep $((attempt * 15))
  attempt=$((attempt + 1))
done
echo "Notarization succeeded, ticket stapled"
