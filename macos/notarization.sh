#!/bin/zsh

APP_PATH="$1"

# Perform multiple attempts as this command sometimes fails
while true; do
  sub=$(xcrun notarytool submit "$APP_PATH" --keychain-profile "Edamame")
  if [ $? -eq 0 ]; then
    break
  fi
  echo "Failed to submit notarization request, retrying in 5 seconds"
  sleep 5
done

id=$(echo "$sub" | grep "id:" | awk '{ print $2 }' | head -n1)
echo "$sub"
echo "Success requesting notarization for id $id"
wai=$(xcrun notarytool wait "$id" --keychain-profile "Edamame")
stat=$(echo "$wai" | grep status |  awk '{ print $2 }' | tail -n1)
echo "$wai"
if [ "$stat" = "Invalid" ]; then
	xcrun notarytool log "$id" --keychain-profile "Edamame"
	echo "Notarization failed"
	exit 1
fi
echo "Notarization succeeded"
