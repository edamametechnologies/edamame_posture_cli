#!/bin/bash

# Path to your application
APP_PATH="$1"

# Find the first available identity
IDENTITY=$(security find-identity -v -p codesigning | grep -oE '"[^"]+"' | head -n 1)
# Remove the quotes
IDENTITY="${IDENTITY//\"}"

if [ -z "$IDENTITY" ]; then
  echo "No signing identity found."
  exit 1
else
  echo "Found identity: $IDENTITY"
fi

# Codesign the application with the found identity
codesign --timestamp -s "$IDENTITY" "$APP_PATH"

# Verify the signature
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "Application signed and verified successfully."
