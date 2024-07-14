#!/bin/bash

APP_PATH="$1"

# Sign + hardened runtime
codesign --timestamp --options=runtime -s "Developer ID Application: Edamame Technologies (WSL782B48J)" -v "$APP_PATH"
