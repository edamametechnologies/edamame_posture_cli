#!/usr/bin/env bash

REPO_URL="$1"
SUITE="$2"
COMPONENT="$3"
ARCH="$4"
PACKAGE_NAME="$5"

if [ -z "$REPO_URL" ] || [ -z "$SUITE" ] || [ -z "$COMPONENT" ] || [ -z "$ARCH" ] || [ -z "$PACKAGE_NAME" ]; then
  echo "Usage: $0 <repo_url> <suite> <component> <architecture> <package_name>"
  exit 1
fi

# Create a temporary working directory
WORKDIR="$(mktemp -d)"
cd "$WORKDIR" || exit 1

echo "======================================================================"
echo "1. Fetch InRelease or Release."
echo "======================================================================"
INRELEASE_URL="${REPO_URL}/dists/${SUITE}/InRelease"
RELEASE_URL="${REPO_URL}/dists/${SUITE}/Release"
if ! curl -fsS -o InRelease "$INRELEASE_URL"; then
  echo "InRelease not found. Trying Release..."
  if ! curl -fsS -o Release "$RELEASE_URL"; then
    echo "Could not download InRelease or Release."
    exit 1
  else
    RELEASE_OR_INRELEASE="Release"
  fi
else
  RELEASE_OR_INRELEASE="InRelease"
fi

echo ""
echo "======================================================================"
echo "2. (Optional) Check 'Valid-Until' field."
echo "======================================================================"
# apt can consider a repo 'expired' if 'Valid-Until' is in the past
VALID_UNTIL="$(awk '/^Valid-Until:/ { $1=""; print $0 }' "${RELEASE_OR_INRELEASE}" | xargs)"
if [ -n "$VALID_UNTIL" ]; then
  echo "Repository provides a Valid-Until date: $VALID_UNTIL"
  
  # Compare with current date if 'date' command can parse it
  # (This may fail depending on exact date format; it's best-effort.)
  if command -v date >/dev/null 2>&1; then
    # convert the "Valid-Until" date to epoch seconds
    # many Debian-based repos use RFC 2822-like format, e.g. "Fri, 15 Sep 2023 00:00:00 UTC"
    VALID_UNTIL_EPOCH="$(date -d "$VALID_UNTIL" +%s 2>/dev/null || true)"
    if [ -n "$VALID_UNTIL_EPOCH" ]; then
      CURRENT_EPOCH="$(date +%s)"
      if [ "$CURRENT_EPOCH" -gt "$VALID_UNTIL_EPOCH" ]; then
        echo "WARNING: Valid-Until date is in the past! Apt may refuse this repo unless 'Acquire::Check-Valid-Until' is disabled."
      else
        echo "OK: Valid-Until is in the future."
      fi
    else
      echo "NOTICE: Could not parse Valid-Until date format. Skipping expiration check."
    fi
  else
    echo "NOTICE: 'date' command unavailable or not found. Skipping expiration check."
  fi
else
  echo "No Valid-Until field found. This is normal for some repositories."
fi

echo ""
echo "======================================================================"
echo "3. Locate the correct Packages file reference for '${COMPONENT}/binary-${ARCH}'."
echo "======================================================================"
# We attempt to find both an MD5Sum line and a possible SHA256 line
CHECKSUM_LINE_MD5="$(awk '/^MD5Sum:/, /^SHA256:/' "${RELEASE_OR_INRELEASE}" \
               | grep " ${COMPONENT}/binary-${ARCH}/Packages" \
               | head -n 1)"

CHECKSUM_LINE_SHA256="$(awk '/^SHA256:/, /^SHA512:/' "${RELEASE_OR_INRELEASE}" \
                  | grep " ${COMPONENT}/binary-${ARCH}/Packages" \
                  | head -n 1)"

# If empty, we have a problem
if [ -z "$CHECKSUM_LINE_MD5" ]; then
  echo "Could not find any Packages or Packages.gz entry under 'MD5Sum:' for '${COMPONENT}/binary-${ARCH}'."
  echo "This is unusual but might happen if the Release file doesn't list MD5 sums."
fi

if [ -z "$CHECKSUM_LINE_MD5" ] && [ -z "$CHECKSUM_LINE_SHA256" ]; then
  echo "No MD5 or SHA256 line found for ${COMPONENT}/binary-${ARCH}/Packages. Exiting."
  exit 1
fi

# Show what we found
echo "MD5 line:      $CHECKSUM_LINE_MD5"
echo "SHA256 line:   $CHECKSUM_LINE_SHA256"

# Parse out MD5 (if present)
if [ -n "$CHECKSUM_LINE_MD5" ]; then
  MD5_SUM="$(echo "$CHECKSUM_LINE_MD5" | awk '{print $1}')"
  SIZE="$(echo "$CHECKSUM_LINE_MD5" | awk '{print $2}')"
  PACKAGES_PATH="$(echo "$CHECKSUM_LINE_MD5" | awk '{print $3}')"
fi

# Parse out SHA256 (if present)
if [ -n "$CHECKSUM_LINE_SHA256" ]; then
  SHA256_SUM="$(echo "$CHECKSUM_LINE_SHA256" | awk '{print $1}')"
  SIZE_SHA256="$(echo "$CHECKSUM_LINE_SHA256" | awk '{print $2}')"
  PACKAGES_PATH_SHA256="$(echo "$CHECKSUM_LINE_SHA256" | awk '{print $3}')"
fi

# We'll prefer PACKAGES_PATH from MD5 if it exists, else from SHA256
if [ -z "$PACKAGES_PATH" ] && [ -n "$PACKAGES_PATH_SHA256" ]; then
  PACKAGES_PATH="$PACKAGES_PATH_SHA256"
  # If we didn't get a size from the MD5 line, we'll use the SHA256 size if it exists
  if [ -n "$SIZE_SHA256" ] && [ -z "$SIZE" ]; then
    SIZE="$SIZE_SHA256"
  fi
fi

if [ -z "$PACKAGES_PATH" ]; then
  echo "No Packages file path found via either MD5Sum or SHA256. Cannot proceed."
  exit 1
fi

echo " - Chosen Packages Path: $PACKAGES_PATH"
echo " - Claimed Size:         $SIZE"
echo " - (Optional) MD5:       $MD5_SUM"
echo " - (Optional) SHA256:    $SHA256_SUM"

echo ""
echo "======================================================================"
echo "4. Download the Packages file and verify size, MD5, and (optionally) SHA256."
echo "======================================================================"
PACKAGES_URL="${REPO_URL}/dists/${SUITE}/${PACKAGES_PATH}"
echo "Downloading from: $PACKAGES_URL"

if ! curl -fsS -O "$PACKAGES_URL"; then
  echo "Failed to download $PACKAGES_URL"
  exit 1
fi

DOWNLOADED_PACKAGES_FILE="$(basename "$PACKAGES_PATH")"

# Handle different 'stat' formats for macOS vs. Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
  DOWNLOADED_SIZE="$(stat -f%z "$DOWNLOADED_PACKAGES_FILE")"
else
  DOWNLOADED_SIZE="$(stat -c%s "$DOWNLOADED_PACKAGES_FILE")"
fi

if [ -n "$SIZE" ]; then
  if [ "$DOWNLOADED_SIZE" != "$SIZE" ]; then
    echo "Size mismatch! Expected $SIZE, got $DOWNLOADED_SIZE"
    exit 1
  fi
  echo "Packages file size matches: $SIZE"
else
  echo "No size available to compare. Skipping size check."
fi

# Handle md5 on Linux vs. macOS
if [ -n "$MD5_SUM" ]; then
  # If MD5 was found, let's verify it
  if command -v md5sum >/dev/null 2>&1; then
    CALC_MD5="$(md5sum "$DOWNLOADED_PACKAGES_FILE" | awk '{print $1}')"
  elif command -v md5 >/dev/null 2>&1; then
    # macOS typically uses 'md5 -q'; prints just the checksum
    CALC_MD5="$(md5 -q "$DOWNLOADED_PACKAGES_FILE")"
  else
    echo "No MD5 utility found (neither md5sum nor md5). Please install one of them."
    exit 1
  fi

  if [ "$CALC_MD5" != "$MD5_SUM" ]; then
    echo "MD5 mismatch!"
    echo " - Expected: $MD5_SUM"
    echo " - Got:      $CALC_MD5"
    exit 1
  else
    echo "MD5 successfully verified."
  fi
fi

# Optional: If SHA256 is present, let's verify it
if [ -n "$SHA256_SUM" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    CALC_SHA256="$(sha256sum "$DOWNLOADED_PACKAGES_FILE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    # macOS typically uses shasum
    CALC_SHA256="$(shasum -a 256 "$DOWNLOADED_PACKAGES_FILE" | awk '{print $1}')"
  else
    echo "No SHA256 utility found (sha256sum or shasum). Skipping SHA256 verification."
  fi

  if [ -n "$CALC_SHA256" ]; then
    if [ "$CALC_SHA256" != "$SHA256_SUM" ]; then
      echo "SHA256 mismatch!"
      echo " - Expected: $SHA256_SUM"
      echo " - Got:      $CALC_SHA256"
      exit 1
    else
      echo "SHA256 successfully verified."
    fi
  fi
fi

echo ""
echo "======================================================================"
echo "5. Decompress (if needed) and search for '${PACKAGE_NAME}'."
echo "======================================================================"
# If it's a .gz file, decompress it
if [[ "$DOWNLOADED_PACKAGES_FILE" == *.gz ]]; then
  echo "Decompressing $DOWNLOADED_PACKAGES_FILE..."
  gunzip -c "$DOWNLOADED_PACKAGES_FILE" > Packages
  SEARCH_FILE="Packages"
else
  SEARCH_FILE="$DOWNLOADED_PACKAGES_FILE"
fi

# Now search for the package in the uncompressed Packages data
PACKAGE_ENTRY="$(awk -v pkg="$PACKAGE_NAME" 'BEGIN { RS="" ; FS="\n" } $0 ~ "Package: "pkg { print $0 }' "$SEARCH_FILE")"

if [ -z "$PACKAGE_ENTRY" ]; then
  echo "Package '$PACKAGE_NAME' not found in Packages."
  exit 1
fi

echo "Found package stanza for '$PACKAGE_NAME':"
echo "------------------------------------------------"
echo "$PACKAGE_ENTRY"
echo "------------------------------------------------"

# Optional: Check for an Architecture: line in the package stanza
REPO_ARCH_LINE="$(echo "$PACKAGE_ENTRY" | grep '^Architecture:')"
if [ -n "$REPO_ARCH_LINE" ]; then
  REPO_ARCH_FIELD="$(echo "$REPO_ARCH_LINE" | awk '{print $2}')"
  # Compare with the user-supplied ARG ($ARCH)
  if [ "$REPO_ARCH_FIELD" != "$ARCH" ]; then
    echo "WARNING: The package's Architecture field is '$REPO_ARCH_FIELD' which does not match requested '$ARCH'."
  else
    echo "OK: Package Architecture ($REPO_ARCH_FIELD) matches requested '$ARCH'."
  fi
fi

# Optional: Check for a Version: line in the package stanza
VERSION_LINE="$(echo "$PACKAGE_ENTRY" | grep '^Version:')"
if [ -z "$VERSION_LINE" ]; then
  echo "WARNING: No 'Version:' field found in the package stanza. Apt may have trouble pinning or comparing versions."
else
  echo "Package version line: $VERSION_LINE"
fi

DEB_FILENAME="$(echo "$PACKAGE_ENTRY" | grep '^Filename:' | awk '{print $2}')"
if [ -z "$DEB_FILENAME" ]; then
  echo "No 'Filename:' field found for package '$PACKAGE_NAME'."
  exit 1
fi

echo ""
echo "======================================================================"
echo "6. Check the .deb file is actually present."
echo "======================================================================"
DEB_URL="${REPO_URL}/${DEB_FILENAME}"
echo "Checking: $DEB_URL"

if curl -fsI "$DEB_URL" >/dev/null 2>&1; then
  echo "Success: The .deb file is present."
else
  echo "ERROR: The .deb file is NOT found at $DEB_URL"
  exit 1
fi

###############################################################################
#           ADDITIONAL APT-FRIENDLY CHECKS
###############################################################################
echo ""
echo "======================================================================"
echo "7. Confirm the 'Suite' or 'Codename' matches '${SUITE}'."
echo "======================================================================"
# apt often expects the Release or InRelease file to contain 'Suite: <SUITE>'
# or 'Codename: <SUITE>' that matches the declared suite in the sources.list.
# If it doesn't match, apt might ignore or misinterpret this repository.

if [ "$RELEASE_OR_INRELEASE" = "InRelease" ]; then
  SUITE_FIELD=$(awk '/^Suite:|^Codename:/ { print $2 }' InRelease | head -n 1)
else
  SUITE_FIELD=$(awk '/^Suite:|^Codename:/ { print $2 }' Release | head -n 1)
fi

if [ -n "$SUITE_FIELD" ] && [ "$SUITE_FIELD" != "$SUITE" ]; then
  echo "WARNING: The repository's declared Suite/Codename ($SUITE_FIELD) does not match '$SUITE'."
  echo "         apt may fail to pick up the repo or show warnings unless this matches."
else
  [ -z "$SUITE_FIELD" ] && echo "NOTICE: No explicit 'Suite:' or 'Codename:' found in $RELEASE_OR_INRELEASE."
  [ -n "$SUITE_FIELD" ] && echo "OK: $RELEASE_OR_INRELEASE indicates Suite/Codename is '$SUITE_FIELD', matching expected '$SUITE'."
fi

echo ""
echo "======================================================================"
echo "8. Check for GPG signature presence (optional)."
echo "======================================================================"
# apt typically requires a valid GPG signature or apt options allowing unsigned repos.
# If there is no Release.gpg (for 'Release') or if 'InRelease' is not properly signed,
# apt will complain unless configured to trust it.

if [ "$RELEASE_OR_INRELEASE" = "InRelease" ]; then
  # InRelease is a combined Release + GPG signature
  if command -v gpg >/dev/null 2>&1; then
    echo "Attempting GPG signature check for '$RELEASE_OR_INRELEASE'..."
    if ! gpg --verify "$RELEASE_OR_INRELEASE" 2>/dev/null; then
      echo "WARNING: GPG signature check of InRelease FAILED."
      echo "         Ensure you have imported the repository's signing key or apt won't trust it."
    else
      echo "GPG signature for InRelease verified (assuming you have the correct public key)."
    fi
  else
    echo "NOTICE: 'gpg' not found. Skipping signature check for InRelease."
  fi
else
  # We used 'Release'; see if there's a Release.gpg
  RELEASE_GPG_URL="${RELEASE_URL}.gpg"
  echo "Attempting to download Release.gpg from ${RELEASE_GPG_URL}..."
  if curl -fsS -O "${RELEASE_GPG_URL}"; then
    if command -v gpg >/dev/null 2>&1; then
      echo "Attempting GPG signature check for 'Release' with 'Release.gpg'..."
      if ! gpg --verify Release.gpg Release 2>/dev/null; then
        echo "WARNING: GPG signature check for Release FAILED."
        echo "         apt might refuse this repository unless the correct signing key is trusted."
      else
        echo "GPG signature for Release verified (assuming you have the correct public key)."
      fi
    else
      echo "NOTICE: 'gpg' not found. Skipping signature check for Release."
    fi
  else
    echo "WARNING: No Release.gpg found. If apt is configured to require signatures, it may ignore this repo."
  fi
fi

echo ""
echo "All checks have completed."
cd - >/dev/null 2>&1
rm -rf "$WORKDIR"

