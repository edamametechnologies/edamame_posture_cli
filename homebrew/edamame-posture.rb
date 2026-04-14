# typed: true
# frozen_string_literal: true

cask "edamame-posture" do
  version "1.2.0"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v#{version}/edamame-posture-macos-#{version}.pkg"
  name "EDAMAME Posture"
  desc "EDAMAME Security posture analysis and remediation CLI"
  homepage "https://github.com/edamametechnologies/edamame_posture_cli"

  pkg "edamame-posture-macos-#{version}.pkg"

  uninstall delete: "/usr/local/bin/edamame_posture"

  caveats <<~EOS
    This package requires admin privileges to install.
    The Endpoint Security provisioning profile is included in the package.
  EOS
end
