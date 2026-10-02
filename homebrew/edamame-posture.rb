# typed: true
# frozen_string_literal: true

cask "edamame-posture" do
  version "2.0.4"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v#{version}/edamame-posture-macos-#{version}.pkg"
  name "EDAMAME Posture"
  desc "EDAMAME Security posture analysis and remediation CLI"
  homepage "https://github.com/edamametechnologies/edamame_posture_cli"

  pkg "edamame-posture-macos-#{version}.pkg"

  # launchctl/delete of the LaunchDaemon cover `edamame_posture install-service`;
  # the configuration file is kept.
  uninstall launchctl: "com.edamametechnologies.edamame-posture",
            delete:    [
              "/Library/LaunchDaemons/com.edamametechnologies.edamame-posture.plist",
              "/usr/local/bin/edamame_posture",
              "/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.app",
            ]

  zap delete: [
    "/Library/Application Support/EDAMAME/EDAMAME-Posture/service-enabled",
    "/Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.conf",
  ]

  caveats <<~EOS
    This package requires admin privileges to install.
    The package installs an app-like bundle with an embedded Endpoint Security
    provisioning profile and exposes /usr/local/bin/edamame_posture as a
    symlink into that bundle.

    To run it as a service that survives reboots (EDAMAME >= 2.0.2):
      sudo edamame_posture install-service
    then edit /Library/Application Support/EDAMAME/EDAMAME-Posture/edamame_posture.conf
    and restart it with:
      sudo launchctl kickstart -k system/com.edamametechnologies.edamame-posture
  EOS
end
