$packageName = 'edamame-posture'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileFullPath = Join-Path $toolsDir "edamame_posture.exe"

# Remove the service installed by `edamame_posture install-service`, if any
# (the configuration in %ProgramData%\EDAMAME\Posture is kept).
if ((Test-Path $fileFullPath) -and (Get-Service -Name 'edamame_posture' -ErrorAction SilentlyContinue)) {
    & $fileFullPath uninstall-service
}

# Remove the binary file if it exists
if (Test-Path $fileFullPath) {
    Remove-Item $fileFullPath -Force -ErrorAction SilentlyContinue
}

# Remove shim registration
Uninstall-BinFile -Name $packageName -Path $fileFullPath



