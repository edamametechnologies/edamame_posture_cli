$packageName = 'edamame-posture'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileFullPath = Join-Path $toolsDir "edamame_posture.exe"

# Remove the binary file if it exists
if (Test-Path $fileFullPath) {
    Remove-Item $fileFullPath -Force -ErrorAction SilentlyContinue
}

# Remove shim registration
Uninstall-BinFile -Name $packageName -Path $fileFullPath



