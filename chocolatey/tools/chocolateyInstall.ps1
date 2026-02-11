$packageName = 'edamame-posture'
$packageVersion = '1.0.4'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url64 = "https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v$packageVersion/edamame_posture-$packageVersion-x86_64-pc-windows-msvc.exe"
$checksum64 = 'a462edd862ff1d45378a41480d9219a0bcb867a05b5f735cfa3ed60c13051582'

# Download the standalone executable
$fileFullPath = Join-Path $toolsDir "edamame_posture.exe"
Get-ChocolateyWebFile -PackageName $packageName `
                      -FileFullPath $fileFullPath `
                      -Url64bit $url64 `
                      -Checksum64 $checksum64 `
                      -ChecksumType64 'sha256'

# Create a shim so the binary is exposed on PATH
Install-BinFile -Name $packageName `
                -Path $fileFullPath



