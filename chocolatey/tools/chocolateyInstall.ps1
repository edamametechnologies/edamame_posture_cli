$packageName = 'edamame-posture'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url64 = 'https://github.com/edamametechnologies/edamame_posture_cli/releases/download/v0.9.81/edamame_posture-0.9.81-x86_64-pc-windows-msvc.exe'
$checksum64 = '0000000000000000000000000000000000000000000000000000000000000000'

Install-ChocolateyPackage -PackageName $packageName `
                          -FileType 'exe' `
                          -Url64bit $url64 `
                          -Checksum64 $checksum64 `
                          -ChecksumType64 'sha256'



