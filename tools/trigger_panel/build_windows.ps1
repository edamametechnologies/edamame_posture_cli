<#
.SYNOPSIS
  Build a self-contained Windows bundle of the EDAMAME Trigger Panel.

.DESCRIPTION
  Embeds its own standalone CPython (fetched with uv) plus a copy of
  tests/security/triggers and a tiny GUI launcher .exe built from
  launcher_windows.c. Recipients do not need Python installed. The bundled
  interpreter's path is not a macOS .app, so triggers run under it directly.

  The embedded Python version is the EDAMAME_EMBED_PYTHON_VERSION env var
  (default 3.11). The asset version is EDAMAME_PANEL_VERSION (default "dev").
  When the AZURE_SIGN_* env vars are present the launcher is Authenticode
  signed with AzureSignTool before the zip is sealed.

.PARAMETER DistDir
  Output directory. Defaults to <script dir>\dist.

.OUTPUTS
  Prints "ARTIFACT=<path>" with the produced .zip path.
#>
[CmdletBinding()]
param(
  [string]$DistDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PanelDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $PanelDir '..\..')).Path
$TriggersSrc = Join-Path $RepoRoot 'tests\security\triggers'
if (-not $DistDir) { $DistDir = Join-Path $PanelDir 'dist' }

$PythonVersion = if ($env:EDAMAME_EMBED_PYTHON_VERSION) { $env:EDAMAME_EMBED_PYTHON_VERSION } else { '3.11' }
$Version = if ($env:EDAMAME_PANEL_VERSION) { $env:EDAMAME_PANEL_VERSION } else { 'dev' }

if (-not (Test-Path (Join-Path $TriggersSrc 'cleanup.py'))) {
  throw "Missing triggers at $TriggersSrc"
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  throw 'uv is required to fetch a relocatable CPython (https://github.com/astral-sh/uv)'
}

$AppName = 'EDAMAME Trigger Panel'
$BundleDir = Join-Path $DistDir $AppName
if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null

# --- Fetch a standalone (managed) CPython ----------------------------------
$env:UV_PYTHON_PREFERENCE = 'only-managed'
Write-Host "Installing relocatable CPython $PythonVersion (x64)..."
uv python install $PythonVersion
if ($LASTEXITCODE -ne 0) { throw "uv python install $PythonVersion failed" }

$PyExe = (uv python find $PythonVersion).Trim()
if (-not $PyExe -or -not (Test-Path $PyExe)) { throw "Could not resolve CPython $PythonVersion via uv" }
$PyHome = Split-Path -Parent $PyExe
Write-Host "Using Python home: $PyHome"

if (-not (Test-Path (Join-Path $PyHome 'pythonw.exe'))) {
  throw "Embedded Python at $PyHome has no pythonw.exe"
}
& (Join-Path $PyHome 'python.exe') -c 'import tkinter' 2>$null
if ($LASTEXITCODE -ne 0) { throw "Embedded Python at $PyHome has no tkinter; pick another version." }

# --- Assemble the bundle ----------------------------------------------------
$PyDest = Join-Path $BundleDir 'python'
Write-Host "Copying runtime into $PyDest"
Copy-Item -Recurse -Force $PyHome $PyDest
# Drop test / cache trees to keep the download small.
foreach ($junk in @('Lib\test', 'Lib\idlelib', 'Lib\turtledemo', 'Lib\ensurepip')) {
  $p = Join-Path $PyDest $junk
  if (Test-Path $p) { Remove-Item -Recurse -Force $p }
}
Get-ChildItem -Path $PyDest -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Copy-Item -Force (Join-Path $PanelDir 'app.py') (Join-Path $BundleDir 'app.py')
$TriggersDest = Join-Path $BundleDir 'triggers'
New-Item -ItemType Directory -Force -Path $TriggersDest | Out-Null
Copy-Item -Recurse -Force (Join-Path $TriggersSrc '*') $TriggersDest
Get-ChildItem -Path $TriggersDest -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- Compile the launcher with MSVC ----------------------------------------
$LauncherExe = Join-Path $BundleDir "$AppName.exe"
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere not found at $vswhere (Visual Studio C++ tools required)" }
$vsPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsPath) { throw 'No Visual Studio installation with the C++ toolset was found' }
Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -no_logo'

# Compile to a space-free name, then rename, to avoid native-arg quoting of
# the display name with spaces.
Push-Location $BundleDir
try {
  cl /nologo /O2 /MD (Join-Path $PanelDir 'launcher_windows.c') `
    /Fe:panel_launcher.exe `
    /link /SUBSYSTEM:WINDOWS shell32.lib shlwapi.lib user32.lib
  if ($LASTEXITCODE -ne 0) { throw "cl failed to build the launcher ($LASTEXITCODE)" }
  Remove-Item -Force 'launcher_windows.obj' -ErrorAction SilentlyContinue
} finally {
  Pop-Location
}
$BuiltExe = Join-Path $BundleDir 'panel_launcher.exe'
if (-not (Test-Path $BuiltExe)) { throw "Launcher not produced: $BuiltExe" }
Move-Item -Force $BuiltExe $LauncherExe
if (-not (Test-Path $LauncherExe)) { throw "Launcher not produced: $LauncherExe" }

# Exercise the embedded runtime before sealing.
& (Join-Path $PyDest 'python.exe') -c 'import tkinter, sys; print("embedded python ok:", sys.version.split()[0], "tk", tkinter.TkVersion)'
if ($LASTEXITCODE -ne 0) { throw 'Embedded runtime failed its tkinter self-check' }

# --- Authenticode-sign the launcher (CI only) ------------------------------
if ($env:AZURE_SIGN_KEY_VAULT_URI -and $env:AZURE_SIGN_CLIENT_ID) {
  Write-Host 'Signing the launcher with AzureSignTool...'
  AzureSignTool sign `
    -kvt $env:AZURE_SIGN_TENANT_ID `
    -kvu $env:AZURE_SIGN_KEY_VAULT_URI `
    -kvi $env:AZURE_SIGN_CLIENT_ID `
    -kvs $env:AZURE_SIGN_CLIENT_SECRET `
    -kvc $env:AZURE_SIGN_CERT_NAME `
    -tr http://timestamp.digicert.com -v "$LauncherExe"
  if ($LASTEXITCODE -ne 0) { throw "AzureSignTool failed ($LASTEXITCODE)" }
} else {
  Write-Host 'AZURE_SIGN_* not set; launcher left unsigned (local build).'
}

# --- Zip --------------------------------------------------------------------
$ZipName = "edamame-trigger-panel-windows-x64-$Version.zip"
$ZipPath = Join-Path $DistDir $ZipName
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
# Keep the parent folder so the zip extracts into a named directory with the
# launcher, app.py, python\ and triggers\ together.
Compress-Archive -Path $BundleDir -DestinationPath $ZipPath

Write-Host "Built: $BundleDir"
Write-Host "Zip:   $ZipPath"
# Emit the marker on the success stream so a caller capturing output sees it.
Write-Output "ARTIFACT=$ZipPath"
