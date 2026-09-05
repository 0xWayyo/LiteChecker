#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$entry = Join-Path $PSScriptRoot 'LiteChecker.bat'
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
    Write-Host 'LiteChecker: extract the complete Windows ZIP from GitHub Releases.'
    exit 2
}
& $entry
exit $LASTEXITCODE
