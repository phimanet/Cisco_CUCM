Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

git config core.hooksPath .githooks

Write-Host "Protected script lock enabled for this repo."
$hooksPath = git config --get core.hooksPath
Write-Host "hooksPath=$hooksPath"
