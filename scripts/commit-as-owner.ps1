# Single-author commit without IDE co-author trailers (use from repo root).
param(
  [Parameter(Mandatory = $true)]
  [string]$Message
)
$ErrorActionPreference = "Stop"
$emptyHooks = Join-Path (Join-Path $PSScriptRoot "..") ".empty_hooks"
if (-not (Test-Path $emptyHooks)) { New-Item -ItemType Directory -Path $emptyHooks | Out-Null }
$env:GIT_AUTHOR_NAME = "Hassan Khodaiemehr"
$env:GIT_AUTHOR_EMAIL = "hassankhodaiemehr@gmail.com"
$env:GIT_COMMITTER_NAME = "Hassan Khodaiemehr"
$env:GIT_COMMITTER_EMAIL = "hassankhodaiemehr@gmail.com"
git -c core.hooksPath=$emptyHooks commit -m $Message
