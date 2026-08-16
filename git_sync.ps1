<#
  git_sync.ps1 - commit this folder's work and push to GitHub, keeping file history.

  Why a script: the assistant's sandbox can't reach api.github.com and can't manage
  the OneDrive .git, so committing/pushing runs here on your machine.

  Run from this folder (right-click > Run with PowerShell, or):
      powershell -ExecutionPolicy Bypass -File .\git_sync.ps1
  Optional:
      .\git_sync.ps1 -Repo "AI-Agent-Security" -Private $true -Message "my note"

  It reads GITHUB_ACCESS_TOKEN from .env (never printed, never committed), ensures the
  repo exists (creates it private if missing), commits, and pushes. .gitignore keeps
  .env, model weights, and the vendored SDK out of the repo. Re-run anytime (or schedule
  it) to keep history.
#>
param(
  [string]$Repo = "AI-Agent-Security",
  [bool]$Private = $true,
  [string]$Message = ""
)
Set-Location -Path $PSScriptRoot

# 1) Token from .env
if (-not (Test-Path ".env")) { throw ".env not found (need GITHUB_ACCESS_TOKEN=...)" }
$line = Get-Content ".env" | Where-Object { $_ -match '^\s*GITHUB_ACCESS_TOKEN\s*=' } | Select-Object -First 1
$token = ($line -replace '^\s*GITHUB_ACCESS_TOKEN\s*=\s*','').Trim()
if (-not $token) { throw "GITHUB_ACCESS_TOKEN missing in .env" }
$headers = @{ Authorization = "Bearer $token"; "User-Agent" = "aas-sync"; Accept = "application/vnd.github+json" }

# 2) Who am I
$me = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/user"
$login = $me.login
Write-Host "GitHub user: $login"
$repoFull = "$login/$Repo"

# 3) Ensure repo exists (create private if missing)
try {
  Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repoFull" | Out-Null
  Write-Host "Repo exists: $repoFull"
} catch {
  Write-Host "Creating repo $repoFull (private=$Private)"
  $body = @{ name = $Repo; private = $Private; auto_init = $false } | ConvertTo-Json
  Invoke-RestMethod -Headers $headers -Method Post -Uri "https://api.github.com/user/repos" -Body $body | Out-Null
}

# 4) Local git hygiene
if (Test-Path ".git\index.lock") { Remove-Item -Force ".git\index.lock" -ErrorAction SilentlyContinue }
if (-not (Test-Path ".git")) { git init | Out-Null }
if (-not (git config user.name))  { git config user.name  "Rishav" }
if (-not (git config user.email)) { git config user.email "rrishavrraj@gmail.com" }

# 5) Stage + commit (only if there are changes). .gitignore excludes .env / SDK / weights.
git add -A
$pending = git status --porcelain
if ($pending) {
  if (-not $Message) { $Message = "sync: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
  git commit -m $Message | Out-Null
  Write-Host "Committed: $Message"
} else {
  Write-Host "Nothing new to commit."
}
git branch -M main

# 6) Push with an ephemeral token URL (token is NOT written to .git\config)
$pushUrl = "https://x-access-token:$token@github.com/$repoFull.git"
git push $pushUrl main
Write-Host "Pushed -> https://github.com/$repoFull"
