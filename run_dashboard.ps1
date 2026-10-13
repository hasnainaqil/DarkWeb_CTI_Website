param(
  [string]$PgHost,
  [int]$Port,
  [string]$Database,
  [string]$User,
  [string]$Table,
  [string]$SslMode,
  [string]$DatabaseUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
  Write-Host "DarkWeb CTI Dashboard" -ForegroundColor Cyan
  Write-Host "Working folder: $PSScriptRoot" -ForegroundColor Cyan

  # Run from this folder
  Set-Location $PSScriptRoot

# Use the workspace venv (one level up)
$python = Join-Path (Split-Path $PSScriptRoot -Parent) '.venv\Scripts\python.exe'

if (-not (Test-Path $python)) {
  throw "Workspace venv not found at: $python"
}

# Defaults for this project (Supabase Session Pooler)
$defaultPgHost = 'aws-1-ap-northeast-2.pooler.supabase.com'
$defaultPort = 5432
$defaultDatabase = 'postgres'
$defaultUser = 'postgres.ypefuoljwvczzmivbgmb'
$defaultTable = 'public."DarkWeb_CTI_Data"'
$defaultSslMode = 'require'

if (-not [string]::IsNullOrWhiteSpace($DatabaseUrl)) {
  $env:DATABASE_URL = $DatabaseUrl
}

if ([string]::IsNullOrWhiteSpace($env:DATABASE_URL)) {
  if ([string]::IsNullOrWhiteSpace($env:PGHOST)) {
    $env:PGHOST = $(if (-not [string]::IsNullOrWhiteSpace($PgHost)) { $PgHost } else { $defaultPgHost })
  }
  if ([string]::IsNullOrWhiteSpace($env:PGPORT)) {
    $env:PGPORT = $(if ($Port -gt 0) { "$Port" } else { "$defaultPort" })
  }
  if ([string]::IsNullOrWhiteSpace($env:PGDATABASE)) {
    $env:PGDATABASE = $(if (-not [string]::IsNullOrWhiteSpace($Database)) { $Database } else { $defaultDatabase })
  }
  if ([string]::IsNullOrWhiteSpace($env:PGUSER)) {
    $env:PGUSER = $(if (-not [string]::IsNullOrWhiteSpace($User)) { $User } else { $defaultUser })
  }
  if ([string]::IsNullOrWhiteSpace($env:PGSSLMODE)) {
    $env:PGSSLMODE = $(if (-not [string]::IsNullOrWhiteSpace($SslMode)) { $SslMode } else { $defaultSslMode })
  }
  if ([string]::IsNullOrWhiteSpace($env:DWCTI_TABLE)) {
    $env:DWCTI_TABLE = $(if (-not [string]::IsNullOrWhiteSpace($Table)) { $Table } else { $defaultTable })
  }
}

$hasDatabaseUrl = -not [string]::IsNullOrWhiteSpace($env:DATABASE_URL)
$hasPgHost = -not [string]::IsNullOrWhiteSpace($env:PGHOST)
$hasPgPassword = -not [string]::IsNullOrWhiteSpace($env:PGPASSWORD)

if (-not $hasDatabaseUrl -and $hasPgHost -and -not $hasPgPassword) {
  $secure = Read-Host "Supabase DB password" -AsSecureString
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  )
  $env:PGPASSWORD = $plain
  $hasPgPassword = $true
}

if (-not $hasDatabaseUrl -and (-not $hasPgHost -or -not $hasPgPassword)) {
  Write-Host "Missing database connection environment variables." -ForegroundColor Red
  Write-Host "Set DATABASE_URL, or set PGHOST and PGPASSWORD (plus PGPORT/PGDATABASE/PGUSER as needed)." -ForegroundColor Yellow
  Write-Host "If your network is IPv4-only, use Supabase Session Pooler host+port." -ForegroundColor Yellow
  exit 1
}

Write-Host "Starting dashboard with:" -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($env:DATABASE_URL)) {
  Write-Host "  DATABASE_URL is set" -ForegroundColor Cyan
} else {
  Write-Host "  PGHOST=$($env:PGHOST)" -ForegroundColor Cyan
  Write-Host "  PGPORT=$($env:PGPORT)" -ForegroundColor Cyan
  Write-Host "  PGDATABASE=$($env:PGDATABASE)" -ForegroundColor Cyan
  Write-Host "  PGUSER=$($env:PGUSER)" -ForegroundColor Cyan
  Write-Host "  PGSSLMODE=$($env:PGSSLMODE)" -ForegroundColor Cyan
}
Write-Host "  DWCTI_TABLE=$($env:DWCTI_TABLE)" -ForegroundColor Cyan

& $python -m streamlit run .\dashboard_app.py
}
catch {
  Write-Host "\nDashboard failed to start:" -ForegroundColor Red
  Write-Host $_ -ForegroundColor Red
  Write-Host "\nTip: In VS Code use Command Palette → 'PowerShell: Run File' to see prompts/output." -ForegroundColor Yellow
  Read-Host "Press Enter to close"
  exit 1
}

