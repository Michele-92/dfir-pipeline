# DFIR Pipeline — Daten-Setup fuer Windows
# Verwendung: cd dfir_pipeline\data && powershell -ExecutionPolicy Bypass -File setup_data.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "=== DFIR Pipeline - Daten-Setup ===" -ForegroundColor Cyan

# 1. MITRE ATT&CK v15 (~80 MB)
$mitreFile = "enterprise-attack-v15.json"
$mitreUrl  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

if ((Test-Path $mitreFile) -and (Get-Item $mitreFile).Length -gt 1000) {
    Write-Host "[1/4] MITRE ATT&CK v15 bereits vorhanden - uebersprungen." -ForegroundColor Green
} else {
    Write-Host "[1/4] Lade MITRE ATT&CK v15 (~80 MB)..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $mitreUrl -OutFile $mitreFile -UseBasicParsing
    Write-Host "  MITRE ATT&CK v15 gespeichert." -ForegroundColor Green
}

# 2. YARA Community-Regeln
if (Test-Path "yara-rules\community\.git") {
    Write-Host "[2/4] YARA Community-Regeln bereits vorhanden - uebersprungen." -ForegroundColor Green
} else {
    Write-Host "[2/4] Klone YARA Community-Regeln..." -ForegroundColor Yellow
    if (Test-Path "yara-rules\community") { Remove-Item "yara-rules\community" -Recurse -Force }
    git clone --depth=1 https://github.com/Yara-Rules/rules yara-rules\community
    Write-Host "  YARA Community-Regeln gespeichert." -ForegroundColor Green
}

# 3. Signature-Base (Florian Roth)
if (Test-Path "yara-rules\signature-base\.git") {
    Write-Host "[3/4] Signature-Base bereits vorhanden - uebersprungen." -ForegroundColor Green
} else {
    Write-Host "[3/4] Klone Signature-Base..." -ForegroundColor Yellow
    if (Test-Path "yara-rules\signature-base") { Remove-Item "yara-rules\signature-base" -Recurse -Force }
    git clone --depth=1 https://github.com/Neo23x0/signature-base yara-rules\signature-base
    Write-Host "  Signature-Base gespeichert." -ForegroundColor Green
}

# 4. Sigma-Regeln (SigmaHQ)
if (Test-Path "sigma-rules\.git") {
    Write-Host "[4/4] Sigma-Regeln bereits vorhanden - uebersprungen." -ForegroundColor Green
} else {
    Write-Host "[4/4] Klone Sigma-Regeln..." -ForegroundColor Yellow
    if (Test-Path "sigma-rules") { Remove-Item "sigma-rules" -Recurse -Force }
    git clone --depth=1 https://github.com/SigmaHQ/sigma sigma-rules
    Write-Host "  Sigma-Regeln gespeichert." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Setup abgeschlossen ===" -ForegroundColor Cyan
Write-Host "Inhalt von data\:" -ForegroundColor Cyan
Get-ChildItem . | Format-Table Name, Length, LastWriteTime
