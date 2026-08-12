# PowerShell script to run connector tests on Windows.
$ErrorActionPreference = "Stop"

# Set current directory to script folder
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "=== Setting up Python Virtual Environment ===" -ForegroundColor Cyan
if (-not (Test-Path "venv")) {
    python -m venv venv
}

# Activate virtual environment
if (Test-Path "venv\Scripts\Activate.ps1") {
    . venv\Scripts\Activate.ps1
} else {
    Write-Error "Virtual environment activation script not found."
}

Write-Host "=== Installing Dependencies ===" -ForegroundColor Cyan
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "=== Running Integration Tests ===" -ForegroundColor Cyan
$env:PYTHONPATH = $ScriptDir
pytest -v -s tests/

Write-Host "=== Tests completed successfully ===" -ForegroundColor Green
