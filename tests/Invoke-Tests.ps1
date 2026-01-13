# Run Pester tests for the FolioClient module
param(
    [string]$TestPath = (Join-Path $PSScriptRoot 'FolioClient.Tests.ps1')
)

Write-Host "Ensuring Pester is installed..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name Pester)) {
    try {
        Install-Module -Name Pester -Force -Scope CurrentUser -MinimumVersion 5.0.0
    } catch {
        Write-Warning "Failed to install Pester automatically. Please run: Install-Module Pester -Scope CurrentUser"
    }
}

Write-Host "Running tests at $TestPath" -ForegroundColor Cyan
Invoke-Pester -Path $TestPath -Output Detailed