<#
.SYNOPSIS
    Single-session runner for all M365 lab scripts.
.DESCRIPTION
    Connects once to Microsoft Graph and runs selected scripts without re-auth.
#>

param(
    [switch]$SetupUsers,
    [switch]$IntroduceProblems,
    [switch]$IntroduceMigrationIssues,
    [switch]$Verify,
    [switch]$All
)

$ErrorActionPreference = "Continue"
$TenantDomain = "8k8232.onmicrosoft.com"

# All scopes needed for any script
$AllScopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Application.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Organization.Read.All"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "M365 Lab - Single Session Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Connect once with all scopes
$context = Get-MgContext
if (-not $context) {
    Write-Host "`nConnecting to Microsoft Graph (one-time auth)..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $AllScopes -UseDeviceCode -NoWelcome
    Write-Host "Connected!`n" -ForegroundColor Green
} else {
    Write-Host "Already connected to: $($context.TenantId)" -ForegroundColor Green
}

# Determine what to run
if ($All) {
    $SetupUsers = $true
    $IntroduceProblems = $true
    $IntroduceMigrationIssues = $true
    $Verify = $true
}

if (-not ($SetupUsers -or $IntroduceProblems -or $IntroduceMigrationIssues -or $Verify)) {
    Write-Host "Usage: ./run-all.ps1 [-SetupUsers] [-IntroduceProblems] [-IntroduceMigrationIssues] [-Verify] [-All]" -ForegroundColor Yellow
    Write-Host "`nExamples:" -ForegroundColor White
    Write-Host "  ./run-all.ps1 -All                          # Run everything" -ForegroundColor Gray
    Write-Host "  ./run-all.ps1 -IntroduceProblems -IntroduceMigrationIssues  # Just problems" -ForegroundColor Gray
    Write-Host "  ./run-all.ps1 -Verify                       # Just verify" -ForegroundColor Gray
    exit
}

# Helper to run scripts without re-auth
function Invoke-LabScript {
    param([string]$ScriptName, [string]$Description)

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Running: $Description" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $scriptPath = Join-Path $PSScriptRoot $ScriptName
    if (Test-Path $scriptPath) {
        # Source the script content but skip the Connect-MgGraph calls
        $content = Get-Content $scriptPath -Raw

        # Remove the connect block from the script
        $pattern = '(?s)\$context = Get-MgContext.*?Connect-MgGraph[^\n]*\n'
        $modifiedContent = $content -replace $pattern, '# [Auth handled by runner]`n'

        # Also remove standalone Connect-MgGraph calls
        $modifiedContent = $modifiedContent -replace 'Connect-MgGraph[^\n]*-UseDeviceCode[^\n]*\n', '# [Auth handled by runner]`n'

        # Execute the modified script
        $scriptBlock = [ScriptBlock]::Create($modifiedContent)
        & $scriptBlock
    } else {
        Write-Host "Script not found: $scriptPath" -ForegroundColor Red
    }
}

# Run selected scripts
if ($SetupUsers) {
    Invoke-LabScript -ScriptName "setup-m365-lab.ps1" -Description "Setup 100 Users"
}

if ($IntroduceProblems) {
    Invoke-LabScript -ScriptName "introduce-problems.ps1" -Description "Introduce Assessment Problems"
}

if ($IntroduceMigrationIssues) {
    Invoke-LabScript -ScriptName "introduce-migration-issues.ps1" -Description "Introduce Migration Issues"
}

if ($Verify) {
    Invoke-LabScript -ScriptName "verify-setup.ps1" -Description "Verify Setup"
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "All selected scripts completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
