<#
.SYNOPSIS
    Checks prerequisites for running the M365 lab setup.
.DESCRIPTION
    Verifies Microsoft Graph modules are installed and checks available licenses.
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com"
)

$ErrorActionPreference = "Continue"
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "M365 Lab Setup - Prerequisites Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check PowerShell version
Write-Host "`n[1/4] Checking PowerShell version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
Write-Host "  PowerShell version: $psVersion" -ForegroundColor White
if ($psVersion.Major -ge 7) {
    Write-Host "  [OK] PowerShell 7+ detected" -ForegroundColor Green
} elseif ($psVersion.Major -ge 5) {
    Write-Host "  [OK] PowerShell 5.1 detected (7+ recommended)" -ForegroundColor Yellow
} else {
    Write-Host "  [ERROR] PowerShell 5.1+ required" -ForegroundColor Red
    exit 1
}

# Check required modules
Write-Host "`n[2/4] Checking Microsoft Graph modules..." -ForegroundColor Yellow
$missingModules = @()

foreach ($module in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $module
    if ($installed) {
        Write-Host "  [OK] $module (v$($installed.Version))" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $module" -ForegroundColor Red
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "`n  To install missing modules, run:" -ForegroundColor Yellow
    Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
    Write-Host "`n  Or install individual modules:" -ForegroundColor Yellow
    foreach ($module in $missingModules) {
        Write-Host "  Install-Module $module -Scope CurrentUser" -ForegroundColor Cyan
    }
}

# Check Graph connection and permissions
Write-Host "`n[3/4] Checking Microsoft Graph connection..." -ForegroundColor Yellow

try {
    $context = Get-MgContext
    if ($context) {
        Write-Host "  [OK] Connected to tenant: $($context.TenantId)" -ForegroundColor Green
        Write-Host "  Account: $($context.Account)" -ForegroundColor White

        # Check scopes
        $requiredScopes = @("User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All")
        $hasAllScopes = $true

        Write-Host "  Checking required scopes..." -ForegroundColor White
        foreach ($scope in $requiredScopes) {
            if ($context.Scopes -contains $scope) {
                Write-Host "    [OK] $scope" -ForegroundColor Green
            } else {
                Write-Host "    [MISSING] $scope" -ForegroundColor Red
                $hasAllScopes = $false
            }
        }

        if (-not $hasAllScopes) {
            Write-Host "`n  To reconnect with required scopes, run:" -ForegroundColor Yellow
            Write-Host "  Disconnect-MgGraph" -ForegroundColor Cyan
            Write-Host "  Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Directory.ReadWrite.All' -UseDeviceCode" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  [NOT CONNECTED] Run the following to connect:" -ForegroundColor Yellow
        Write-Host "  Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Directory.ReadWrite.All' -UseDeviceCode" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  [ERROR] Could not check Graph connection: $_" -ForegroundColor Red
}

# Check available licenses
Write-Host "`n[4/4] Checking available licenses..." -ForegroundColor Yellow

try {
    $context = Get-MgContext
    if ($context) {
        $licenses = Get-MgSubscribedSku -All

        Write-Host "  Available licenses:" -ForegroundColor White
        foreach ($license in $licenses) {
            $available = $license.PrepaidUnits.Enabled - $license.ConsumedUnits
            $status = if ($available -gt 0) { "Green" } else { "Red" }
            Write-Host "    $($license.SkuPartNumber): $($license.ConsumedUnits)/$($license.PrepaidUnits.Enabled) used ($available available)" -ForegroundColor $status
        }

        # Check specifically for E5 Developer license
        $e5License = $licenses | Where-Object { $_.SkuPartNumber -like "*DEVELOPERPACK*" -or $_.SkuPartNumber -like "*E5*" }
        if ($e5License) {
            $e5Available = $e5License.PrepaidUnits.Enabled - $e5License.ConsumedUnits
            if ($e5Available -ge 25) {
                Write-Host "`n  [OK] Sufficient E5 licenses available for 25 key users" -ForegroundColor Green
            } else {
                Write-Host "`n  [WARNING] Only $e5Available E5 licenses available (need 25)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [SKIPPED] Not connected to Graph" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [ERROR] Could not check licenses: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($missingModules.Count -eq 0) {
    Write-Host "[OK] All modules installed" -ForegroundColor Green
} else {
    Write-Host "[ACTION REQUIRED] Install missing modules" -ForegroundColor Red
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Install any missing modules (if needed)" -ForegroundColor White
Write-Host "2. Connect to Microsoft Graph with required scopes" -ForegroundColor White
Write-Host "3. Run: ./setup-m365-lab.ps1 -WhatIf    (preview mode)" -ForegroundColor Cyan
Write-Host "4. Run: ./setup-m365-lab.ps1            (execute)" -ForegroundColor Cyan
