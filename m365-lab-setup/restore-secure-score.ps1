#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Restores secure score settings after demo.
.DESCRIPTION
    Re-enables security controls that were disabled for demo purposes.
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com"
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes @(
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.Authorization",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "User.ReadWrite.All"
    ) -UseDeviceCode -NoWelcome
}

Write-Log "========================================" -Level "INFO"
Write-Log "Restoring Secure Score Settings" -Level "INFO"
Write-Log "========================================" -Level "INFO"

# 1. Re-enable Security Defaults
Write-Log "`nRe-enabling security defaults..." -Level "INFO"
try {
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled:$true
    Write-Log "Security defaults ENABLED" -Level "SUCCESS"
} catch {
    Write-Log "Could not enable security defaults: $_" -Level "ERROR"
}

# 2. Remove excessive roles from Tony Stark
Write-Log "`nRemoving excessive roles from Tony Stark..." -Level "INFO"
$targetUser = Get-MgUser -Filter "displayName eq 'Tony Stark'" -ErrorAction SilentlyContinue
if ($targetUser) {
    $rolesToRemove = @("Global Administrator", "Exchange Administrator", "SharePoint Administrator", "Teams Administrator", "Security Administrator")
    foreach ($roleName in $rolesToRemove) {
        try {
            $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
            if ($role) {
                Remove-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $targetUser.Id -ErrorAction SilentlyContinue
                Write-Log "  Removed $roleName" -Level "SUCCESS"
            }
        } catch { }
    }
}

# 3. Remove unprotected admin
Write-Log "`nRemoving unprotected admin account..." -Level "INFO"
try {
    $unprotectedAdmin = Get-MgUser -Filter "userPrincipalName eq 'unprotected-admin@$TenantDomain'" -ErrorAction SilentlyContinue
    if ($unprotectedAdmin) {
        Remove-MgUser -UserId $unprotectedAdmin.Id
        Write-Log "Removed unprotected-admin" -Level "SUCCESS"
    }
} catch {
    Write-Log "Could not remove unprotected admin: $_" -Level "ERROR"
}

# 4. Restrict app consent
Write-Log "`nRestricting app consent settings..." -Level "INFO"
try {
    $params = @{
        DefaultUserRolePermissions = @{
            AllowedToCreateApps = $false
            AllowedToCreateSecurityGroups = $true
            AllowedToReadOtherUsers = $true
            PermissionGrantPoliciesAssigned = @()
        }
    }
    Update-MgPolicyAuthorizationPolicy -BodyParameter $params -ErrorAction SilentlyContinue
    Write-Log "App consent restricted" -Level "SUCCESS"
} catch {
    Write-Log "Could not update app consent: $_" -Level "ERROR"
}

Write-Log "`n========================================" -Level "INFO"
Write-Log "Restoration Complete!" -Level "SUCCESS"
Write-Log "========================================" -Level "INFO"
Write-Log "Secure Score will update within 24-48 hours" -Level "INFO"

# Remove degradation manifest
$manifestPath = "$PSScriptRoot/secure-score-degradation.json"
if (Test-Path $manifestPath) {
    Remove-Item $manifestPath
    Write-Log "Removed degradation manifest" -Level "SUCCESS"
}
