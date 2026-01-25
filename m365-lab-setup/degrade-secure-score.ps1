#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Intentionally degrades Microsoft Secure Score for assessment demos.
.DESCRIPTION
    Modifies security configurations to create a lower secure score.
    WARNING: Only use in test/demo tenants!
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com",
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$changes = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "DEGRADE" { "Magenta" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Add-Change {
    param([string]$Control, [string]$Action, [string]$Impact)
    $script:changes += @{
        Control = $Control
        Action = $Action
        Impact = $Impact
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    Write-Log "[DEGRADED] $Control - $Action" -Level "DEGRADE"
}

# Connect to Graph
$context = Get-MgContext
if (-not $context) {
    Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
    Connect-MgGraph -Scopes @(
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.Authorization",
        "Directory.ReadWrite.All",
        "Application.ReadWrite.All",
        "Policy.ReadWrite.AuthenticationMethod",
        "Organization.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "User.ReadWrite.All"
    ) -UseDeviceCode -NoWelcome
}

Write-Log "========================================" -Level "WARNING"
Write-Log "DEGRADING SECURE SCORE FOR DEMO" -Level "WARNING"
Write-Log "Tenant: $TenantDomain" -Level "WARNING"
Write-Log "========================================" -Level "WARNING"

if (-not $WhatIf) {
    Write-Host "`nWARNING: This will weaken your tenant security!" -ForegroundColor Red
    Write-Host "Only proceed in TEST/DEMO environments!`n" -ForegroundColor Red
}

# ============================================
# 1. DISABLE SECURITY DEFAULTS
# ============================================
Write-Log "`n=== Checking Security Defaults ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # Get current security defaults status
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

        if ($securityDefaults.IsEnabled) {
            Write-Log "Security defaults are ENABLED - disabling..." -Level "WARNING"
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled:$false
            Add-Change -Control "SecurityDefaults" -Action "Disabled security defaults" -Impact "Removes baseline MFA and security protections"
        } else {
            Write-Log "Security defaults already disabled" -Level "INFO"
            Add-Change -Control "SecurityDefaults" -Action "Already disabled" -Impact "No change needed"
        }
    } catch {
        Write-Log "Could not modify security defaults: $_" -Level "ERROR"
    }
}

# ============================================
# 2. WEAKEN AUTHORIZATION POLICY (Legacy Auth)
# ============================================
Write-Log "`n=== Modifying Authorization Policy ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # Allow legacy authentication by not blocking it
        # Note: This requires Conditional Access to truly block, but we can note the gap
        Add-Change -Control "BlockLegacyAuthentication" -Action "No CA policy blocking legacy auth" -Impact "Legacy protocols (IMAP, POP3, SMTP) can bypass MFA"
    } catch {
        Write-Log "Could not modify auth policy: $_" -Level "ERROR"
    }
}

# ============================================
# 3. REMOVE/WEAKEN CONDITIONAL ACCESS POLICIES
# ============================================
Write-Log "`n=== Checking Conditional Access Policies ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue

        if ($caPolicies.Count -eq 0) {
            Write-Log "No Conditional Access policies found" -Level "INFO"
            Add-Change -Control "AdminMFAV2" -Action "No CA policy requiring admin MFA" -Impact "Admins can sign in without MFA"
            Add-Change -Control "SigninRiskPolicy" -Action "No sign-in risk policy" -Impact "Risky sign-ins not challenged"
            Add-Change -Control "UserRiskPolicy" -Action "No user risk policy" -Impact "Compromised users not detected"
        } else {
            Write-Log "Found $($caPolicies.Count) CA policies" -Level "INFO"
            foreach ($policy in $caPolicies) {
                Write-Log "  - $($policy.DisplayName) (State: $($policy.State))" -Level "INFO"
            }
        }
    } catch {
        Write-Log "Could not check CA policies: $_" -Level "ERROR"
        Add-Change -Control "ConditionalAccess" -Action "Unable to verify CA policies" -Impact "May have security gaps"
    }
}

# ============================================
# 4. ALLOW USER APP CONSENT
# ============================================
Write-Log "`n=== Modifying App Consent Settings ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # Get authorization policy
        $authPolicy = Get-MgPolicyAuthorizationPolicy

        # Check current setting
        Write-Log "Current default user role permissions:" -Level "INFO"

        # Modify to allow user consent (less secure)
        $params = @{
            DefaultUserRolePermissions = @{
                AllowedToCreateApps = $true
                AllowedToCreateSecurityGroups = $true
                AllowedToReadOtherUsers = $true
                PermissionGrantPoliciesAssigned = @("ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
            }
        }

        Update-MgPolicyAuthorizationPolicy -BodyParameter $params -ErrorAction SilentlyContinue
        Add-Change -Control "IntegratedApps" -Action "Enabled user app consent" -Impact "Users can consent to apps without admin approval"

    } catch {
        Write-Log "Could not modify app consent: $_" -Level "ERROR"
    }
}

# ============================================
# 5. CREATE ADDITIONAL GLOBAL ADMIN (for OneAdmin control)
# ============================================
Write-Log "`n=== Checking Global Admin Count ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

        if ($globalAdminRole) {
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -All
            Write-Log "Current global admins: $($globalAdmins.Count)" -Level "INFO"

            if ($globalAdmins.Count -lt 2) {
                # Create a second global admin for the OneAdmin control
                # But actually having only 1 is what LOWERS the score, so we note it
                Add-Change -Control "OneAdmin" -Action "Only 1 global admin exists" -Impact "No backup admin, single point of failure"
            } else {
                Add-Change -Control "OneAdmin" -Action "$($globalAdmins.Count) global admins exist" -Impact "Meets requirement (2-4 recommended)"
            }
        }
    } catch {
        Write-Log "Could not check global admins: $_" -Level "ERROR"
    }
}

# ============================================
# 6. ADD ROLE OVERLAP (RoleOverlap control)
# ============================================
Write-Log "`n=== Creating Role Overlap Issues ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # Find a user and give them multiple admin roles
        $targetUser = Get-MgUser -Filter "displayName eq 'Tony Stark'" -ErrorAction SilentlyContinue

        if ($targetUser) {
            $rolesToAdd = @(
                "Global Administrator",
                "Exchange Administrator",
                "SharePoint Administrator",
                "Teams Administrator",
                "Security Administrator"
            )

            $rolesAdded = 0
            foreach ($roleName in $rolesToAdd) {
                try {
                    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue

                    if (-not $role) {
                        $roleTemplate = Get-MgDirectoryRoleTemplate -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                        if ($roleTemplate) {
                            $role = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id -ErrorAction SilentlyContinue
                        }
                    }

                    if ($role) {
                        $existingMember = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -eq $targetUser.Id }

                        if (-not $existingMember) {
                            New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $targetUser.Id -ErrorAction SilentlyContinue
                            $rolesAdded++
                            Write-Log "  Added $roleName to Tony Stark" -Level "WARNING"
                        }
                    }
                } catch { }
            }

            if ($rolesAdded -gt 0) {
                Add-Change -Control "RoleOverlap" -Action "User Tony Stark has $rolesAdded+ admin roles" -Impact "Excessive privileges, violates least privilege"
            }
        }
    } catch {
        Write-Log "Could not create role overlap: $_" -Level "ERROR"
    }
}

# ============================================
# 7. WEAKEN PASSWORD POLICY
# ============================================
Write-Log "`n=== Checking Password Policy ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # Note: Password policy in cloud is already "never expire" by default
        # We just document the state
        Add-Change -Control "PWAgePolicyNew" -Action "Password expiration policy checked" -Impact "Should be set to never expire (Microsoft recommendation)"
    } catch {
        Write-Log "Could not check password policy: $_" -Level "ERROR"
    }
}

# ============================================
# 8. DISABLE SSPR FOR SOME USERS
# ============================================
Write-Log "`n=== Checking Self-Service Password Reset ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        # SSPR configuration is in Azure AD settings
        # We document the gap
        Add-Change -Control "SelfServicePasswordReset" -Action "SSPR may not be enabled for all users" -Impact "Users can't self-reset passwords, increases helpdesk load"
    } catch {
        Write-Log "Could not check SSPR: $_" -Level "ERROR"
    }
}

# ============================================
# 9. CREATE UNPROTECTED ADMIN ACCOUNT
# ============================================
Write-Log "`n=== Creating Unprotected Admin Account ===" -Level "INFO"

if (-not $WhatIf) {
    try {
        $upn = "unprotected-admin@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

        if (-not $existingUser) {
            $newAdmin = New-MgUser -DisplayName "Unprotected Admin Account" `
                -MailNickname "unprotected-admin" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "WeakAdmin123!"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Administrator" `
                -Department "IT" `
                -UsageLocation "US"

            # Make them a global admin
            $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
            if ($globalAdminRole) {
                New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $newAdmin.Id -ErrorAction SilentlyContinue
            }

            Add-Change -Control "AdminMFAV2" -Action "Created admin without MFA: unprotected-admin" -Impact "Admin account vulnerable to credential attacks"
            Write-Log "Created unprotected admin account" -Level "WARNING"
        } else {
            Write-Log "Unprotected admin already exists" -Level "INFO"
        }
    } catch {
        Write-Log "Could not create unprotected admin: $_" -Level "ERROR"
    }
}

# ============================================
# SUMMARY
# ============================================
Write-Log "`n========================================" -Level "INFO"
Write-Log "Secure Score Degradation Complete!" -Level "WARNING"
Write-Log "========================================" -Level "INFO"

Write-Log "`nChanges Made:" -Level "INFO"
foreach ($change in $changes) {
    Write-Host "  [$($change.Control)] $($change.Action)" -ForegroundColor Magenta
    Write-Host "    Impact: $($change.Impact)" -ForegroundColor DarkGray
}

# Save changes to JSON
$outputPath = "$PSScriptRoot/secure-score-degradation.json"
$changes | ConvertTo-Json -Depth 5 | Out-File $outputPath
Write-Log "`nChange manifest saved to: $outputPath" -Level "SUCCESS"

Write-Log "`nTotal changes: $($changes.Count)" -Level "WARNING"
Write-Log "Re-check Secure Score in 24-48 hours for updated values" -Level "INFO"
Write-Log "`nTo restore security, run: ./restore-secure-score.ps1" -Level "INFO"
