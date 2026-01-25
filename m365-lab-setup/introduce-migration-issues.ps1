#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Introduces pre-migration assessment issues.
.DESCRIPTION
    Creates issues typically found during M365 tenant migration assessments.
    All changes are free/no additional cost.
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com",
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$issuesCreated = @()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "PROBLEM" { "Magenta" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Add-Issue {
    param([string]$Category, [string]$Severity, [string]$Description, [string]$Details, [string]$MigrationImpact)
    $script:issuesCreated += @{
        Category = $Category
        Severity = $Severity
        Description = $Description
        Details = $Details
        MigrationImpact = $MigrationImpact
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    Write-Log "[MIGRATION ISSUE] $Description" -Level "PROBLEM"
}

# Connect to Graph if not connected
$context = Get-MgContext
if (-not $context) {
    Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
    Connect-MgGraph -Scopes @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Application.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory"
    ) -UseDeviceCode
}

Write-Log "========================================" -Level "INFO"
Write-Log "Introducing Pre-Migration Issues" -Level "INFO"
Write-Log "Tenant: $TenantDomain" -Level "INFO"
Write-Log "========================================" -Level "INFO"

$allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department, JobTitle, Mail, ProxyAddresses, AccountEnabled, AssignedLicenses
Write-Log "Found $($allUsers.Count) users" -Level "INFO"

# ============================================
# CATEGORY 1: UPN/EMAIL ISSUES
# ============================================
Write-Log "`n=== Creating UPN/Email Issues ===" -Level "WARNING"

# 1.1 Create users with UPN mismatch (UPN doesn't match primary SMTP)
Write-Log "Creating users with UPN/email mismatches..." -Level "INFO"
$upnMismatchUsers = @(
    @{ DisplayName = "John Smith (UPN Mismatch)"; MailNickname = "jsmith-mismatch"; GivenName = "John"; Surname = "Smith" },
    @{ DisplayName = "Jane Doe (UPN Mismatch)"; MailNickname = "jdoe-mismatch"; GivenName = "Jane"; Surname = "Doe" }
)

foreach ($user in $upnMismatchUsers) {
    if (-not $WhatIf) {
        try {
            $upn = "$($user.MailNickname)@$TenantDomain"
            $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                # Create user where the mail nickname suggests a different email pattern
                New-MgUser -DisplayName $user.DisplayName `
                    -MailNickname $user.MailNickname `
                    -UserPrincipalName $upn `
                    -GivenName $user.GivenName `
                    -Surname $user.Surname `
                    -AccountEnabled:$true `
                    -PasswordProfile @{ Password = "MigrateP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                    -UsageLocation "US" `
                    -Department "Migration Test"
                Add-Issue -Category "UPN/Email" -Severity "High" -Description "User with potential UPN mismatch: $($user.DisplayName)" -Details $upn -MigrationImpact "Mail routing issues post-migration"
            }
        } catch { Write-Log "Failed: $_" -Level "ERROR" }
    }
}

# 1.2 Create user with special characters that might cause issues
Write-Log "Creating users with problematic characters..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $upn = "user.with" + "dots@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser -DisplayName "User With.Multiple.Dots" `
                -MailNickname "user.with.dots" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "MigrateP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                -UsageLocation "US" `
                -Department "Migration Test"
            Add-Issue -Category "UPN/Email" -Severity "Medium" -Description "User with multiple dots in UPN" -Details $upn -MigrationImpact "Some systems don't handle dots well"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 2: LICENSE ISSUES
# ============================================
Write-Log "`n=== Creating License Issues ===" -Level "WARNING"

# 2.1 Create disabled users that still have licenses assigned
Write-Log "Finding disabled users with licenses (flagging existing)..." -Level "INFO"
$disabledWithLicense = $allUsers | Where-Object { $_.AccountEnabled -eq $false -and $_.AssignedLicenses.Count -gt 0 }
foreach ($user in $disabledWithLicense) {
    Add-Issue -Category "Licensing" -Severity "Medium" -Description "Disabled user with active license: $($user.DisplayName)" -Details $user.UserPrincipalName -MigrationImpact "Wasted license cost, cleanup needed pre-migration"
}

# 2.2 Create a user without license but should have one (based on role)
Write-Log "Creating users that should have licenses but don't..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $upn = "unlicensed-manager@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser -DisplayName "Unlicensed Manager" `
                -MailNickname "unlicensed-manager" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "MigrateP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Senior Manager" `
                -Department "Operations" `
                -UsageLocation "US"
            Add-Issue -Category "Licensing" -Severity "High" -Description "Manager-level user without license: Unlicensed Manager" -Details $upn -MigrationImpact "User won't have mailbox/services post-migration"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 3: GROUP NESTING ISSUES
# ============================================
Write-Log "`n=== Creating Group Nesting Issues ===" -Level "WARNING"

# 3.1 Create deeply nested groups (3+ levels)
Write-Log "Creating deeply nested group structure..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $level1 = Get-MgGroup -Filter "displayName eq 'Nested-Level-1'" -ErrorAction SilentlyContinue
        if (-not $level1) {
            $level1 = New-MgGroup -DisplayName "Nested-Level-1" -Description "Top level of nested group chain" -MailEnabled:$false -MailNickname "nested-level-1" -SecurityEnabled:$true
            Start-Sleep -Milliseconds 500

            $level2 = New-MgGroup -DisplayName "Nested-Level-2" -Description "Second level nesting" -MailEnabled:$false -MailNickname "nested-level-2" -SecurityEnabled:$true
            Start-Sleep -Milliseconds 500

            $level3 = New-MgGroup -DisplayName "Nested-Level-3" -Description "Third level nesting" -MailEnabled:$false -MailNickname "nested-level-3" -SecurityEnabled:$true
            Start-Sleep -Milliseconds 500

            $level4 = New-MgGroup -DisplayName "Nested-Level-4" -Description "Fourth level - too deep!" -MailEnabled:$false -MailNickname "nested-level-4" -SecurityEnabled:$true
            Start-Sleep -Milliseconds 500

            # Nest them
            New-MgGroupMember -GroupId $level1.Id -DirectoryObjectId $level2.Id -ErrorAction SilentlyContinue
            New-MgGroupMember -GroupId $level2.Id -DirectoryObjectId $level3.Id -ErrorAction SilentlyContinue
            New-MgGroupMember -GroupId $level3.Id -DirectoryObjectId $level4.Id -ErrorAction SilentlyContinue

            Add-Issue -Category "Groups" -Severity "High" -Description "Deeply nested group chain (4 levels)" -Details "Nested-Level-1 -> 2 -> 3 -> 4" -MigrationImpact "May cause sync issues, permission inheritance problems"
        }
    } catch { Write-Log "Failed to create nested groups: $_" -Level "ERROR" }
}

# 3.2 Create mail-enabled security group (hybrid artifact)
Write-Log "Creating mail-enabled security group..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'Mail-Enabled-Security-Group'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-MgGroup -DisplayName "Mail-Enabled-Security-Group" `
                -Description "Hybrid artifact - mail-enabled security group" `
                -MailEnabled:$true `
                -MailNickname "mail-enabled-sec" `
                -SecurityEnabled:$true `
                -GroupTypes @()
            Add-Issue -Category "Groups" -Severity "Medium" -Description "Mail-enabled security group (hybrid artifact)" -Details "mail-enabled-sec" -MigrationImpact "May have issues with cloud-only features"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 3.3 Create group with very long name
Write-Log "Creating group with problematic name length..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $longName = "This-Is-A-Very-Long-Group-Name-That-Might-Cause-Issues-During-Migration-Process-And-Should-Be-Flagged"
        $existingGroup = Get-MgGroup -Filter "displayName eq '$longName'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-MgGroup -DisplayName $longName `
                -Description "Group with excessively long name" `
                -MailEnabled:$false `
                -MailNickname "very-long-name-group" `
                -SecurityEnabled:$true
            Add-Issue -Category "Groups" -Severity "Low" -Description "Group with very long name (100+ chars)" -Details $longName -MigrationImpact "May truncate or cause display issues"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 4: APPLICATION MIGRATION ISSUES
# ============================================
Write-Log "`n=== Creating Application Migration Issues ===" -Level "WARNING"

# 4.1 Create app with credential expiring within migration window
Write-Log "Creating apps with near-expiry credentials..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'Migration-Critical-App'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            $app = New-MgApplication -DisplayName "Migration-Critical-App" `
                -Description "App with secret expiring during typical migration window" `
                -SignInAudience "AzureADMyOrg"

            # Add secret expiring in 14 days
            $expiryDate = (Get-Date).AddDays(14)
            Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
                DisplayName = "MigrationSecret"
                EndDateTime = $expiryDate
            } -ErrorAction SilentlyContinue

            Add-Issue -Category "Applications" -Severity "Critical" -Description "App with secret expiring in 14 days: Migration-Critical-App" -Details "Secret expires: $($expiryDate.ToString('yyyy-MM-dd'))" -MigrationImpact "Will break during migration if not renewed"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 4.2 Create app with hardcoded-looking tenant reference in name
Write-Log "Creating app suggesting hardcoded tenant ID..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'Legacy-App-8k8232-Tenant'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            New-MgApplication -DisplayName "Legacy-App-8k8232-Tenant" `
                -Description "WARNING: May have hardcoded tenant ID references in code" `
                -SignInAudience "AzureADMyOrg"
            Add-Issue -Category "Applications" -Severity "High" -Description "App with potential hardcoded tenant reference" -Details "Legacy-App-8k8232-Tenant" -MigrationImpact "May fail post-migration if tenant ID is hardcoded"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 4.3 Create multi-tenant app (might have external dependencies)
Write-Log "Creating multi-tenant app..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'Multi-Tenant-Integration'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            New-MgApplication -DisplayName "Multi-Tenant-Integration" `
                -Description "Multi-tenant app - verify all tenant relationships" `
                -SignInAudience "AzureADMultipleOrgs"
            Add-Issue -Category "Applications" -Severity "Medium" -Description "Multi-tenant application found" -Details "Multi-Tenant-Integration" -MigrationImpact "External tenant relationships need verification"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 5: MAILBOX/EXCHANGE ISSUES
# ============================================
Write-Log "`n=== Creating Mailbox Migration Issue Markers ===" -Level "WARNING"

# 5.1 Create shared mailbox user (simulated)
Write-Log "Creating shared mailbox indicators..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $upn = "shared-reception@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser -DisplayName "Reception Shared Mailbox" `
                -MailNickname "shared-reception" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "SharedP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Shared Mailbox" `
                -Department "Shared Resources" `
                -UsageLocation "US"
            Add-Issue -Category "Mailbox" -Severity "Medium" -Description "Shared mailbox with direct login enabled" -Details $upn -MigrationImpact "Should be converted to proper shared mailbox, disable sign-in"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 5.2 Create resource mailbox indicators
Write-Log "Creating resource mailbox indicators..." -Level "INFO"
$resourceMailboxes = @(
    @{ Name = "Conference Room A"; Nickname = "conf-room-a"; Type = "Room" },
    @{ Name = "Company Car Pool"; Nickname = "car-pool"; Type = "Equipment" },
    @{ Name = "Projector Booking"; Nickname = "projector"; Type = "Equipment" }
)

foreach ($resource in $resourceMailboxes) {
    if (-not $WhatIf) {
        try {
            $upn = "$($resource.Nickname)@$TenantDomain"
            $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-MgUser -DisplayName $resource.Name `
                    -MailNickname $resource.Nickname `
                    -UserPrincipalName $upn `
                    -AccountEnabled:$false `
                    -PasswordProfile @{ Password = "ResourceP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                    -JobTitle "$($resource.Type) Resource" `
                    -Department "Resources" `
                    -UsageLocation "US"
                Add-Issue -Category "Mailbox" -Severity "Low" -Description "Resource mailbox needs migration planning: $($resource.Name)" -Details "$upn ($($resource.Type))" -MigrationImpact "Resource mailboxes need special handling"
            }
        } catch { Write-Log "Failed: $_" -Level "ERROR" }
    }
}

# ============================================
# CATEGORY 6: DATA COMPLIANCE ISSUES
# ============================================
Write-Log "`n=== Creating Data/Compliance Migration Issues ===" -Level "WARNING"

# 6.1 Create group suggesting eDiscovery hold
Write-Log "Creating eDiscovery/legal hold indicators..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'Legal-Hold-Users-2023'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            $group = New-MgGroup -DisplayName "Legal-Hold-Users-2023" `
                -Description "LEGAL HOLD - Do not delete - Users under litigation hold for Case #2023-001" `
                -MailEnabled:$false `
                -MailNickname "legal-hold-2023" `
                -SecurityEnabled:$true

            # Add some random users
            $randomUsers = $allUsers | Where-Object { $_.AccountEnabled -eq $true } | Get-Random -Count 3
            foreach ($user in $randomUsers) {
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
            }
            Add-Issue -Category "Compliance" -Severity "Critical" -Description "Users under legal/litigation hold" -Details "Legal-Hold-Users-2023 (3 users)" -MigrationImpact "Cannot delete data, special migration procedures required"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 6.2 Create group for retention policy scope
Write-Log "Creating retention policy indicators..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'Financial-Records-7Year-Retention'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-MgGroup -DisplayName "Financial-Records-7Year-Retention" `
                -Description "Users subject to 7-year financial records retention - SOX compliance" `
                -MailEnabled:$false `
                -MailNickname "fin-retention-7yr" `
                -SecurityEnabled:$true
            Add-Issue -Category "Compliance" -Severity "High" -Description "Users under regulatory retention requirements" -Details "Financial-Records-7Year-Retention (SOX)" -MigrationImpact "Retention policies must be recreated in target tenant"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 6.3 Create GDPR-related group
Write-Log "Creating GDPR data subject indicators..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'GDPR-Data-Processors'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-MgGroup -DisplayName "GDPR-Data-Processors" `
                -Description "Users who process EU personal data - GDPR Article 30 records required" `
                -MailEnabled:$false `
                -MailNickname "gdpr-processors" `
                -SecurityEnabled:$true
            Add-Issue -Category "Compliance" -Severity "High" -Description "GDPR data processor tracking group" -Details "GDPR-Data-Processors" -MigrationImpact "Data processing records and DPA must be updated post-migration"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 7: HYBRID/SYNC ISSUES
# ============================================
Write-Log "`n=== Creating Hybrid/Sync Issue Indicators ===" -Level "WARNING"

# 7.1 Create user that looks like it should be synced
Write-Log "Creating potential sync conflict users..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $upn = "ad.sync.user@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser -DisplayName "AD Sync User (Cloud Only)" `
                -MailNickname "ad.sync.user" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "SyncP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Potential Sync Conflict" `
                -Department "IT" `
                -UsageLocation "US"
            Add-Issue -Category "Directory Sync" -Severity "High" -Description "Cloud user with AD-like naming convention" -Details $upn -MigrationImpact "May conflict with AD sync if hybrid is planned"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# 7.2 Create duplicate-looking users
Write-Log "Creating potential duplicate users..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $dupeUsers = @(
            @{ DisplayName = "Robert Johnson"; Nickname = "rjohnson1" },
            @{ DisplayName = "Bob Johnson"; Nickname = "bjohnson" },
            @{ DisplayName = "Robert B Johnson"; Nickname = "rbjohnson" }
        )

        foreach ($user in $dupeUsers) {
            $upn = "$($user.Nickname)@$TenantDomain"
            $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-MgUser -DisplayName $user.DisplayName `
                    -MailNickname $user.Nickname `
                    -UserPrincipalName $upn `
                    -AccountEnabled:$true `
                    -PasswordProfile @{ Password = "DupeP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                    -Department "Sales" `
                    -UsageLocation "US"
            }
        }
        Add-Issue -Category "Identity" -Severity "Medium" -Description "Potential duplicate users detected" -Details "rjohnson1, bjohnson, rbjohnson (similar names)" -MigrationImpact "Need to verify if these are same person or different"
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 8: SECURITY MIGRATION ISSUES
# ============================================
Write-Log "`n=== Creating Security Migration Issues ===" -Level "WARNING"

# 8.1 Flag users without MFA (check existing)
Write-Log "Checking for MFA gaps..." -Level "INFO"
Add-Issue -Category "Security" -Severity "Critical" -Description "MFA registration status unknown for migrating users" -Details "Run: Get-MgUserAuthenticationMethod for all users" -MigrationImpact "Users may need to re-register MFA in target tenant"

# 8.2 Create break-glass account indicator
if (-not $WhatIf) {
    try {
        $upn = "break-glass-admin@$TenantDomain"
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser -DisplayName "Break Glass Admin" `
                -MailNickname "break-glass-admin" `
                -UserPrincipalName $upn `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "BreakGl@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Emergency Access Account" `
                -Department "IT Security" `
                -UsageLocation "US"
            Add-Issue -Category "Security" -Severity "High" -Description "Break-glass account needs migration planning" -Details $upn -MigrationImpact "Emergency access procedures must be updated for target tenant"
        }
    } catch { Write-Log "Failed: $_" -Level "ERROR" }
}

# ============================================
# SUMMARY
# ============================================
Write-Log "`n========================================" -Level "INFO"
Write-Log "Migration Issue Introduction Complete!" -Level "SUCCESS"
Write-Log "========================================" -Level "INFO"

$issuesByCategory = $issuesCreated | Group-Object Category
Write-Log "`nMigration Issues by Category:" -Level "INFO"
foreach ($category in $issuesByCategory) {
    Write-Log "  $($category.Name): $($category.Count) issues" -Level "WARNING"
}

Write-Log "`nIssues by Severity:" -Level "INFO"
$issuesBySeverity = $issuesCreated | Group-Object Severity
foreach ($severity in $issuesBySeverity) {
    $color = switch ($severity.Name) {
        "Critical" { "Red" }
        "High" { "Yellow" }
        "Medium" { "Cyan" }
        "Low" { "White" }
        default { "White" }
    }
    Write-Host "  $($severity.Name): $($severity.Count) issues" -ForegroundColor $color
}

# Save to JSON
$outputPath = "$PSScriptRoot/migration-issues.json"
$issuesCreated | ConvertTo-Json -Depth 5 | Out-File $outputPath
Write-Log "`nMigration issue manifest saved to: $outputPath" -Level "SUCCESS"

Write-Log "`nTotal migration issues introduced: $($issuesCreated.Count)" -Level "WARNING"
Write-Log "Run pre-migration assessment tools to detect these!" -Level "INFO"
