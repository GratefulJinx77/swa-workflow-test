#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Introduces intentional misconfigurations for assessment testing.
.DESCRIPTION
    Creates security, compliance, and identity issues that assessment tools will detect.
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
    param([string]$Category, [string]$Severity, [string]$Description, [string]$Details)
    $script:issuesCreated += @{
        Category = $Category
        Severity = $Severity
        Description = $Description
        Details = $Details
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    Write-Log "[PROBLEM CREATED] $Description" -Level "PROBLEM"
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
        "Policy.ReadWrite.ConditionalAccess",
        "RoleManagement.ReadWrite.Directory",
        "Organization.ReadWrite.All"
    ) -UseDeviceCode
}

Write-Log "========================================" -Level "INFO"
Write-Log "Introducing Assessment Problems" -Level "INFO"
Write-Log "Tenant: $TenantDomain" -Level "INFO"
Write-Log "========================================" -Level "INFO"

# Get all users for reference
$allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department, JobTitle, OfficeLocation, Manager
$userCount = $allUsers.Count
Write-Log "Found $userCount users to work with" -Level "INFO"

# ============================================
# CATEGORY 1: IDENTITY ISSUES
# ============================================
Write-Log "`n=== Creating Identity Issues ===" -Level "WARNING"

# 1.1 Remove manager from some users (broken org chart)
Write-Log "Creating broken manager relationships..." -Level "INFO"
$usersToBreak = $allUsers | Where-Object { $_.Department -eq "Engineering" } | Select-Object -First 5
foreach ($user in $usersToBreak) {
    if (-not $WhatIf) {
        try {
            Remove-MgUserManagerByRef -UserId $user.Id -ErrorAction SilentlyContinue
            Add-Issue -Category "Identity" -Severity "Medium" -Description "User missing manager: $($user.DisplayName)" -Details $user.UserPrincipalName
        } catch { }
    }
}

# 1.2 Clear department for some users
Write-Log "Creating users with missing department..." -Level "INFO"
$usersNoDept = $allUsers | Where-Object { $_.Department -eq "Support" } | Select-Object -First 3
foreach ($user in $usersNoDept) {
    if (-not $WhatIf) {
        try {
            Update-MgUser -UserId $user.Id -Department $null
            Add-Issue -Category "Identity" -Severity "Low" -Description "User missing department: $($user.DisplayName)" -Details $user.UserPrincipalName
        } catch { }
    }
}

# 1.3 Clear office location for some users
Write-Log "Creating users with missing office location..." -Level "INFO"
$usersNoOffice = $allUsers | Where-Object { $_.Department -eq "Marketing" } | Select-Object -First 3
foreach ($user in $usersNoOffice) {
    if (-not $WhatIf) {
        try {
            Update-MgUser -UserId $user.Id -OfficeLocation $null
            Add-Issue -Category "Identity" -Severity "Low" -Description "User missing office location: $($user.DisplayName)" -Details $user.UserPrincipalName
        } catch { }
    }
}

# 1.4 Create stale/inactive test accounts
Write-Log "Creating stale test accounts..." -Level "INFO"
$staleAccounts = @(
    @{ DisplayName = "Test Account 2019"; MailNickname = "testaccount2019"; JobTitle = "Test User" },
    @{ DisplayName = "Temp Contractor"; MailNickname = "tempcontractor"; JobTitle = "Contractor" },
    @{ DisplayName = "Old Service Account"; MailNickname = "oldsvcaccount"; JobTitle = "Service Account" },
    @{ DisplayName = "Departed Employee"; MailNickname = "departeduser"; JobTitle = "Former Employee" }
)

foreach ($account in $staleAccounts) {
    if (-not $WhatIf) {
        try {
            $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($account.MailNickname)@$TenantDomain'" -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                $newUser = New-MgUser -DisplayName $account.DisplayName `
                    -MailNickname $account.MailNickname `
                    -UserPrincipalName "$($account.MailNickname)@$TenantDomain" `
                    -AccountEnabled:$false `
                    -PasswordProfile @{ Password = "OldP@ss2019!"; ForceChangePasswordNextSignIn = $false } `
                    -JobTitle $account.JobTitle `
                    -UsageLocation "US"
                Add-Issue -Category "Identity" -Severity "Medium" -Description "Stale/disabled account: $($account.DisplayName)" -Details "$($account.MailNickname)@$TenantDomain"
            }
        } catch { Write-Log "Failed to create stale account: $_" -Level "ERROR" }
    }
}

# 1.5 Create account with weak display name (potential security issue)
Write-Log "Creating accounts with suspicious names..." -Level "INFO"
$suspiciousAccounts = @(
    @{ DisplayName = "Admin"; MailNickname = "fakeadmin"; JobTitle = "User" },
    @{ DisplayName = "IT Support"; MailNickname = "fakeitsupport"; JobTitle = "User" }
)

foreach ($account in $suspiciousAccounts) {
    if (-not $WhatIf) {
        try {
            $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($account.MailNickname)@$TenantDomain'" -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                $newUser = New-MgUser -DisplayName $account.DisplayName `
                    -MailNickname $account.MailNickname `
                    -UserPrincipalName "$($account.MailNickname)@$TenantDomain" `
                    -AccountEnabled:$true `
                    -PasswordProfile @{ Password = "DemoP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                    -JobTitle $account.JobTitle `
                    -UsageLocation "US"
                Add-Issue -Category "Security" -Severity "High" -Description "Account with misleading admin-like name: $($account.DisplayName)" -Details "$($account.MailNickname)@$TenantDomain"
            }
        } catch { Write-Log "Failed to create suspicious account: $_" -Level "ERROR" }
    }
}

# ============================================
# CATEGORY 2: GROUP ISSUES
# ============================================
Write-Log "`n=== Creating Group Issues ===" -Level "WARNING"

# 2.1 Create empty groups
Write-Log "Creating empty groups..." -Level "INFO"
$emptyGroups = @(
    @{ Name = "Abandoned Project Team"; Desc = "Old project team - never cleaned up"; Nickname = "abandoned-project" },
    @{ Name = "Legacy System Users"; Desc = "Users of decommissioned system"; Nickname = "legacy-system" },
    @{ Name = "2019 Interns"; Desc = "Intern cohort from 2019"; Nickname = "2019-interns" }
)

foreach ($group in $emptyGroups) {
    if (-not $WhatIf) {
        try {
            $existingGroup = Get-MgGroup -Filter "displayName eq '$($group.Name)'" -ErrorAction SilentlyContinue
            if (-not $existingGroup) {
                New-MgGroup -DisplayName $group.Name -Description $group.Desc -MailEnabled:$false -MailNickname $group.Nickname -SecurityEnabled:$true
                Add-Issue -Category "Groups" -Severity "Low" -Description "Empty group: $($group.Name)" -Details $group.Nickname
            }
        } catch { Write-Log "Failed to create empty group: $_" -Level "ERROR" }
    }
}

# 2.2 Create groups without owners
Write-Log "Creating groups without owners..." -Level "INFO"
$noOwnerGroups = @(
    @{ Name = "Orphaned Security Group"; Desc = "Security group with no owner"; Nickname = "orphaned-security" },
    @{ Name = "Ownerless Distribution"; Desc = "No one manages this group"; Nickname = "ownerless-dist" }
)

foreach ($group in $noOwnerGroups) {
    if (-not $WhatIf) {
        try {
            $existingGroup = Get-MgGroup -Filter "displayName eq '$($group.Name)'" -ErrorAction SilentlyContinue
            if (-not $existingGroup) {
                $newGroup = New-MgGroup -DisplayName $group.Name -Description $group.Desc -MailEnabled:$false -MailNickname $group.Nickname -SecurityEnabled:$true
                # Add a member but no owner
                $randomUser = $allUsers | Get-Random
                New-MgGroupMember -GroupId $newGroup.Id -DirectoryObjectId $randomUser.Id
                Add-Issue -Category "Groups" -Severity "Medium" -Description "Group without owner: $($group.Name)" -Details $group.Nickname
            }
        } catch { Write-Log "Failed to create ownerless group: $_" -Level "ERROR" }
    }
}

# 2.3 Create M365 group with external sharing enabled (simulated via description)
Write-Log "Creating groups with external sharing notes..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'External Collaboration Space'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            $extGroup = New-MgGroup -DisplayName "External Collaboration Space" `
                -Description "WARNING: External sharing enabled - contains sensitive project data" `
                -MailEnabled:$true `
                -MailNickname "external-collab" `
                -SecurityEnabled:$true `
                -GroupTypes @("Unified")
            Add-Issue -Category "Compliance" -Severity "High" -Description "M365 group potentially sharing externally: External Collaboration Space" -Details "external-collab"
        }
    } catch { Write-Log "Failed to create external group: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 3: PRIVILEGED ACCESS ISSUES
# ============================================
Write-Log "`n=== Creating Privileged Access Issues ===" -Level "WARNING"

# Get directory roles
$roles = Get-MgDirectoryRole -All

# 3.1 Assign Global Admin to a regular user (excessive privileges)
Write-Log "Creating over-privileged user accounts..." -Level "INFO"
$globalAdminRole = $roles | Where-Object { $_.DisplayName -eq "Global Administrator" }
$userAdminRole = $roles | Where-Object { $_.DisplayName -eq "User Administrator" }
$exchangeAdminRole = $roles | Where-Object { $_.DisplayName -eq "Exchange Administrator" }

# Find a non-exec user to over-privilege
$regularUser = $allUsers | Where-Object { $_.Department -eq "Sales" -and $_.JobTitle -notmatch "VP|Director|Manager" } | Select-Object -First 1

if ($regularUser -and $userAdminRole) {
    if (-not $WhatIf) {
        try {
            # Activate the role if needed
            $roleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "User Administrator" }
            if ($roleTemplate -and -not $userAdminRole) {
                $userAdminRole = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id
            }

            if ($userAdminRole) {
                $existingMember = Get-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id | Where-Object { $_.Id -eq $regularUser.Id }
                if (-not $existingMember) {
                    New-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id -DirectoryObjectId $regularUser.Id
                    Add-Issue -Category "Security" -Severity "Critical" -Description "Non-IT user with User Administrator role: $($regularUser.DisplayName)" -Details $regularUser.UserPrincipalName
                }
            }
        } catch { Write-Log "Failed to assign admin role: $_" -Level "ERROR" }
    }
}

# 3.2 Create a service account with admin privileges
Write-Log "Creating over-privileged service account..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $svcAccount = Get-MgUser -Filter "userPrincipalName eq 'svc-backup@$TenantDomain'" -ErrorAction SilentlyContinue
        if (-not $svcAccount) {
            $svcAccount = New-MgUser -DisplayName "Backup Service Account" `
                -MailNickname "svc-backup" `
                -UserPrincipalName "svc-backup@$TenantDomain" `
                -AccountEnabled:$true `
                -PasswordProfile @{ Password = "Backup2024!Svc"; ForceChangePasswordNextSignIn = $false } `
                -JobTitle "Service Account" `
                -Department "IT" `
                -UsageLocation "US"
            Add-Issue -Category "Security" -Severity "High" -Description "Service account created: Backup Service Account" -Details "svc-backup@$TenantDomain"
        }

        # Try to assign Exchange Admin role to service account
        if ($exchangeAdminRole -and $svcAccount) {
            $existingMember = Get-MgDirectoryRoleMember -DirectoryRoleId $exchangeAdminRole.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $svcAccount.Id }
            if (-not $existingMember) {
                New-MgDirectoryRoleMember -DirectoryRoleId $exchangeAdminRole.Id -DirectoryObjectId $svcAccount.Id -ErrorAction SilentlyContinue
                Add-Issue -Category "Security" -Severity "Critical" -Description "Service account with Exchange Admin role" -Details "svc-backup@$TenantDomain"
            }
        }
    } catch { Write-Log "Failed to create service account: $_" -Level "ERROR" }
}

# 3.3 Assign multiple admin roles to one user (role accumulation)
Write-Log "Creating user with multiple admin roles..." -Level "INFO"
$multiRoleUser = $allUsers | Where-Object { $_.DisplayName -eq "Tony Stark" } | Select-Object -First 1

if ($multiRoleUser) {
    $rolesToAssign = @("Helpdesk Administrator", "Groups Administrator", "License Administrator")
    foreach ($roleName in $rolesToAssign) {
        if (-not $WhatIf) {
            try {
                $role = $roles | Where-Object { $_.DisplayName -eq $roleName }
                if (-not $role) {
                    $roleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $roleName }
                    if ($roleTemplate) {
                        $role = New-MgDirectoryRole -RoleTemplateId $roleTemplate.Id -ErrorAction SilentlyContinue
                    }
                }
                if ($role) {
                    $existingMember = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $multiRoleUser.Id }
                    if (-not $existingMember) {
                        New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $multiRoleUser.Id -ErrorAction SilentlyContinue
                    }
                }
            } catch { }
        }
    }
    Add-Issue -Category "Security" -Severity "High" -Description "User with multiple admin roles: $($multiRoleUser.DisplayName)" -Details "Helpdesk Admin, Groups Admin, License Admin"
}

# ============================================
# CATEGORY 4: APPLICATION ISSUES
# ============================================
Write-Log "`n=== Creating Application Issues ===" -Level "WARNING"

# 4.1 Create app registration with excessive permissions
Write-Log "Creating app with excessive API permissions..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'Legacy Integration App'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            $appParams = @{
                DisplayName = "Legacy Integration App"
                Description = "Old integration - owner unknown"
                SignInAudience = "AzureADMyOrg"
                RequiredResourceAccess = @(
                    @{
                        ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
                        ResourceAccess = @(
                            @{ Id = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"; Type = "Role" }  # Application.ReadWrite.All
                            @{ Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"; Type = "Role" }  # Directory.ReadWrite.All
                            @{ Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"; Type = "Role" }  # RoleManagement.ReadWrite.Directory
                            @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }  # User.Read.All
                        )
                    }
                )
            }
            New-MgApplication -BodyParameter $appParams
            Add-Issue -Category "Security" -Severity "Critical" -Description "App registration with excessive Graph permissions: Legacy Integration App" -Details "Has Application.ReadWrite.All, Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory"
        }
    } catch { Write-Log "Failed to create app registration: $_" -Level "ERROR" }
}

# 4.2 Create app with no owner
Write-Log "Creating app without owner..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'Orphaned Automation App'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            New-MgApplication -DisplayName "Orphaned Automation App" -Description "Creator left the company" -SignInAudience "AzureADMyOrg"
            Add-Issue -Category "Security" -Severity "Medium" -Description "App registration without owner: Orphaned Automation App" -Details "No owner assigned"
        }
    } catch { Write-Log "Failed to create orphaned app: $_" -Level "ERROR" }
}

# 4.3 Create app with credentials expiring soon (simulated via description)
Write-Log "Creating app with expiring credentials note..." -Level "INFO"
if (-not $WhatIf) {
    try {
        $existingApp = Get-MgApplication -Filter "displayName eq 'CRM Integration'" -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            $app = New-MgApplication -DisplayName "CRM Integration" -Description "ALERT: Client secret expires 2024-02-01" -SignInAudience "AzureADMyOrg"
            # Add a secret that expires soon
            $endDate = (Get-Date).AddDays(30)
            Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ EndDateTime = $endDate; DisplayName = "OldSecret" } -ErrorAction SilentlyContinue
            Add-Issue -Category "Operations" -Severity "High" -Description "App with expiring credentials: CRM Integration" -Details "Secret expires in 30 days"
        }
    } catch { Write-Log "Failed to create app with expiring creds: $_" -Level "ERROR" }
}

# ============================================
# CATEGORY 5: GUEST/EXTERNAL USER ISSUES
# ============================================
Write-Log "`n=== Creating Guest User Issues ===" -Level "WARNING"

# 5.1 Create guest users (simulating B2B guests)
Write-Log "Creating guest users with various issues..." -Level "INFO"
$guestUsers = @(
    @{ DisplayName = "External Vendor"; Mail = "vendor@external-company.com" },
    @{ DisplayName = "Partner Contact"; Mail = "partner@old-partner.com" },
    @{ DisplayName = "Consultant Access"; Mail = "consultant@temp-firm.com" }
)

foreach ($guest in $guestUsers) {
    if (-not $WhatIf) {
        try {
            # Check if guest already exists
            $existingGuest = Get-MgUser -Filter "mail eq '$($guest.Mail)'" -ErrorAction SilentlyContinue
            if (-not $existingGuest) {
                # Create as a regular user simulating a guest (actual guest invite requires the email to exist)
                $guestNickname = $guest.Mail -replace "@.*", "" -replace "\.", ""
                $existingUser = Get-MgUser -Filter "userPrincipalName eq '$guestNickname-guest@$TenantDomain'" -ErrorAction SilentlyContinue
                if (-not $existingUser) {
                    New-MgUser -DisplayName "$($guest.DisplayName) (Guest)" `
                        -MailNickname "$guestNickname-guest" `
                        -UserPrincipalName "$guestNickname-guest@$TenantDomain" `
                        -AccountEnabled:$true `
                        -PasswordProfile @{ Password = "GuestP@ss2024!"; ForceChangePasswordNextSignIn = $false } `
                        -JobTitle "External User" `
                        -Department "External" `
                        -UsageLocation "US"
                    Add-Issue -Category "Identity" -Severity "Medium" -Description "External/guest user account: $($guest.DisplayName)" -Details "$guestNickname-guest@$TenantDomain"
                }
            }
        } catch { Write-Log "Failed to create guest user: $_" -Level "ERROR" }
    }
}

# ============================================
# CATEGORY 6: CONFIGURATION ISSUES
# ============================================
Write-Log "`n=== Creating Configuration Issues ===" -Level "WARNING"

# 6.1 Document that legacy auth should be checked
Add-Issue -Category "Security" -Severity "High" -Description "Legacy authentication protocols may be enabled" -Details "Check Authentication Methods policies"

# 6.2 Document MFA gaps
Add-Issue -Category "Security" -Severity "Critical" -Description "No Conditional Access policies enforcing MFA" -Details "Users can authenticate without MFA"

# 6.3 Document missing security defaults
Add-Issue -Category "Security" -Severity "High" -Description "Security defaults may not be enabled" -Details "Check Azure AD > Properties > Security defaults"

# ============================================
# CATEGORY 7: DATA/COMPLIANCE ISSUES
# ============================================
Write-Log "`n=== Creating Compliance Issue Markers ===" -Level "WARNING"

# 7.1 Create group that suggests sensitive data handling issues
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'PII Data Handlers'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            $piiGroup = New-MgGroup -DisplayName "PII Data Handlers" `
                -Description "Users with access to personally identifiable information - NO DLP POLICY APPLIED" `
                -MailEnabled:$false `
                -MailNickname "pii-handlers" `
                -SecurityEnabled:$true
            # Add some random users
            $randomUsers = $allUsers | Get-Random -Count 5
            foreach ($user in $randomUsers) {
                New-MgGroupMember -GroupId $piiGroup.Id -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
            }
            Add-Issue -Category "Compliance" -Severity "Critical" -Description "Group handling PII without DLP policy: PII Data Handlers" -Details "5 users with PII access, no data loss prevention"
        }
    } catch { Write-Log "Failed to create PII group: $_" -Level "ERROR" }
}

# 7.2 Create group suggesting GDPR issues
if (-not $WhatIf) {
    try {
        $existingGroup = Get-MgGroup -Filter "displayName eq 'EU Customer Data Team'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            $euGroup = New-MgGroup -DisplayName "EU Customer Data Team" `
                -Description "Handles EU customer data - GDPR compliance not verified - No retention policy" `
                -MailEnabled:$false `
                -MailNickname "eu-data-team" `
                -SecurityEnabled:$true
            Add-Issue -Category "Compliance" -Severity "Critical" -Description "EU data handling group without verified GDPR compliance" -Details "eu-data-team - No retention policy configured"
        }
    } catch { Write-Log "Failed to create EU data group: $_" -Level "ERROR" }
}

# ============================================
# SUMMARY
# ============================================
Write-Log "`n========================================" -Level "INFO"
Write-Log "Problem Introduction Complete!" -Level "SUCCESS"
Write-Log "========================================" -Level "INFO"

# Group issues by category
$issuesByCategory = $issuesCreated | Group-Object Category

Write-Log "`nIssues Created by Category:" -Level "INFO"
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

# Save issues to JSON for reference
$outputPath = "$PSScriptRoot/introduced-problems.json"
$issuesCreated | ConvertTo-Json -Depth 5 | Out-File $outputPath
Write-Log "`nIssue manifest saved to: $outputPath" -Level "SUCCESS"

Write-Log "`nTotal issues introduced: $($issuesCreated.Count)" -Level "WARNING"
Write-Log "Run assessment tools to detect these issues!" -Level "INFO"
