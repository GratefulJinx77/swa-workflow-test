#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Removes the intentionally introduced problems.
.DESCRIPTION
    Cleans up misconfigurations created by introduce-problems.ps1
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com",
    [switch]$Force
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Connect if needed
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Application.ReadWrite.All","RoleManagement.ReadWrite.Directory" -UseDeviceCode
}

Write-Log "========================================" -Level "INFO"
Write-Log "Cleaning Up Introduced Problems" -Level "INFO"
Write-Log "========================================" -Level "INFO"

if (-not $Force) {
    $confirm = Read-Host "This will remove all intentionally introduced problems. Type 'CLEANUP' to confirm"
    if ($confirm -ne "CLEANUP") {
        Write-Log "Cleanup cancelled" -Level "INFO"
        exit
    }
}

# Users to remove (stale accounts, suspicious accounts, service accounts, guests)
$usersToRemove = @(
    "testaccount2019", "tempcontractor", "oldsvcaccount", "departeduser",
    "fakeadmin", "fakeitsupport", "svc-backup",
    "vendor-guest", "partner-guest", "consultant-guest"
)

Write-Log "`nRemoving problem user accounts..." -Level "INFO"
foreach ($nickname in $usersToRemove) {
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$nickname@$TenantDomain'" -ErrorAction SilentlyContinue
        if ($user) {
            Remove-MgUser -UserId $user.Id
            Write-Log "Removed user: $nickname" -Level "SUCCESS"
        }
    } catch { Write-Log "Failed to remove $nickname : $_" -Level "ERROR" }
}

# Groups to remove
$groupsToRemove = @(
    "Abandoned Project Team", "Legacy System Users", "2019 Interns",
    "Orphaned Security Group", "Ownerless Distribution", "External Collaboration Space",
    "PII Data Handlers", "EU Customer Data Team"
)

Write-Log "`nRemoving problem groups..." -Level "INFO"
foreach ($groupName in $groupsToRemove) {
    try {
        $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if ($group) {
            Remove-MgGroup -GroupId $group.Id
            Write-Log "Removed group: $groupName" -Level "SUCCESS"
        }
    } catch { Write-Log "Failed to remove group $groupName : $_" -Level "ERROR" }
}

# Apps to remove
$appsToRemove = @(
    "Legacy Integration App", "Orphaned Automation App", "CRM Integration"
)

Write-Log "`nRemoving problem app registrations..." -Level "INFO"
foreach ($appName in $appsToRemove) {
    try {
        $app = Get-MgApplication -Filter "displayName eq '$appName'" -ErrorAction SilentlyContinue
        if ($app) {
            Remove-MgApplication -ApplicationId $app.Id
            Write-Log "Removed app: $appName" -Level "SUCCESS"
        }
    } catch { Write-Log "Failed to remove app $appName : $_" -Level "ERROR" }
}

# Remove role assignments from over-privileged users
Write-Log "`nRemoving excessive role assignments..." -Level "INFO"
$roles = Get-MgDirectoryRole -All

# Find and remove role from sales user
$salesUsers = Get-MgUser -Filter "department eq 'Sales'" -All
$userAdminRole = $roles | Where-Object { $_.DisplayName -eq "User Administrator" }
if ($userAdminRole) {
    foreach ($user in $salesUsers) {
        try {
            $member = Get-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id | Where-Object { $_.Id -eq $user.Id }
            if ($member) {
                Remove-MgDirectoryRoleMember -DirectoryRoleId $userAdminRole.Id -DirectoryObjectId $user.Id
                Write-Log "Removed User Admin role from: $($user.DisplayName)" -Level "SUCCESS"
            }
        } catch { }
    }
}

# Remove extra roles from Tony Stark
$tonyStark = Get-MgUser -Filter "displayName eq 'Tony Stark'" -ErrorAction SilentlyContinue
if ($tonyStark) {
    $rolesToRemove = @("Helpdesk Administrator", "Groups Administrator", "License Administrator")
    foreach ($roleName in $rolesToRemove) {
        $role = $roles | Where-Object { $_.DisplayName -eq $roleName }
        if ($role) {
            try {
                $member = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $tonyStark.Id }
                if ($member) {
                    Remove-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $tonyStark.Id
                    Write-Log "Removed $roleName from Tony Stark" -Level "SUCCESS"
                }
            } catch { }
        }
    }
}

# Restore missing attributes (this would need the original data)
Write-Log "`nNote: To restore missing manager/department/office attributes, re-run setup-m365-lab.ps1" -Level "WARNING"

Write-Log "`n========================================" -Level "INFO"
Write-Log "Cleanup Complete!" -Level "SUCCESS"
Write-Log "========================================" -Level "INFO"

# Remove the issues manifest
$manifestPath = "$PSScriptRoot/introduced-problems.json"
if (Test-Path $manifestPath) {
    Remove-Item $manifestPath
    Write-Log "Removed issues manifest file" -Level "SUCCESS"
}
