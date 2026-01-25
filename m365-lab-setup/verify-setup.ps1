#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Verifies the M365 test lab setup.
.DESCRIPTION
    Checks user counts, group memberships, manager hierarchy, and license assignments.
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com"
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

# Connect to Graph if not connected
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Directory.Read.All" -UseDeviceCode
}

Write-Log "========================================" -Level "INFO"
Write-Log "M365 Test Lab Verification" -Level "INFO"
Write-Log "Tenant: $TenantDomain" -Level "INFO"
Write-Log "========================================" -Level "INFO"

# 1. User Count
Write-Log "`nUser Statistics:" -Level "INFO"
Write-Log "----------------" -Level "INFO"

$allUsers = Get-MgUser -All -Property Id, DisplayName, Department, JobTitle, OfficeLocation, AssignedLicenses
$userCount = $allUsers.Count
Write-Log "Total users: $userCount" -Level $(if ($userCount -ge 100) { "SUCCESS" } else { "WARNING" })

# Department breakdown
$deptCounts = $allUsers | Group-Object Department | Sort-Object Count -Descending
Write-Log "`nUsers by Department:" -Level "INFO"
foreach ($dept in $deptCounts) {
    Write-Log "  $($dept.Name): $($dept.Count)" -Level "INFO"
}

# Location breakdown
$locationCounts = $allUsers | Group-Object OfficeLocation | Sort-Object Count -Descending
Write-Log "`nUsers by Location:" -Level "INFO"
foreach ($loc in $locationCounts) {
    Write-Log "  $($loc.Name): $($loc.Count)" -Level "INFO"
}

# 2. License Count
$licensedUsers = $allUsers | Where-Object { $_.AssignedLicenses.Count -gt 0 }
Write-Log "`nLicensed users: $($licensedUsers.Count)" -Level $(if ($licensedUsers.Count -ge 25) { "SUCCESS" } else { "WARNING" })

# 3. Manager Hierarchy
Write-Log "`nManager Hierarchy Check:" -Level "INFO"
Write-Log "------------------------" -Level "INFO"

$usersWithManagers = 0
$usersWithoutManagers = 0
$ceoFound = $false

foreach ($user in $allUsers) {
    try {
        $manager = Get-MgUserManager -UserId $user.Id -ErrorAction SilentlyContinue
        if ($manager) {
            $usersWithManagers++
        } else {
            $usersWithoutManagers++
            if ($user.JobTitle -eq "Chief Executive Officer") {
                $ceoFound = $true
            }
        }
    } catch {
        $usersWithoutManagers++
        if ($user.JobTitle -eq "Chief Executive Officer") {
            $ceoFound = $true
        }
    }
}

Write-Log "Users with managers: $usersWithManagers" -Level "INFO"
Write-Log "Users without managers (including CEO): $usersWithoutManagers" -Level "INFO"
Write-Log "CEO found at top of hierarchy: $ceoFound" -Level $(if ($ceoFound) { "SUCCESS" } else { "WARNING" })

# 4. Groups
Write-Log "`nGroup Statistics:" -Level "INFO"
Write-Log "-----------------" -Level "INFO"

$allGroups = Get-MgGroup -All -Property Id, DisplayName, GroupTypes, MembershipRule
$groupCount = $allGroups.Count
Write-Log "Total groups: $groupCount" -Level "INFO"

$m365Groups = $allGroups | Where-Object { $_.GroupTypes -contains "Unified" }
$securityGroups = $allGroups | Where-Object { $_.GroupTypes -notcontains "Unified" }

Write-Log "M365 Groups: $($m365Groups.Count)" -Level "INFO"
Write-Log "Security Groups: $($securityGroups.Count)" -Level "INFO"

# Expected groups
$expectedGroups = @(
    "Engineering Team", "Product Team", "Design Team", "Sales Team",
    "Marketing Team", "Support Team", "HR Team", "Finance Team",
    "NYC Office", "London Office", "Phoenix Office",
    "Executive Team", "All Managers", "All Directors",
    "Platform Team", "Mobile Team", "API Team", "Enterprise Sales", "SMB Sales"
)

Write-Log "`nChecking expected groups:" -Level "INFO"
foreach ($groupName in $expectedGroups) {
    $found = $allGroups | Where-Object { $_.DisplayName -eq $groupName }
    if ($found) {
        $memberCount = (Get-MgGroupMember -GroupId $found.Id -All).Count
        Write-Log "  [OK] $groupName ($memberCount members)" -Level "SUCCESS"
    } else {
        Write-Log "  [MISSING] $groupName" -Level "ERROR"
    }
}

# 5. Sample Org Chart
Write-Log "`nSample Org Chart (Executives):" -Level "INFO"
Write-Log "------------------------------" -Level "INFO"

$executives = $allUsers | Where-Object { $_.Department -eq "Executive" }
foreach ($exec in $executives) {
    $reports = Get-MgUserDirectReport -UserId $exec.Id -All -ErrorAction SilentlyContinue
    Write-Log "  $($exec.DisplayName) - $($exec.JobTitle)" -Level "INFO"
    if ($reports) {
        foreach ($report in $reports | Select-Object -First 3) {
            $reportUser = Get-MgUser -UserId $report.Id -Property DisplayName, JobTitle
            Write-Log "    -> $($reportUser.DisplayName) ($($reportUser.JobTitle))" -Level "INFO"
        }
        if ($reports.Count -gt 3) {
            Write-Log "    -> ... and $($reports.Count - 3) more" -Level "INFO"
        }
    }
}

# Summary
Write-Log "`n========================================" -Level "INFO"
Write-Log "Verification Summary" -Level "INFO"
Write-Log "========================================" -Level "INFO"

$issues = @()
if ($userCount -lt 100) { $issues += "User count is $userCount (expected 100)" }
if ($licensedUsers.Count -lt 25) { $issues += "Only $($licensedUsers.Count) users are licensed (expected 25)" }
if (-not $ceoFound) { $issues += "CEO not found at top of hierarchy" }

if ($issues.Count -eq 0) {
    Write-Log "All checks passed!" -Level "SUCCESS"
} else {
    Write-Log "Issues found:" -Level "WARNING"
    foreach ($issue in $issues) {
        Write-Log "  - $issue" -Level "WARNING"
    }
}
