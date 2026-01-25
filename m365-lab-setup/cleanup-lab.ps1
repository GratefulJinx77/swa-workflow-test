#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Cleans up the M365 test lab - removes created users and groups.
.DESCRIPTION
    WARNING: This will delete users and groups! Use with caution.
.PARAMETER RemoveUsers
    If specified, removes all users created by the setup script.
.PARAMETER RemoveGroups
    If specified, removes all groups created by the setup script.
.PARAMETER Force
    Skip confirmation prompts.
#>

param(
    [switch]$RemoveUsers,
    [switch]$RemoveGroups,
    [switch]$Force,
    [string]$TenantDomain = "8k8232.onmicrosoft.com"
)

$ErrorActionPreference = "Stop"

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

# Groups created by the setup script
$labGroups = @(
    "Engineering Team", "Product Team", "Design Team", "Sales Team",
    "Marketing Team", "Support Team", "HR Team", "Finance Team",
    "NYC Office", "London Office", "Phoenix Office",
    "Executive Team", "All Managers", "All Directors",
    "Platform Team", "Mobile Team", "API Team", "Enterprise Sales", "SMB Sales"
)

# User mail nicknames created by the setup script (from users-data.json)
$labUserNicknames = @(
    # Executives
    "jpicard", "tstark", "smcduck", "mpriestly", "ddraper",
    # Engineering
    "fsmoak", "swakanda", "qbranch", "nmatrix", "tcode", "mdebug", "oquery", "toperator", "csmith",
    "asmith", "larchitect", "ncaptain", "stoggle", "aruntime", "mclick", "sguardian", "mdata",
    "pcache", "klock", "troute", "rkandra", "sprogram", "lcommander", "gprotocol", "vbinary", "dprocess", "kpanic",
    "bflipper", "soverflow", "npointer",
    # Product
    "srogers", "ppotts", "hhogan", "jrhodes", "pparker", "nleeds", "mjwatson", "bbrant", "fthompson", "mparker",
    # Design
    "emode", "bross", "awarhol", "fkahlo", "gokeeffe", "jpollock", "sdali", "ppicasso", "vvangogh", "cmonet",
    # Sales
    "jbelfort", "sgoodman", "dcorleone", "ggekko", "fbueller", "ewoods", "hspecter", "agold",
    "jmaguire", "sbell", "tshelby", "mscott", "dschrute", "jhalpert", "pbeesly",
    # Marketing
    "polson", "jholloway", "rsterling", "srizzo", "mginsberg", "sromano", "kcosgrove", "hcrane", "pkinsey", "mcalvet",
    # Support
    "lknope", "rswanson", "bwyatt", "ctraeger", "aludgate", "adwyer", "thaverford", "dmeagle", "jgergich", "aperkins",
    # HR
    "tflenderson", "hflax", "jlevinson", "rhoward", "kkapoor",
    # Finance
    "amartin", "omartinez", "kmalone", "shudson", "pvance"
)

# Connect to Graph if not connected
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All" -UseDeviceCode
}

Write-Log "========================================" -Level "WARNING"
Write-Log "M365 Test Lab CLEANUP" -Level "WARNING"
Write-Log "========================================" -Level "WARNING"

if (-not $RemoveUsers -and -not $RemoveGroups) {
    Write-Log "No cleanup actions specified. Use -RemoveUsers and/or -RemoveGroups" -Level "INFO"
    Write-Log "Example: ./cleanup-lab.ps1 -RemoveUsers -RemoveGroups" -Level "INFO"
    exit
}

# Confirmation
if (-not $Force) {
    Write-Host "`nWARNING: This will permanently delete:" -ForegroundColor Red
    if ($RemoveUsers) { Write-Host "  - $($labUserNicknames.Count) users" -ForegroundColor Red }
    if ($RemoveGroups) { Write-Host "  - $($labGroups.Count) groups" -ForegroundColor Red }

    $confirm = Read-Host "`nType 'DELETE' to confirm"
    if ($confirm -ne "DELETE") {
        Write-Log "Cleanup cancelled" -Level "INFO"
        exit
    }
}

# Remove Groups
if ($RemoveGroups) {
    Write-Log "`nRemoving groups..." -Level "INFO"

    foreach ($groupName in $labGroups) {
        try {
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
            if ($group) {
                Remove-MgGroup -GroupId $group.Id
                Write-Log "Deleted group: $groupName" -Level "SUCCESS"
            } else {
                Write-Log "Group not found: $groupName" -Level "INFO"
            }
        } catch {
            Write-Log "Failed to delete group $groupName : $_" -Level "ERROR"
        }
        Start-Sleep -Milliseconds 200
    }
}

# Remove Users
if ($RemoveUsers) {
    Write-Log "`nRemoving users..." -Level "INFO"

    foreach ($nickname in $labUserNicknames) {
        $upn = "$nickname@$TenantDomain"
        try {
            $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
            if ($user) {
                Remove-MgUser -UserId $user.Id
                Write-Log "Deleted user: $upn" -Level "SUCCESS"
            } else {
                Write-Log "User not found: $upn" -Level "INFO"
            }
        } catch {
            Write-Log "Failed to delete user $upn : $_" -Level "ERROR"
        }
        Start-Sleep -Milliseconds 200
    }
}

Write-Log "`n========================================" -Level "INFO"
Write-Log "Cleanup Complete!" -Level "SUCCESS"
Write-Log "========================================" -Level "INFO"

# Verification
$remainingUsers = (Get-MgUser -All).Count
$remainingGroups = (Get-MgGroup -All).Count
Write-Log "Remaining users: $remainingUsers" -Level "INFO"
Write-Log "Remaining groups: $remainingGroups" -Level "INFO"
