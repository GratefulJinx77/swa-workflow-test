#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Sets up the M365 test lab with 100 users, org structure, and groups.
.DESCRIPTION
    This script creates/updates users in the 8k8232.onmicrosoft.com tenant
    with a realistic demo organizational structure.
#>

param(
    [string]$TenantDomain = "8k8232.onmicrosoft.com",
    [string]$DefaultPassword = "DemoP@ss2024!",
    [string]$DataFile = "$PSScriptRoot/users-data.json",
    [switch]$WhatIf
)

# Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Location to country/usage location mapping
$LocationConfig = @{
    "NYC" = @{ Country = "United States"; UsageLocation = "US"; City = "New York"; State = "NY"; PostalCode = "10001"; StreetAddress = "350 Fifth Avenue" }
    "London" = @{ Country = "United Kingdom"; UsageLocation = "GB"; City = "London"; State = "England"; PostalCode = "EC1A 1BB"; StreetAddress = "30 St Mary Axe" }
    "Phoenix" = @{ Country = "United States"; UsageLocation = "US"; City = "Phoenix"; State = "AZ"; PostalCode = "85001"; StreetAddress = "100 W Washington St" }
}

# E5 Developer License SKU ID (Microsoft 365 E5 Developer)
$E5LicenseSkuId = "c42b9cae-ea4f-4ab7-9717-81576235ccac"

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

function Connect-ToGraph {
    Write-Log "Connecting to Microsoft Graph..."

    # Check if already connected
    try {
        $context = Get-MgContext
        if ($context) {
            Write-Log "Already connected to tenant: $($context.TenantId)" -Level "SUCCESS"
            return
        }
    } catch { }

    # Connect with required scopes
    $scopes = @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Organization.Read.All"
    )

    Connect-MgGraph -Scopes $scopes -UseDeviceCode
    Write-Log "Connected to Microsoft Graph" -Level "SUCCESS"
}

function Get-ExistingUsers {
    Write-Log "Fetching existing users..."
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, Department, JobTitle, OfficeLocation
    Write-Log "Found $($users.Count) existing users" -Level "INFO"
    return $users
}

function New-M365User {
    param(
        [Parameter(Mandatory=$true)]$UserData,
        [hashtable]$ExistingUsersMap
    )

    $upn = "$($UserData.mailNickname)@$TenantDomain"

    # Check if user already exists
    if ($ExistingUsersMap.ContainsKey($upn)) {
        Write-Log "User $upn already exists, updating..." -Level "WARNING"
        return Update-M365User -UserData $UserData -UserId $ExistingUsersMap[$upn].Id
    }

    $locationInfo = $LocationConfig[$UserData.location]

    $userParams = @{
        AccountEnabled = $true
        DisplayName = $UserData.displayName
        MailNickname = $UserData.mailNickname
        UserPrincipalName = $upn
        PasswordProfile = @{
            ForceChangePasswordNextSignIn = $false
            Password = $DefaultPassword
        }
        Department = $UserData.department
        JobTitle = $UserData.jobTitle
        OfficeLocation = $UserData.location
        UsageLocation = $locationInfo.UsageLocation
        City = $locationInfo.City
        State = $locationInfo.State
        Country = $locationInfo.Country
        PostalCode = $locationInfo.PostalCode
        StreetAddress = $locationInfo.StreetAddress
    }

    if ($WhatIf) {
        Write-Log "[WhatIf] Would create user: $($UserData.displayName) ($upn)" -Level "INFO"
        return $null
    }

    try {
        $user = New-MgUser -BodyParameter $userParams
        Write-Log "Created user: $($UserData.displayName) ($upn)" -Level "SUCCESS"
        return $user
    } catch {
        Write-Log "Failed to create user $upn : $_" -Level "ERROR"
        return $null
    }
}

function Update-M365User {
    param(
        [Parameter(Mandatory=$true)]$UserData,
        [string]$UserId
    )

    $locationInfo = $LocationConfig[$UserData.location]

    $updateParams = @{
        DisplayName = $UserData.displayName
        Department = $UserData.department
        JobTitle = $UserData.jobTitle
        OfficeLocation = $UserData.location
        UsageLocation = $locationInfo.UsageLocation
        City = $locationInfo.City
        State = $locationInfo.State
        Country = $locationInfo.Country
        PostalCode = $locationInfo.PostalCode
        StreetAddress = $locationInfo.StreetAddress
    }

    if ($WhatIf) {
        Write-Log "[WhatIf] Would update user: $($UserData.displayName)" -Level "INFO"
        return $null
    }

    try {
        Update-MgUser -UserId $UserId -BodyParameter $updateParams
        Write-Log "Updated user: $($UserData.displayName)" -Level "SUCCESS"
        return Get-MgUser -UserId $UserId
    } catch {
        Write-Log "Failed to update user $($UserData.displayName): $_" -Level "ERROR"
        return $null
    }
}

function Set-UserManager {
    param(
        [string]$UserId,
        [string]$ManagerUpn
    )

    if ([string]::IsNullOrEmpty($ManagerUpn)) { return }

    $managerUpn = "$ManagerUpn@$TenantDomain"

    if ($WhatIf) {
        Write-Log "[WhatIf] Would set manager for user to: $managerUpn" -Level "INFO"
        return
    }

    try {
        $manager = Get-MgUser -UserId $managerUpn
        $managerRef = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($manager.Id)"
        }
        Set-MgUserManagerByRef -UserId $UserId -BodyParameter $managerRef
        Write-Log "Set manager to $managerUpn" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to set manager $managerUpn : $_" -Level "WARNING"
    }
}

function Assign-License {
    param(
        [string]$UserId,
        [string]$UserDisplayName
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would assign E5 license to: $UserDisplayName" -Level "INFO"
        return
    }

    try {
        # Check current licenses
        $currentLicenses = Get-MgUserLicenseDetail -UserId $UserId
        if ($currentLicenses.SkuId -contains $E5LicenseSkuId) {
            Write-Log "User $UserDisplayName already has E5 license" -Level "INFO"
            return
        }

        $licenseParams = @{
            AddLicenses = @(
                @{
                    SkuId = $E5LicenseSkuId
                }
            )
            RemoveLicenses = @()
        }

        Set-MgUserLicense -UserId $UserId -BodyParameter $licenseParams
        Write-Log "Assigned E5 license to: $UserDisplayName" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to assign license to $UserDisplayName : $_" -Level "WARNING"
    }
}

function New-M365Group {
    param(
        [string]$DisplayName,
        [string]$Description,
        [string]$MailNickname,
        [string]$GroupType = "Unified"  # Unified = M365 Group, Security = Security Group
    )

    # Check if group exists
    $existingGroup = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existingGroup) {
        Write-Log "Group '$DisplayName' already exists" -Level "INFO"
        return $existingGroup
    }

    if ($WhatIf) {
        Write-Log "[WhatIf] Would create group: $DisplayName" -Level "INFO"
        return $null
    }

    try {
        $groupParams = @{
            DisplayName = $DisplayName
            Description = $Description
            MailEnabled = ($GroupType -eq "Unified")
            MailNickname = $MailNickname
            SecurityEnabled = $true
        }

        if ($GroupType -eq "Unified") {
            $groupParams.GroupTypes = @("Unified")
        }

        $group = New-MgGroup -BodyParameter $groupParams
        Write-Log "Created group: $DisplayName" -Level "SUCCESS"
        Start-Sleep -Milliseconds 500  # Brief pause to avoid throttling
        return $group
    } catch {
        Write-Log "Failed to create group $DisplayName : $_" -Level "ERROR"
        return $null
    }
}

function Add-UserToGroup {
    param(
        [string]$GroupId,
        [string]$UserId,
        [string]$GroupName,
        [string]$UserName
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would add $UserName to group $GroupName" -Level "INFO"
        return
    }

    try {
        # Check if already a member
        $members = Get-MgGroupMember -GroupId $GroupId -All
        if ($members.Id -contains $UserId) {
            Write-Log "$UserName is already a member of $GroupName" -Level "INFO"
            return
        }

        $memberRef = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
        }
        New-MgGroupMember -GroupId $GroupId -BodyParameter $memberRef
        Write-Log "Added $UserName to $GroupName" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to add $UserName to $GroupName : $_" -Level "WARNING"
    }
}

function Process-UserList {
    param(
        [array]$UserList,
        [hashtable]$ExistingUsersMap,
        [hashtable]$CreatedUsersMap
    )

    foreach ($userData in $UserList) {
        $user = New-M365User -UserData $userData -ExistingUsersMap $ExistingUsersMap
        if ($user) {
            $upn = "$($userData.mailNickname)@$TenantDomain"
            $CreatedUsersMap[$userData.mailNickname] = @{
                Id = $user.Id
                DisplayName = $userData.displayName
                Manager = $userData.manager
                License = $userData.license
                Department = $userData.department
                Location = $userData.location
            }
        }
        Start-Sleep -Milliseconds 200  # Avoid throttling
    }
}

# Main execution
function Main {
    Write-Log "========================================" -Level "INFO"
    Write-Log "M365 Test Lab Setup Script" -Level "INFO"
    Write-Log "Tenant: $TenantDomain" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    # Connect to Graph
    Connect-ToGraph

    # Load user data
    Write-Log "Loading user data from $DataFile..."
    $data = Get-Content $DataFile | ConvertFrom-Json

    # Get existing users and create lookup map
    $existingUsers = Get-ExistingUsers
    $existingUsersMap = @{}
    foreach ($user in $existingUsers) {
        $existingUsersMap[$user.UserPrincipalName] = $user
    }

    # Track created/updated users for manager assignment
    $createdUsersMap = @{}

    # Phase 1: Create all users
    Write-Log "========================================" -Level "INFO"
    Write-Log "Phase 1: Creating/Updating Users" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    # Process executives
    Write-Log "Processing Executives..." -Level "INFO"
    Process-UserList -UserList $data.executives -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Engineering
    Write-Log "Processing Engineering..." -Level "INFO"
    Process-UserList -UserList $data.engineering.vps -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.engineering.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.engineering.engineers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Product
    Write-Log "Processing Product..." -Level "INFO"
    Process-UserList -UserList @($data.product.vp) -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.product.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.product.analysts -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Design
    Write-Log "Processing Design..." -Level "INFO"
    Process-UserList -UserList @($data.design.cdo) -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.design.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.design.designers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Sales
    Write-Log "Processing Sales..." -Level "INFO"
    Process-UserList -UserList @($data.sales.vp) -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.sales.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.sales.reps -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Marketing
    Write-Log "Processing Marketing..." -Level "INFO"
    Process-UserList -UserList $data.marketing.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.marketing.staff -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Support
    Write-Log "Processing Support..." -Level "INFO"
    Process-UserList -UserList @($data.support.vp) -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.support.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.support.staff -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process HR
    Write-Log "Processing HR..." -Level "INFO"
    Process-UserList -UserList @($data.hr.vp) -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.hr.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.hr.staff -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Process Finance
    Write-Log "Processing Finance..." -Level "INFO"
    Process-UserList -UserList $data.finance.managers -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap
    Process-UserList -UserList $data.finance.staff -ExistingUsersMap $existingUsersMap -CreatedUsersMap $createdUsersMap

    # Phase 2: Set Manager Hierarchy
    Write-Log "========================================" -Level "INFO"
    Write-Log "Phase 2: Setting Manager Hierarchy" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    foreach ($mailNickname in $createdUsersMap.Keys) {
        $userInfo = $createdUsersMap[$mailNickname]
        if ($userInfo.Manager) {
            Write-Log "Setting manager for $($userInfo.DisplayName)..." -Level "INFO"
            Set-UserManager -UserId $userInfo.Id -ManagerUpn $userInfo.Manager
        }
    }

    # Phase 3: Assign Licenses
    Write-Log "========================================" -Level "INFO"
    Write-Log "Phase 3: Assigning Licenses" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    foreach ($mailNickname in $createdUsersMap.Keys) {
        $userInfo = $createdUsersMap[$mailNickname]
        if ($userInfo.License) {
            Assign-License -UserId $userInfo.Id -UserDisplayName $userInfo.DisplayName
        }
    }

    # Phase 4: Create Groups
    Write-Log "========================================" -Level "INFO"
    Write-Log "Phase 4: Creating Groups" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    $groups = @{}

    # Department Groups (M365 Groups)
    $deptGroups = @(
        @{ Name = "Engineering Team"; Desc = "All Engineering department members"; Nickname = "engineering-team" },
        @{ Name = "Product Team"; Desc = "All Product department members"; Nickname = "product-team" },
        @{ Name = "Design Team"; Desc = "All Design department members"; Nickname = "design-team" },
        @{ Name = "Sales Team"; Desc = "All Sales department members"; Nickname = "sales-team" },
        @{ Name = "Marketing Team"; Desc = "All Marketing department members"; Nickname = "marketing-team" },
        @{ Name = "Support Team"; Desc = "All Support department members"; Nickname = "support-team" },
        @{ Name = "HR Team"; Desc = "All HR department members"; Nickname = "hr-team" },
        @{ Name = "Finance Team"; Desc = "All Finance department members"; Nickname = "finance-team" }
    )

    foreach ($dg in $deptGroups) {
        $group = New-M365Group -DisplayName $dg.Name -Description $dg.Desc -MailNickname $dg.Nickname -GroupType "Unified"
        if ($group) { $groups[$dg.Nickname] = $group }
    }

    # Location Groups (Security Groups)
    $locationGroups = @(
        @{ Name = "NYC Office"; Desc = "All New York office employees"; Nickname = "nyc-office" },
        @{ Name = "London Office"; Desc = "All London office employees"; Nickname = "london-office" },
        @{ Name = "Phoenix Office"; Desc = "All Phoenix office employees"; Nickname = "phoenix-office" }
    )

    foreach ($lg in $locationGroups) {
        $group = New-M365Group -DisplayName $lg.Name -Description $lg.Desc -MailNickname $lg.Nickname -GroupType "Security"
        if ($group) { $groups[$lg.Nickname] = $group }
    }

    # Management Groups (Security Groups)
    $mgmtGroups = @(
        @{ Name = "Executive Team"; Desc = "C-level executives"; Nickname = "executive-team" },
        @{ Name = "All Managers"; Desc = "All people managers"; Nickname = "all-managers" },
        @{ Name = "All Directors"; Desc = "Directors and VPs"; Nickname = "all-directors" }
    )

    foreach ($mg in $mgmtGroups) {
        $group = New-M365Group -DisplayName $mg.Name -Description $mg.Desc -MailNickname $mg.Nickname -GroupType "Security"
        if ($group) { $groups[$mg.Nickname] = $group }
    }

    # Project Groups (M365 Groups)
    $projectGroups = @(
        @{ Name = "Platform Team"; Desc = "Platform engineering team"; Nickname = "platform-team" },
        @{ Name = "Mobile Team"; Desc = "Mobile development team"; Nickname = "mobile-team" },
        @{ Name = "API Team"; Desc = "API development team"; Nickname = "api-team" },
        @{ Name = "Enterprise Sales"; Desc = "Enterprise sales team"; Nickname = "enterprise-sales" },
        @{ Name = "SMB Sales"; Desc = "SMB sales team"; Nickname = "smb-sales" }
    )

    foreach ($pg in $projectGroups) {
        $group = New-M365Group -DisplayName $pg.Name -Description $pg.Desc -MailNickname $pg.Nickname -GroupType "Unified"
        if ($group) { $groups[$pg.Nickname] = $group }
    }

    # Phase 5: Add Users to Groups
    Write-Log "========================================" -Level "INFO"
    Write-Log "Phase 5: Adding Users to Groups" -Level "INFO"
    Write-Log "========================================" -Level "INFO"

    # Map departments to group nicknames
    $deptToGroup = @{
        "Engineering" = "engineering-team"
        "Product" = "product-team"
        "Design" = "design-team"
        "Sales" = "sales-team"
        "Marketing" = "marketing-team"
        "Support" = "support-team"
        "HR" = "hr-team"
        "Finance" = "finance-team"
        "Executive" = "executive-team"
    }

    # Map locations to group nicknames
    $locationToGroup = @{
        "NYC" = "nyc-office"
        "London" = "london-office"
        "Phoenix" = "phoenix-office"
    }

    foreach ($mailNickname in $createdUsersMap.Keys) {
        $userInfo = $createdUsersMap[$mailNickname]

        # Add to department group
        $deptGroupNickname = $deptToGroup[$userInfo.Department]
        if ($deptGroupNickname -and $groups[$deptGroupNickname]) {
            Add-UserToGroup -GroupId $groups[$deptGroupNickname].Id -UserId $userInfo.Id -GroupName $deptGroupNickname -UserName $userInfo.DisplayName
        }

        # Add to location group
        $locGroupNickname = $locationToGroup[$userInfo.Location]
        if ($locGroupNickname -and $groups[$locGroupNickname]) {
            Add-UserToGroup -GroupId $groups[$locGroupNickname].Id -UserId $userInfo.Id -GroupName $locGroupNickname -UserName $userInfo.DisplayName
        }

        # Add managers to all-managers group
        if ($userInfo.Manager -and $groups["all-managers"]) {
            # This user has reports, so they should be in managers group
            # Actually, we should add users who ARE managers, not who HAVE managers
        }
    }

    # Add people with "Manager", "Director", "VP", "Chief" in title to management groups
    foreach ($mailNickname in $createdUsersMap.Keys) {
        $userInfo = $createdUsersMap[$mailNickname]
        $user = Get-MgUser -UserId $userInfo.Id -Property JobTitle
        $title = $user.JobTitle

        if ($title -match "Manager") {
            if ($groups["all-managers"]) {
                Add-UserToGroup -GroupId $groups["all-managers"].Id -UserId $userInfo.Id -GroupName "all-managers" -UserName $userInfo.DisplayName
            }
        }

        if ($title -match "VP|Director|Vice President") {
            if ($groups["all-directors"]) {
                Add-UserToGroup -GroupId $groups["all-directors"].Id -UserId $userInfo.Id -GroupName "all-directors" -UserName $userInfo.DisplayName
            }
        }

        if ($title -match "Chief|CEO|CTO|CFO|COO|CMO") {
            if ($groups["executive-team"]) {
                Add-UserToGroup -GroupId $groups["executive-team"].Id -UserId $userInfo.Id -GroupName "executive-team" -UserName $userInfo.DisplayName
            }
        }
    }

    # Summary
    Write-Log "========================================" -Level "INFO"
    Write-Log "Setup Complete!" -Level "SUCCESS"
    Write-Log "========================================" -Level "INFO"

    # Verification
    Write-Log "Running verification..." -Level "INFO"
    $totalUsers = (Get-MgUser -All).Count
    $totalGroups = (Get-MgGroup -All).Count

    Write-Log "Total users in tenant: $totalUsers" -Level "INFO"
    Write-Log "Total groups in tenant: $totalGroups" -Level "INFO"
    Write-Log "Users created/updated by this script: $($createdUsersMap.Count)" -Level "INFO"
    Write-Log "Groups created by this script: $($groups.Count)" -Level "INFO"
}

# Run main function
Main
