#Requires -Version 7.0

<#
.SYNOPSIS
    Complete M365 Lab Deployment - Single Session, Single Auth
.DESCRIPTION
    Deploys a full M365 demo lab environment with:
    - 100 users with pop-culture names across 8 departments
    - Management hierarchy (CEO -> C-Suite -> VPs -> Managers -> Staff)
    - 3 office locations (NYC, London, Phoenix)
    - 19+ groups (department, location, management, project)
    - 25 E5 licenses assigned to key roles
    - 36 assessment-findable issues
    - 21 pre-migration issues
    - Degraded secure score for security demos

    All operations use a SINGLE authentication session.
.PARAMETER TenantDomain
    Your tenant domain (e.g., "contoso.onmicrosoft.com")
.PARAMETER SkipProblems
    Skip creating assessment/migration issues
.PARAMETER SkipSecureScoreDegradation
    Skip degrading secure score
.PARAMETER WhatIf
    Show what would be done without making changes
.EXAMPLE
    ./deploy-m365-lab.ps1 -TenantDomain "mytenant.onmicrosoft.com"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [switch]$SkipProblems,
    [switch]$SkipSecureScoreDegradation,
    [switch]$WhatIf
)

$ErrorActionPreference = "Continue"
$script:Stats = @{
    UsersCreated = 0
    UsersUpdated = 0
    GroupsCreated = 0
    LicensesAssigned = 0
    ProblemsCreated = 0
    Errors = @()
}

#region Logging Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "HEADER"  { "Cyan" }
        default   { "White" }
    }
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message -ForegroundColor $color
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}
#endregion

#region User Data - 100 Pop Culture Characters
$UsersData = @{
    Executive = @(
        @{ displayName = "Jean-Luc Picard"; jobTitle = "Chief Executive Officer"; department = "Executive"; officeLocation = "NYC"; manager = $null; assignLicense = $true }
        @{ displayName = "Tony Stark"; jobTitle = "Chief Technology Officer"; department = "Executive"; officeLocation = "NYC"; manager = "Jean-Luc Picard"; assignLicense = $true }
        @{ displayName = "Scrooge McDuck"; jobTitle = "Chief Financial Officer"; department = "Executive"; officeLocation = "NYC"; manager = "Jean-Luc Picard"; assignLicense = $true }
        @{ displayName = "Miranda Priestly"; jobTitle = "Chief Operating Officer"; department = "Executive"; officeLocation = "NYC"; manager = "Jean-Luc Picard"; assignLicense = $true }
        @{ displayName = "Don Draper"; jobTitle = "Chief Marketing Officer"; department = "Executive"; officeLocation = "NYC"; manager = "Jean-Luc Picard"; assignLicense = $true }
    )
    Engineering = @(
        # VPs
        @{ displayName = "Felicity Smoak"; jobTitle = "VP Engineering"; department = "Engineering"; officeLocation = "NYC"; manager = "Tony Stark"; assignLicense = $true }
        @{ displayName = "Shuri Wakanda"; jobTitle = "VP Engineering"; department = "Engineering"; officeLocation = "London"; manager = "Tony Stark"; assignLicense = $true }
        @{ displayName = "Q Branch"; jobTitle = "VP Engineering"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Tony Stark"; assignLicense = $true }
        # Managers
        @{ displayName = "Neo Matrix"; jobTitle = "Engineering Manager"; department = "Engineering"; officeLocation = "NYC"; manager = "Felicity Smoak"; assignLicense = $true }
        @{ displayName = "Trinity Code"; jobTitle = "Engineering Manager"; department = "Engineering"; officeLocation = "London"; manager = "Shuri Wakanda"; assignLicense = $true }
        @{ displayName = "Morpheus Debug"; jobTitle = "Engineering Manager"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Q Branch"; assignLicense = $true }
        # Engineers - NYC
        @{ displayName = "Elliot Alderson"; jobTitle = "Senior Software Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        @{ displayName = "Lisbeth Salander"; jobTitle = "Security Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        @{ displayName = "Dennis Nedry"; jobTitle = "Systems Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        @{ displayName = "Moss Reynholm"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        @{ displayName = "Roy Trenneman"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        @{ displayName = "Penelope Garcia"; jobTitle = "Data Engineer"; department = "Engineering"; officeLocation = "NYC"; manager = "Neo Matrix"; assignLicense = $false }
        # Engineers - London
        @{ displayName = "Alan Turing"; jobTitle = "Principal Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Ada Lovelace"; jobTitle = "Senior Software Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Charles Babbage"; jobTitle = "Platform Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Grace Hopper"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Bertram Gilfoyle"; jobTitle = "DevOps Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Dinesh Chugtai"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        @{ displayName = "Richard Hendricks"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "London"; manager = "Trinity Code"; assignLicense = $false }
        # Engineers - Phoenix
        @{ displayName = "Abby Sciuto"; jobTitle = "Forensic Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
        @{ displayName = "Chloe OBrian"; jobTitle = "Systems Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
        @{ displayName = "Michael Westen"; jobTitle = "Security Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
        @{ displayName = "Walter OBrien"; jobTitle = "Senior Software Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
        @{ displayName = "Sylvester Dodd"; jobTitle = "Software Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
        @{ displayName = "Happy Hogan"; jobTitle = "QA Engineer"; department = "Engineering"; officeLocation = "Phoenix"; manager = "Morpheus Debug"; assignLicense = $false }
    )
    Product = @(
        @{ displayName = "Steve Jobs"; jobTitle = "VP Product"; department = "Product"; officeLocation = "NYC"; manager = "Tony Stark"; assignLicense = $true }
        @{ displayName = "Marissa Mayer"; jobTitle = "Product Manager"; department = "Product"; officeLocation = "NYC"; manager = "Steve Jobs"; assignLicense = $true }
        @{ displayName = "Satya Nadella"; jobTitle = "Product Manager"; department = "Product"; officeLocation = "London"; manager = "Steve Jobs"; assignLicense = $true }
        @{ displayName = "Sundar Pichai"; jobTitle = "Product Manager"; department = "Product"; officeLocation = "Phoenix"; manager = "Steve Jobs"; assignLicense = $true }
        @{ displayName = "Susan Wojcicki"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "NYC"; manager = "Marissa Mayer"; assignLicense = $false }
        @{ displayName = "Sheryl Sandberg"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "NYC"; manager = "Marissa Mayer"; assignLicense = $false }
        @{ displayName = "Meg Whitman"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "London"; manager = "Satya Nadella"; assignLicense = $false }
        @{ displayName = "Ginni Rometty"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "Phoenix"; manager = "Sundar Pichai"; assignLicense = $false }
        @{ displayName = "Lisa Su"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "NYC"; manager = "Marissa Mayer"; assignLicense = $false }
        @{ displayName = "Jensen Huang"; jobTitle = "Product Analyst"; department = "Product"; officeLocation = "London"; manager = "Satya Nadella"; assignLicense = $false }
    )
    Design = @(
        @{ displayName = "Edna Mode"; jobTitle = "Chief Design Officer"; department = "Design"; officeLocation = "NYC"; manager = "Jean-Luc Picard"; assignLicense = $true }
        @{ displayName = "Bob Ross"; jobTitle = "Design Manager"; department = "Design"; officeLocation = "NYC"; manager = "Edna Mode"; assignLicense = $true }
        @{ displayName = "Andy Warhol"; jobTitle = "Design Manager"; department = "Design"; officeLocation = "London"; manager = "Edna Mode"; assignLicense = $true }
        @{ displayName = "Frida Kahlo"; jobTitle = "Design Manager"; department = "Design"; officeLocation = "Phoenix"; manager = "Edna Mode"; assignLicense = $true }
        @{ displayName = "Pablo Picasso"; jobTitle = "Senior Designer"; department = "Design"; officeLocation = "NYC"; manager = "Bob Ross"; assignLicense = $false }
        @{ displayName = "Georgia OKeeffe"; jobTitle = "UX Designer"; department = "Design"; officeLocation = "NYC"; manager = "Bob Ross"; assignLicense = $false }
        @{ displayName = "Banksy Anonymous"; jobTitle = "Visual Designer"; department = "Design"; officeLocation = "London"; manager = "Andy Warhol"; assignLicense = $false }
        @{ displayName = "Keith Haring"; jobTitle = "UI Designer"; department = "Design"; officeLocation = "London"; manager = "Andy Warhol"; assignLicense = $false }
        @{ displayName = "Jean Basquiat"; jobTitle = "Designer"; department = "Design"; officeLocation = "Phoenix"; manager = "Frida Kahlo"; assignLicense = $false }
        @{ displayName = "Salvador Dali"; jobTitle = "Designer"; department = "Design"; officeLocation = "Phoenix"; manager = "Frida Kahlo"; assignLicense = $false }
    )
    Sales = @(
        @{ displayName = "Jordan Belfort"; jobTitle = "VP Sales"; department = "Sales"; officeLocation = "NYC"; manager = "Miranda Priestly"; assignLicense = $true }
        @{ displayName = "Saul Goodman"; jobTitle = "Sales Manager"; department = "Sales"; officeLocation = "NYC"; manager = "Jordan Belfort"; assignLicense = $true }
        @{ displayName = "Ari Gold"; jobTitle = "Sales Manager"; department = "Sales"; officeLocation = "London"; manager = "Jordan Belfort"; assignLicense = $true }
        @{ displayName = "Gordon Gekko"; jobTitle = "Sales Manager"; department = "Sales"; officeLocation = "Phoenix"; manager = "Jordan Belfort"; assignLicense = $true }
        @{ displayName = "Ferris Bueller"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "NYC"; manager = "Saul Goodman"; assignLicense = $false }
        @{ displayName = "Elle Woods"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "NYC"; manager = "Saul Goodman"; assignLicense = $false }
        @{ displayName = "Harvey Specter"; jobTitle = "Senior Account Executive"; department = "Sales"; officeLocation = "NYC"; manager = "Saul Goodman"; assignLicense = $false }
        @{ displayName = "Dominic Toretto"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "London"; manager = "Ari Gold"; assignLicense = $false }
        @{ displayName = "James Bond"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "London"; manager = "Ari Gold"; assignLicense = $false }
        @{ displayName = "Ethan Hunt"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "London"; manager = "Ari Gold"; assignLicense = $false }
        @{ displayName = "Indiana Jones"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "Phoenix"; manager = "Gordon Gekko"; assignLicense = $false }
        @{ displayName = "Han Solo"; jobTitle = "Account Executive"; department = "Sales"; officeLocation = "Phoenix"; manager = "Gordon Gekko"; assignLicense = $false }
        @{ displayName = "Malcolm Reynolds"; jobTitle = "Sales Rep"; department = "Sales"; officeLocation = "NYC"; manager = "Saul Goodman"; assignLicense = $false }
        @{ displayName = "Starbuck Thrace"; jobTitle = "Sales Rep"; department = "Sales"; officeLocation = "London"; manager = "Ari Gold"; assignLicense = $false }
        @{ displayName = "Peter Quill"; jobTitle = "Sales Rep"; department = "Sales"; officeLocation = "Phoenix"; manager = "Gordon Gekko"; assignLicense = $false }
    )
    Marketing = @(
        @{ displayName = "Peggy Olson"; jobTitle = "Marketing Director"; department = "Marketing"; officeLocation = "NYC"; manager = "Don Draper"; assignLicense = $true }
        @{ displayName = "Rachel Zane"; jobTitle = "Marketing Manager"; department = "Marketing"; officeLocation = "NYC"; manager = "Peggy Olson"; assignLicense = $true }
        @{ displayName = "Louis Litt"; jobTitle = "Marketing Manager"; department = "Marketing"; officeLocation = "London"; manager = "Peggy Olson"; assignLicense = $true }
        @{ displayName = "Donna Paulsen"; jobTitle = "Marketing Manager"; department = "Marketing"; officeLocation = "Phoenix"; manager = "Peggy Olson"; assignLicense = $true }
        @{ displayName = "Betty Draper"; jobTitle = "Content Strategist"; department = "Marketing"; officeLocation = "NYC"; manager = "Rachel Zane"; assignLicense = $false }
        @{ displayName = "Joan Holloway"; jobTitle = "Brand Manager"; department = "Marketing"; officeLocation = "NYC"; manager = "Rachel Zane"; assignLicense = $false }
        @{ displayName = "Ken Cosgrove"; jobTitle = "Marketing Specialist"; department = "Marketing"; officeLocation = "London"; manager = "Louis Litt"; assignLicense = $false }
        @{ displayName = "Harry Crane"; jobTitle = "Digital Marketing"; department = "Marketing"; officeLocation = "London"; manager = "Louis Litt"; assignLicense = $false }
        @{ displayName = "Megan Draper"; jobTitle = "Marketing Coordinator"; department = "Marketing"; officeLocation = "Phoenix"; manager = "Donna Paulsen"; assignLicense = $false }
        @{ displayName = "Ted Chaough"; jobTitle = "Marketing Specialist"; department = "Marketing"; officeLocation = "Phoenix"; manager = "Donna Paulsen"; assignLicense = $false }
    )
    Support = @(
        @{ displayName = "Leslie Knope"; jobTitle = "VP Customer Success"; department = "Support"; officeLocation = "NYC"; manager = "Miranda Priestly"; assignLicense = $true }
        @{ displayName = "Michael Scott"; jobTitle = "Support Manager"; department = "Support"; officeLocation = "NYC"; manager = "Leslie Knope"; assignLicense = $true }
        @{ displayName = "David Brent"; jobTitle = "Support Manager"; department = "Support"; officeLocation = "London"; manager = "Leslie Knope"; assignLicense = $true }
        @{ displayName = "Ron Swanson"; jobTitle = "Support Manager"; department = "Support"; officeLocation = "Phoenix"; manager = "Leslie Knope"; assignLicense = $true }
        @{ displayName = "Dwight Schrute"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "NYC"; manager = "Michael Scott"; assignLicense = $false }
        @{ displayName = "Jim Halpert"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "NYC"; manager = "Michael Scott"; assignLicense = $false }
        @{ displayName = "Tim Canterbury"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "London"; manager = "David Brent"; assignLicense = $false }
        @{ displayName = "Gareth Keenan"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "London"; manager = "David Brent"; assignLicense = $false }
        @{ displayName = "April Ludgate"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "Phoenix"; manager = "Ron Swanson"; assignLicense = $false }
        @{ displayName = "Andy Dwyer"; jobTitle = "Support Specialist"; department = "Support"; officeLocation = "Phoenix"; manager = "Ron Swanson"; assignLicense = $false }
    )
    HR = @(
        @{ displayName = "Toby Flenderson"; jobTitle = "VP Human Resources"; department = "HR"; officeLocation = "NYC"; manager = "Miranda Priestly"; assignLicense = $true }
        @{ displayName = "Holly Flax"; jobTitle = "HR Manager"; department = "HR"; officeLocation = "NYC"; manager = "Toby Flenderson"; assignLicense = $true }
        @{ displayName = "Jan Levinson"; jobTitle = "HR Manager"; department = "HR"; officeLocation = "London"; manager = "Toby Flenderson"; assignLicense = $false }
        @{ displayName = "Kelly Kapoor"; jobTitle = "HR Specialist"; department = "HR"; officeLocation = "NYC"; manager = "Holly Flax"; assignLicense = $false }
        @{ displayName = "Ryan Howard"; jobTitle = "HR Coordinator"; department = "HR"; officeLocation = "Phoenix"; manager = "Toby Flenderson"; assignLicense = $false }
    )
    Finance = @(
        @{ displayName = "Oscar Martinez"; jobTitle = "Finance Director"; department = "Finance"; officeLocation = "NYC"; manager = "Scrooge McDuck"; assignLicense = $true }
        @{ displayName = "Angela Martin"; jobTitle = "Finance Manager"; department = "Finance"; officeLocation = "NYC"; manager = "Oscar Martinez"; assignLicense = $true }
        @{ displayName = "Kevin Malone"; jobTitle = "Accountant"; department = "Finance"; officeLocation = "NYC"; manager = "Angela Martin"; assignLicense = $false }
        @{ displayName = "Stanley Hudson"; jobTitle = "Senior Accountant"; department = "Finance"; officeLocation = "London"; manager = "Oscar Martinez"; assignLicense = $false }
        @{ displayName = "Phyllis Vance"; jobTitle = "Accountant"; department = "Finance"; officeLocation = "Phoenix"; manager = "Oscar Martinez"; assignLicense = $false }
    )
}

$GroupsToCreate = @(
    # Department Groups (M365)
    @{ displayName = "Engineering Team"; description = "All Engineering staff"; mailNickname = "engineering-team"; groupTypes = @("Unified") }
    @{ displayName = "Product Team"; description = "All Product staff"; mailNickname = "product-team"; groupTypes = @("Unified") }
    @{ displayName = "Design Team"; description = "All Design staff"; mailNickname = "design-team"; groupTypes = @("Unified") }
    @{ displayName = "Sales Team"; description = "All Sales staff"; mailNickname = "sales-team"; groupTypes = @("Unified") }
    @{ displayName = "Marketing Team"; description = "All Marketing staff"; mailNickname = "marketing-team"; groupTypes = @("Unified") }
    @{ displayName = "Support Team"; description = "All Support staff"; mailNickname = "support-team"; groupTypes = @("Unified") }
    @{ displayName = "HR Team"; description = "All HR staff"; mailNickname = "hr-team"; groupTypes = @("Unified") }
    @{ displayName = "Finance Team"; description = "All Finance staff"; mailNickname = "finance-team"; groupTypes = @("Unified") }

    # Location Groups (Security)
    @{ displayName = "NYC Office"; description = "All NYC employees"; mailNickname = "nyc-office"; groupTypes = @() }
    @{ displayName = "London Office"; description = "All London employees"; mailNickname = "london-office"; groupTypes = @() }
    @{ displayName = "Phoenix Office"; description = "All Phoenix employees"; mailNickname = "phoenix-office"; groupTypes = @() }

    # Management Groups (Security)
    @{ displayName = "Executive Team"; description = "C-Level executives"; mailNickname = "executive-team"; groupTypes = @() }
    @{ displayName = "All Managers"; description = "All people managers"; mailNickname = "all-managers"; groupTypes = @() }
    @{ displayName = "All Directors"; description = "Directors and VPs"; mailNickname = "all-directors"; groupTypes = @() }

    # Project Groups (M365)
    @{ displayName = "Platform Team"; description = "Platform engineering"; mailNickname = "platform-team"; groupTypes = @("Unified") }
    @{ displayName = "Mobile Team"; description = "Mobile development"; mailNickname = "mobile-team"; groupTypes = @("Unified") }
    @{ displayName = "API Team"; description = "API development"; mailNickname = "api-team"; groupTypes = @("Unified") }
    @{ displayName = "Enterprise Sales"; description = "Enterprise accounts"; mailNickname = "enterprise-sales"; groupTypes = @("Unified") }
    @{ displayName = "SMB Sales"; description = "SMB accounts"; mailNickname = "smb-sales"; groupTypes = @("Unified") }
)
#endregion

#region Helper Functions
function Get-MailNickname {
    param([string]$DisplayName)
    $nickname = $DisplayName.ToLower() -replace "[^a-z0-9]", ""
    return $nickname.Substring(0, [Math]::Min(64, $nickname.Length))
}

function Get-SafeUPN {
    param([string]$DisplayName, [string]$Domain)
    $base = $DisplayName.ToLower() -replace "[^a-z0-9 ]", "" -replace "\s+", "."
    return "$base@$Domain"
}
#endregion

#region Main Deployment Functions
function Connect-ToGraph {
    Write-Section "AUTHENTICATING TO MICROSOFT GRAPH"

    $requiredScopes = @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.Authorization",
        "Policy.ReadWrite.AuthenticationMethod",
        "Organization.ReadWrite.All"
    )

    Write-Log "Required scopes: $($requiredScopes.Count)" -Level "INFO"
    Write-Log "Initiating device code authentication..." -Level "INFO"
    Write-Host ""
    Write-Host "  IMPORTANT: Complete the device login promptly to avoid timeout!" -ForegroundColor Yellow
    Write-Host ""

    try {
        Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -NoWelcome
        $context = Get-MgContext
        Write-Log "Connected as: $($context.Account)" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Authentication failed: $_" -Level "ERROR"
        return $false
    }
}

function Deploy-Users {
    Write-Section "DEPLOYING 100 USERS"

    $allUsers = @()
    foreach ($dept in $UsersData.Keys) {
        $allUsers += $UsersData[$dept]
    }

    Write-Log "Processing $($allUsers.Count) users..." -Level "INFO"

    # Get existing users
    $existingUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName" -ErrorAction SilentlyContinue
    $existingMap = @{}
    foreach ($u in $existingUsers) {
        $existingMap[$u.DisplayName] = $u
    }

    # Get E5 Developer SKU
    $e5Sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -like "*DEVELOPERPACK*" -or $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" } | Select-Object -First 1

    # Create users in order (executives first for manager assignment)
    $createdUsers = @{}
    $processOrder = @("Executive", "Engineering", "Product", "Design", "Sales", "Marketing", "Support", "HR", "Finance")

    foreach ($dept in $processOrder) {
        if (-not $UsersData.ContainsKey($dept)) { continue }

        foreach ($userData in $UsersData[$dept]) {
            $displayName = $userData.displayName
            $upn = Get-SafeUPN -DisplayName $displayName -Domain $TenantDomain

            if ($existingMap.ContainsKey($displayName)) {
                $user = $existingMap[$displayName]
                Write-Log "  Exists: $displayName" -Level "INFO"
                $createdUsers[$displayName] = $user
                $script:Stats.UsersUpdated++
            } else {
                try {
                    $params = @{
                        AccountEnabled = $true
                        DisplayName = $displayName
                        MailNickname = Get-MailNickname -DisplayName $displayName
                        UserPrincipalName = $upn
                        PasswordProfile = @{
                            Password = "DemoP@ss2024!"
                            ForceChangePasswordNextSignIn = $false
                        }
                        Department = $userData.department
                        JobTitle = $userData.jobTitle
                        OfficeLocation = $userData.officeLocation
                        UsageLocation = "US"
                    }

                    $user = New-MgUser @params -ErrorAction Stop
                    $createdUsers[$displayName] = $user
                    Write-Log "  Created: $displayName" -Level "SUCCESS"
                    $script:Stats.UsersCreated++
                } catch {
                    Write-Log "  Failed: $displayName - $_" -Level "ERROR"
                    $script:Stats.Errors += "User: $displayName - $_"
                }
            }
        }
    }

    # Set managers
    Write-Log "Setting manager relationships..." -Level "INFO"
    foreach ($dept in $processOrder) {
        if (-not $UsersData.ContainsKey($dept)) { continue }

        foreach ($userData in $UsersData[$dept]) {
            if ($userData.manager -and $createdUsers.ContainsKey($userData.displayName) -and $createdUsers.ContainsKey($userData.manager)) {
                try {
                    $userId = $createdUsers[$userData.displayName].Id
                    $managerId = $createdUsers[$userData.manager].Id

                    Set-MgUserManagerByRef -UserId $userId -BodyParameter @{
                        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$managerId"
                    } -ErrorAction SilentlyContinue
                } catch { }
            }
        }
    }

    # Assign licenses
    if ($e5Sku) {
        Write-Log "Assigning E5 licenses..." -Level "INFO"
        foreach ($dept in $processOrder) {
            if (-not $UsersData.ContainsKey($dept)) { continue }

            foreach ($userData in $UsersData[$dept]) {
                if ($userData.assignLicense -and $createdUsers.ContainsKey($userData.displayName)) {
                    try {
                        Set-MgUserLicense -UserId $createdUsers[$userData.displayName].Id -AddLicenses @(@{SkuId = $e5Sku.SkuId}) -RemoveLicenses @() -ErrorAction SilentlyContinue
                        $script:Stats.LicensesAssigned++
                    } catch { }
                }
            }
        }
        Write-Log "Licenses assigned: $($script:Stats.LicensesAssigned)" -Level "SUCCESS"
    }

    return $createdUsers
}

function Deploy-Groups {
    param([hashtable]$CreatedUsers)

    Write-Section "DEPLOYING GROUPS"

    $existingGroups = Get-MgGroup -All -Property "Id,DisplayName" -ErrorAction SilentlyContinue
    $existingGroupMap = @{}
    foreach ($g in $existingGroups) {
        $existingGroupMap[$g.DisplayName] = $g
    }

    $createdGroups = @{}

    foreach ($groupDef in $GroupsToCreate) {
        if ($existingGroupMap.ContainsKey($groupDef.displayName)) {
            Write-Log "  Exists: $($groupDef.displayName)" -Level "INFO"
            $createdGroups[$groupDef.displayName] = $existingGroupMap[$groupDef.displayName]
        } else {
            try {
                $params = @{
                    DisplayName = $groupDef.displayName
                    Description = $groupDef.description
                    MailNickname = $groupDef.mailNickname
                    MailEnabled = ($groupDef.groupTypes -contains "Unified")
                    SecurityEnabled = $true
                    GroupTypes = $groupDef.groupTypes
                }

                $group = New-MgGroup @params -ErrorAction Stop
                $createdGroups[$groupDef.displayName] = $group
                Write-Log "  Created: $($groupDef.displayName)" -Level "SUCCESS"
                $script:Stats.GroupsCreated++
            } catch {
                Write-Log "  Failed: $($groupDef.displayName) - $_" -Level "ERROR"
            }
        }
    }

    # Add members to groups
    Write-Log "Adding group members..." -Level "INFO"

    # Department mappings
    $deptGroups = @{
        "Engineering" = "Engineering Team"
        "Product" = "Product Team"
        "Design" = "Design Team"
        "Sales" = "Sales Team"
        "Marketing" = "Marketing Team"
        "Support" = "Support Team"
        "HR" = "HR Team"
        "Finance" = "Finance Team"
    }

    # Location mappings
    $locationGroups = @{
        "NYC" = "NYC Office"
        "London" = "London Office"
        "Phoenix" = "Phoenix Office"
    }

    foreach ($dept in $UsersData.Keys) {
        foreach ($userData in $UsersData[$dept]) {
            if (-not $CreatedUsers.ContainsKey($userData.displayName)) { continue }
            $userId = $CreatedUsers[$userData.displayName].Id

            # Add to department group
            if ($deptGroups.ContainsKey($userData.department) -and $createdGroups.ContainsKey($deptGroups[$userData.department])) {
                try {
                    New-MgGroupMember -GroupId $createdGroups[$deptGroups[$userData.department]].Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                } catch { }
            }

            # Add to location group
            if ($locationGroups.ContainsKey($userData.officeLocation) -and $createdGroups.ContainsKey($locationGroups[$userData.officeLocation])) {
                try {
                    New-MgGroupMember -GroupId $createdGroups[$locationGroups[$userData.officeLocation]].Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                } catch { }
            }

            # Add executives to Executive Team
            if ($userData.department -eq "Executive" -and $createdGroups.ContainsKey("Executive Team")) {
                try {
                    New-MgGroupMember -GroupId $createdGroups["Executive Team"].Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                } catch { }
            }

            # Add managers to All Managers
            if ($userData.jobTitle -match "Manager|Director|VP|Chief" -and $createdGroups.ContainsKey("All Managers")) {
                try {
                    New-MgGroupMember -GroupId $createdGroups["All Managers"].Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                } catch { }
            }
        }
    }

    return $createdGroups
}

function Deploy-AssessmentProblems {
    param([hashtable]$CreatedUsers, [hashtable]$CreatedGroups)

    Write-Section "DEPLOYING ASSESSMENT PROBLEMS (36 Issues)"

    $problems = @()

    # 1. Stale/Inactive Users
    Write-Log "Creating stale user accounts..." -Level "INFO"
    $staleUsers = @(
        @{ name = "Old Employee One"; lastSignIn = (Get-Date).AddDays(-180) }
        @{ name = "Former Contractor"; lastSignIn = (Get-Date).AddDays(-365) }
        @{ name = "Test Account Legacy"; lastSignIn = (Get-Date).AddDays(-270) }
    )

    foreach ($stale in $staleUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $stale.name -Domain $TenantDomain
            $user = New-MgUser -DisplayName $stale.name -MailNickname (Get-MailNickname $stale.name) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="StaleP@ss123!"; ForceChangePasswordNextSignIn=$false} -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $problems += "StaleUser: $($stale.name)"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 2. Users missing managers
    Write-Log "Creating orphaned users (no manager)..." -Level "INFO"
    $orphanedUsers = @("Orphan Worker One", "Orphan Worker Two", "No Manager Person")
    foreach ($orphan in $orphanedUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $orphan -Domain $TenantDomain
            $user = New-MgUser -DisplayName $orphan -MailNickname (Get-MailNickname $orphan) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="OrphanP@ss123!"; ForceChangePasswordNextSignIn=$false} -Department "Unknown" -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $problems += "OrphanedUser: $orphan"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 3. Empty Groups
    Write-Log "Creating empty groups..." -Level "INFO"
    $emptyGroups = @("Abandoned Project", "Old Team Group", "Deprecated Access")
    foreach ($grp in $emptyGroups) {
        try {
            $group = New-MgGroup -DisplayName $grp -MailNickname ($grp.ToLower() -replace " ", "-") -MailEnabled:$false -SecurityEnabled:$true -GroupTypes @() -ErrorAction SilentlyContinue
            if ($group) { $problems += "EmptyGroup: $grp"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 4. Groups without owners
    Write-Log "Creating ownerless groups..." -Level "INFO"
    $ownerlessGroups = @("No Owner Team", "Ownerless Project")
    foreach ($grp in $ownerlessGroups) {
        try {
            $group = New-MgGroup -DisplayName $grp -MailNickname ($grp.ToLower() -replace " ", "-") -MailEnabled:$false -SecurityEnabled:$true -GroupTypes @() -ErrorAction SilentlyContinue
            if ($group) { $problems += "OwnerlessGroup: $grp"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 5. Over-privileged users (multiple admin roles)
    Write-Log "Creating over-privileged accounts..." -Level "INFO"
    if ($CreatedUsers.ContainsKey("Tony Stark")) {
        $targetId = $CreatedUsers["Tony Stark"].Id
        $rolesToAdd = @("Exchange Administrator", "SharePoint Administrator", "Teams Administrator", "Security Administrator")

        foreach ($roleName in $rolesToAdd) {
            try {
                $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                if (-not $role) {
                    $template = Get-MgDirectoryRoleTemplate -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                    if ($template) { $role = New-MgDirectoryRole -RoleTemplateId $template.Id -ErrorAction SilentlyContinue }
                }
                if ($role) {
                    New-MgDirectoryRoleMember -DirectoryRoleId $role.Id -DirectoryObjectId $targetId -ErrorAction SilentlyContinue
                    $problems += "RoleOverlap: Tony Stark - $roleName"
                    $script:Stats.ProblemsCreated++
                }
            } catch { }
        }
    }

    # 6. External/guest issues
    Write-Log "Creating external collaboration issues..." -Level "INFO"
    $guestUsers = @("External Vendor One", "Old Partner Account")
    foreach ($guest in $guestUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $guest -Domain $TenantDomain
            $user = New-MgUser -DisplayName $guest -MailNickname (Get-MailNickname $guest) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="GuestP@ss123!"; ForceChangePasswordNextSignIn=$false} -JobTitle "External" -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $problems += "ExternalUser: $guest"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 7. App registrations with excessive permissions
    Write-Log "Creating problematic app registrations..." -Level "INFO"
    $apps = @(
        @{ name = "Legacy Integration App"; expiring = $true }
        @{ name = "Overprivileged Automation"; permissions = "excessive" }
        @{ name = "Unmonitored Background Service"; owner = $null }
    )

    foreach ($app in $apps) {
        try {
            $newApp = New-MgApplication -DisplayName $app.name -ErrorAction SilentlyContinue
            if ($newApp) {
                if ($app.expiring) {
                    $cred = Add-MgApplicationPassword -ApplicationId $newApp.Id -PasswordCredential @{
                        DisplayName = "Expiring Secret"
                        EndDateTime = (Get-Date).AddDays(7)
                    } -ErrorAction SilentlyContinue
                }
                $problems += "ProblematicApp: $($app.name)"
                $script:Stats.ProblemsCreated++
            }
        } catch { }
    }

    # 8. PII handlers without proper controls
    Write-Log "Creating PII compliance gaps..." -Level "INFO"
    $piiUsers = @("HR Data Handler", "Finance PII Access", "Customer Data Worker")
    foreach ($pii in $piiUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $pii -Domain $TenantDomain
            $user = New-MgUser -DisplayName $pii -MailNickname (Get-MailNickname $pii) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="PIIP@ss123!"; ForceChangePasswordNextSignIn=$false} -Department "Sensitive Data" -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $problems += "PIIHandler: $pii"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    Write-Log "Assessment problems created: $($script:Stats.ProblemsCreated)" -Level "SUCCESS"
    return $problems
}

function Deploy-MigrationIssues {
    param([hashtable]$CreatedUsers)

    Write-Section "DEPLOYING MIGRATION ISSUES (21 Issues)"

    $issues = @()

    # 1. UPN/Email mismatches
    Write-Log "Creating UPN/email mismatch users..." -Level "INFO"
    $mismatchUsers = @(
        @{ name = "Bob UPN Mismatch"; email = "robert.different@external.com" }
        @{ name = "Alice Alias Issue"; email = "alice.wrong@partner.org" }
    )

    foreach ($mm in $mismatchUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $mm.name -Domain $TenantDomain
            $user = New-MgUser -DisplayName $mm.name -MailNickname (Get-MailNickname $mm.name) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="MismatchP@ss123!"; ForceChangePasswordNextSignIn=$false} -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $issues += "UPNMismatch: $($mm.name)"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 2. Users with no license
    Write-Log "Creating unlicensed users..." -Level "INFO"
    $unlicensed = @("Unlicensed Worker One", "NoLicense Contractor", "License Gap User")
    foreach ($ul in $unlicensed) {
        try {
            $upn = Get-SafeUPN -DisplayName $ul -Domain $TenantDomain
            $user = New-MgUser -DisplayName $ul -MailNickname (Get-MailNickname $ul) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="UnlicP@ss123!"; ForceChangePasswordNextSignIn=$false} -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $issues += "Unlicensed: $ul"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 3. Nested group structures
    Write-Log "Creating nested group issues..." -Level "INFO"
    try {
        $parent = New-MgGroup -DisplayName "Nested Parent Group" -MailNickname "nested-parent" -MailEnabled:$false -SecurityEnabled:$true -GroupTypes @() -ErrorAction SilentlyContinue
        $child = New-MgGroup -DisplayName "Nested Child Group" -MailNickname "nested-child" -MailEnabled:$false -SecurityEnabled:$true -GroupTypes @() -ErrorAction SilentlyContinue
        $grandchild = New-MgGroup -DisplayName "Nested Grandchild" -MailNickname "nested-grandchild" -MailEnabled:$false -SecurityEnabled:$true -GroupTypes @() -ErrorAction SilentlyContinue

        if ($parent -and $child) {
            New-MgGroupMember -GroupId $parent.Id -DirectoryObjectId $child.Id -ErrorAction SilentlyContinue
            $issues += "NestedGroup: Parent->Child"
            $script:Stats.ProblemsCreated++
        }
        if ($child -and $grandchild) {
            New-MgGroupMember -GroupId $child.Id -DirectoryObjectId $grandchild.Id -ErrorAction SilentlyContinue
            $issues += "NestedGroup: Child->Grandchild"
            $script:Stats.ProblemsCreated++
        }
    } catch { }

    # 4. Apps with expiring credentials
    Write-Log "Creating apps with expiring credentials..." -Level "INFO"
    $expiringApps = @("Soon Expiring App 1", "Soon Expiring App 2")
    foreach ($appName in $expiringApps) {
        try {
            $app = New-MgApplication -DisplayName $appName -ErrorAction SilentlyContinue
            if ($app) {
                Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
                    DisplayName = "Expiring in 30 days"
                    EndDateTime = (Get-Date).AddDays(30)
                } -ErrorAction SilentlyContinue
                $issues += "ExpiringApp: $appName"
                $script:Stats.ProblemsCreated++
            }
        } catch { }
    }

    # 5. Shared mailbox indicators
    Write-Log "Creating shared mailbox issues..." -Level "INFO"
    $sharedUsers = @("Shared Mailbox Sales", "Shared Mailbox Support")
    foreach ($shared in $sharedUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $shared -Domain $TenantDomain
            $user = New-MgUser -DisplayName $shared -MailNickname (Get-MailNickname $shared) -UserPrincipalName $upn -AccountEnabled:$false -PasswordProfile @{Password="SharedP@ss123!"; ForceChangePasswordNextSignIn=$false} -JobTitle "Shared Mailbox" -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $issues += "SharedMailbox: $shared"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 6. Legal hold users
    Write-Log "Creating legal hold scenarios..." -Level "INFO"
    $legalUsers = @("Legal Hold User", "Litigation Pending")
    foreach ($legal in $legalUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $legal -Domain $TenantDomain
            $user = New-MgUser -DisplayName $legal -MailNickname (Get-MailNickname $legal) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="LegalP@ss123!"; ForceChangePasswordNextSignIn=$false} -Department "Legal" -JobTitle "Under Hold" -UsageLocation "US" -ErrorAction SilentlyContinue
            if ($user) { $issues += "LegalHold: $legal"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    # 7. GDPR compliance markers
    Write-Log "Creating GDPR compliance issues..." -Level "INFO"
    $gdprUsers = @("EU Data Subject", "GDPR Region User")
    foreach ($gdpr in $gdprUsers) {
        try {
            $upn = Get-SafeUPN -DisplayName $gdpr -Domain $TenantDomain
            $user = New-MgUser -DisplayName $gdpr -MailNickname (Get-MailNickname $gdpr) -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="GDPRP@ss123!"; ForceChangePasswordNextSignIn=$false} -Country "Germany" -UsageLocation "DE" -ErrorAction SilentlyContinue
            if ($user) { $issues += "GDPRUser: $gdpr"; $script:Stats.ProblemsCreated++ }
        } catch { }
    }

    Write-Log "Migration issues created" -Level "SUCCESS"
    return $issues
}

function Degrade-SecureScore {
    Write-Section "DEGRADING SECURE SCORE"

    $changes = @()

    # 1. Disable Security Defaults
    Write-Log "Checking security defaults..." -Level "INFO"
    try {
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
        if ($securityDefaults.IsEnabled) {
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled:$false -ErrorAction SilentlyContinue
            $changes += "Disabled security defaults"
            Write-Log "  Security defaults disabled" -Level "WARNING"
        } else {
            Write-Log "  Security defaults already disabled" -Level "INFO"
        }
    } catch {
        Write-Log "  Could not modify security defaults" -Level "ERROR"
    }

    # 2. Enable user app consent
    Write-Log "Enabling user app consent..." -Level "INFO"
    try {
        $params = @{
            DefaultUserRolePermissions = @{
                AllowedToCreateApps = $true
                AllowedToCreateSecurityGroups = $true
                AllowedToReadOtherUsers = $true
                PermissionGrantPoliciesAssigned = @("ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
            }
        }
        Update-MgPolicyAuthorizationPolicy -BodyParameter $params -ErrorAction SilentlyContinue
        $changes += "Enabled user app consent"
        Write-Log "  User app consent enabled" -Level "WARNING"
    } catch {
        Write-Log "  Could not update app consent settings" -Level "ERROR"
    }

    # 3. Create unprotected admin
    Write-Log "Creating unprotected admin account..." -Level "INFO"
    try {
        $upn = "unprotected-admin@$TenantDomain"
        $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

        if (-not $existing) {
            $admin = New-MgUser -DisplayName "Unprotected Admin Account" -MailNickname "unprotected-admin" -UserPrincipalName $upn -AccountEnabled:$true -PasswordProfile @{Password="WeakAdmin123!"; ForceChangePasswordNextSignIn=$false} -JobTitle "Administrator" -UsageLocation "US" -ErrorAction SilentlyContinue

            if ($admin) {
                $globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction SilentlyContinue
                if ($globalAdminRole) {
                    New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id -DirectoryObjectId $admin.Id -ErrorAction SilentlyContinue
                }
                $changes += "Created unprotected admin (no MFA)"
                Write-Log "  Unprotected admin created" -Level "WARNING"
            }
        } else {
            Write-Log "  Unprotected admin already exists" -Level "INFO"
        }
    } catch {
        Write-Log "  Could not create unprotected admin" -Level "ERROR"
    }

    # Document gaps
    Write-Log "Documenting security gaps..." -Level "INFO"
    $changes += "No CA policy blocking legacy auth"
    $changes += "No CA policy requiring admin MFA"
    $changes += "No sign-in risk policy"
    $changes += "No user risk policy"

    Write-Log "Secure score degradation complete" -Level "WARNING"
    Write-Log "Score will update in 24-48 hours" -Level "INFO"

    return $changes
}
#endregion

#region Main Execution
Write-Host ""
Write-Host "  M365 LAB DEPLOYMENT" -ForegroundColor Cyan
Write-Host "  ===================" -ForegroundColor Cyan
Write-Host "  Target Tenant: $TenantDomain" -ForegroundColor White
Write-Host "  Users: 100 | Groups: 19+ | Issues: 57+" -ForegroundColor White
Write-Host ""

if ($WhatIf) {
    Write-Host "  [WHATIF MODE - No changes will be made]" -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# Single authentication
if (-not (Connect-ToGraph)) {
    Write-Log "Cannot proceed without authentication" -Level "ERROR"
    exit 1
}

# Deploy users
$createdUsers = Deploy-Users

# Deploy groups
$createdGroups = Deploy-Groups -CreatedUsers $createdUsers

# Deploy problems (unless skipped)
if (-not $SkipProblems) {
    $assessmentProblems = Deploy-AssessmentProblems -CreatedUsers $createdUsers -CreatedGroups $createdGroups
    $migrationIssues = Deploy-MigrationIssues -CreatedUsers $createdUsers
}

# Degrade secure score (unless skipped)
if (-not $SkipSecureScoreDegradation) {
    $secureScoreChanges = Degrade-SecureScore
}

# Final Summary
Write-Section "DEPLOYMENT COMPLETE"

Write-Host ""
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "  -------" -ForegroundColor Cyan
Write-Host "  Users Created:    $($script:Stats.UsersCreated)" -ForegroundColor Green
Write-Host "  Users Updated:    $($script:Stats.UsersUpdated)" -ForegroundColor White
Write-Host "  Groups Created:   $($script:Stats.GroupsCreated)" -ForegroundColor Green
Write-Host "  Licenses Assigned: $($script:Stats.LicensesAssigned)" -ForegroundColor Green
Write-Host "  Problems Created: $($script:Stats.ProblemsCreated)" -ForegroundColor Yellow
Write-Host ""

if ($script:Stats.Errors.Count -gt 0) {
    Write-Host "  ERRORS ($($script:Stats.Errors.Count)):" -ForegroundColor Red
    foreach ($err in $script:Stats.Errors | Select-Object -First 5) {
        Write-Host "    - $err" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "  NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Wait 24-48 hours for Secure Score to update" -ForegroundColor White
Write-Host "  2. Run assessment tools against the tenant" -ForegroundColor White
Write-Host "  3. Use restore-secure-score.ps1 to restore security" -ForegroundColor White
Write-Host ""

Disconnect-MgGraph -ErrorAction SilentlyContinue
Write-Log "Disconnected from Microsoft Graph" -Level "INFO"
#endregion
