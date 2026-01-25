# M365 Test Lab Setup - Quick Start Guide

## Overview

This setup creates a realistic 100-user demo environment in the `8k8232.onmicrosoft.com` tenant with:
- 100 users with pop-culture inspired names
- 3 office locations (NYC, London, Phoenix)
- 8 departments with realistic hierarchy
- 19 groups (department, location, management, project)
- 25 users with E5 licenses assigned

## Prerequisites

### 1. Install Microsoft Graph PowerShell

```powershell
# Install the Microsoft Graph module (if not already installed)
Install-Module Microsoft.Graph -Scope CurrentUser

# Or install only required submodules
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

### 2. Verify Prerequisites

```powershell
cd ~/swa-workflow-test/m365-lab-setup
./check-prerequisites.ps1
```

## Running the Setup

### Step 1: Connect to Microsoft Graph

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All","Organization.Read.All" -UseDeviceCode
```

Follow the device code flow to authenticate with your admin account.

### Step 2: Preview Changes (Recommended)

```powershell
./setup-m365-lab.ps1 -WhatIf
```

This shows what would be created without making any changes.

### Step 3: Execute Setup

```powershell
./setup-m365-lab.ps1
```

This will:
1. Create 100 users across 8 departments
2. Set manager hierarchy
3. Assign E5 licenses to 25 key users
4. Create 19 groups
5. Assign users to appropriate groups

**Expected runtime:** 5-10 minutes (due to API throttling protection)

### Step 4: Verify Setup

```powershell
./verify-setup.ps1
```

## Files Reference

| File | Purpose |
|------|---------|
| `setup-m365-lab.ps1` | Main setup script |
| `users-data.json` | User definitions with names, roles, hierarchy |
| `verify-setup.ps1` | Validates the setup completed correctly |
| `check-prerequisites.ps1` | Checks modules and permissions |
| `cleanup-lab.ps1` | Removes created users/groups |

## Organizational Structure

### Departments
- Executive (5 users) - NYC only
- Engineering (30 users) - All locations
- Product (10 users) - All locations
- Design (10 users) - All locations
- Sales (15 users) - All locations
- Marketing (10 users) - All locations
- Support (10 users) - All locations
- HR (5 users) - NYC, London, Phoenix
- Finance (5 users) - NYC, London, Phoenix

### Locations
- **NYC (HQ):** 44 users
- **London:** 31 users
- **Phoenix:** 25 users

### Groups Created
- 8 Department groups (M365 Groups)
- 3 Location groups (Security Groups)
- 3 Management groups (Security Groups)
- 5 Project/functional groups (M365 Groups)

## License Assignment

25 users receive E5 licenses:
- All Executives (5)
- All VPs/Directors (8)
- All Managers (12)

## Cleanup

To remove all users and groups created by this script:

```powershell
# Preview what would be deleted
./cleanup-lab.ps1 -RemoveUsers -RemoveGroups -WhatIf

# Execute cleanup (will prompt for confirmation)
./cleanup-lab.ps1 -RemoveUsers -RemoveGroups

# Skip confirmation (use with caution)
./cleanup-lab.ps1 -RemoveUsers -RemoveGroups -Force
```

## Troubleshooting

### "Insufficient privileges" error
Make sure you're signed in as a Global Administrator or User Administrator.

### API throttling errors
The script includes built-in delays. If you still see throttling:
1. Wait 5 minutes and retry
2. Re-run the script (it will skip already-created users)

### Module not found
```powershell
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
```

### License assignment failures
Check available licenses:
```powershell
Get-MgSubscribedSku | Select-Object SkuPartNumber, ConsumedUnits, @{N='Available';E={$_.PrepaidUnits.Enabled - $_.ConsumedUnits}}
```

## Password

All users are created with the password: `DemoP@ss2024!`

Users will NOT be prompted to change password on first sign-in (for demo convenience).
