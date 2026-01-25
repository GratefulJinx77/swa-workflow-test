# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository creates a Microsoft 365 demo lab environment for assessment and migration testing. It deploys 100 users with pop-culture names, organizational hierarchy, groups, and intentional security/compliance issues that assessment tools can detect.

## Commands

### Full Deployment (Single Auth Session)
```bash
pwsh ./deploy-m365-lab.ps1 -TenantDomain "TENANT.onmicrosoft.com"
```

### Deployment Options
```powershell
# Preview only
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -WhatIf

# Skip assessment issues
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -SkipProblems

# Skip secure score degradation
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -SkipSecureScoreDegradation
```

### Cleanup
```powershell
./restore-secure-score.ps1 -TenantDomain "tenant.onmicrosoft.com"  # Restore security
./cleanup-problems.ps1 -TenantDomain "tenant.onmicrosoft.com"      # Remove problem accounts
./cleanup-lab.ps1 -RemoveUsers -RemoveGroups                        # Full removal
```

### Verification
```powershell
./verify-setup.ps1
./check-prerequisites.ps1
```

## Architecture

**Primary script:** `deploy-m365-lab.ps1` - Self-contained single-session deployment that includes all user data, group definitions, and problem creation logic inline. Does not depend on external JSON files.

**Legacy scripts:** `setup-m365-lab.ps1` + `users-data.json` - Original modular approach requiring separate data file. Still functional but requires multiple auth sessions.

**Problem injection scripts:**
- `introduce-problems.ps1` - Creates 36 assessment-findable issues (stale users, empty groups, over-privileged accounts)
- `introduce-migration-issues.ps1` - Creates 21 pre-migration issues (UPN mismatches, nested groups, legal holds)
- `degrade-secure-score.ps1` - Weakens security posture for demo purposes

## Microsoft Graph Scopes Required

All scripts use device code authentication (`Connect-MgGraph -UseDeviceCode`). Required scopes:
- User.ReadWrite.All
- Group.ReadWrite.All
- Directory.ReadWrite.All
- RoleManagement.ReadWrite.Directory
- Application.ReadWrite.All
- Policy.ReadWrite.ConditionalAccess
- Policy.ReadWrite.Authorization

## Key Constraints

- Device code auth times out after 120 seconds - complete login promptly
- Secure Score changes take 24-48 hours to reflect in Microsoft's portal
- M365 groups require unique mail nicknames
- Scripts handle existing resources gracefully (skip duplicates)
- Default password for all created users: `DemoP@ss2024!`
