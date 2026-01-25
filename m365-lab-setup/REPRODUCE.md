# M365 Demo Lab - Complete Reproduction Guide

## One-Command Deployment

```bash
pwsh ./deploy-m365-lab.ps1 -TenantDomain "YOUR-TENANT.onmicrosoft.com"
```

**Single authentication prompt** - complete device login within 120 seconds.

---

## What Gets Deployed

### 100 Users (Pop Culture Names)

| Department | NYC | London | Phoenix | Total |
|------------|-----|--------|---------|-------|
| Executive | 5 | - | - | 5 |
| Engineering | 12 | 10 | 8 | 30 |
| Product | 5 | 3 | 2 | 10 |
| Design | 4 | 3 | 3 | 10 |
| Sales | 6 | 5 | 4 | 15 |
| Marketing | 4 | 3 | 3 | 10 |
| Support | 3 | 4 | 3 | 10 |
| HR | 2 | 2 | 1 | 5 |
| Finance | 3 | 1 | 1 | 5 |

**Key Characters:**
- CEO: Jean-Luc Picard
- CTO: Tony Stark
- CFO: Scrooge McDuck
- COO: Miranda Priestly
- CMO: Don Draper
- Engineers: Neo Matrix, Trinity Code, Elliot Alderson, Ada Lovelace, Alan Turing
- Sales: Jordan Belfort, Saul Goodman, Harvey Specter, Han Solo
- Support: Michael Scott, Dwight Schrute, Leslie Knope, Ron Swanson

### 19+ Groups

**Department Groups (M365):** Engineering, Product, Design, Sales, Marketing, Support, HR, Finance
**Location Groups (Security):** NYC Office, London Office, Phoenix Office
**Management Groups:** Executive Team, All Managers, All Directors
**Project Groups:** Platform Team, Mobile Team, API Team, Enterprise Sales, SMB Sales

### 25 E5 Licenses

Assigned to: All Executives, VPs, Directors, Managers

### 57 Assessment-Findable Issues

**Identity Issues (12):**
- 3 stale/inactive users (180-365 days)
- 3 orphaned users (no manager)
- 2 external user gaps
- 4 PII handlers without proper controls

**Group Issues (8):**
- 3 empty groups
- 2 ownerless groups
- 3 nested group structures

**Security Issues (15):**
- 1 user with 5+ admin roles (Tony Stark)
- 3 problematic app registrations
- 4 apps with expiring credentials
- Security defaults disabled
- User app consent enabled
- Unprotected admin account
- No CA policies (legacy auth, admin MFA, risk policies)

**Compliance Issues (8):**
- 3 unlicensed users
- 2 shared mailbox indicators
- 2 legal hold scenarios
- 2 GDPR region users

**Migration Issues (14):**
- 2 UPN/email mismatches
- Deep nested group hierarchy
- Credential expiration gaps

### Degraded Secure Score

**Expected Score Drop: 81% → ~50-60%**

Changes made:
- Security defaults: DISABLED
- User app consent: ENABLED
- Unprotected admin: CREATED (Global Admin, no MFA)
- Legacy auth blocking: NONE
- Admin MFA requirement: NONE
- Sign-in risk policy: NONE
- User risk policy: NONE

---

## Prerequisites

1. **PowerShell 7+**
   ```bash
   # Install on Linux/WSL
   wget https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz
   mkdir -p ~/.local/powershell && tar -xzf powershell-7.4.6-linux-x64.tar.gz -C ~/.local/powershell
   export PATH="$HOME/.local/powershell:$PATH"
   ```

2. **Microsoft Graph PowerShell SDK**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser -Force
   ```

3. **Required Permissions**
   - User.ReadWrite.All
   - Group.ReadWrite.All
   - Directory.ReadWrite.All
   - RoleManagement.ReadWrite.Directory
   - Application.ReadWrite.All
   - Policy.ReadWrite.ConditionalAccess
   - Policy.ReadWrite.Authorization

4. **Tenant Requirements**
   - Microsoft 365 E5 Developer subscription (or equivalent)
   - At least 25 available licenses
   - Global Administrator access

---

## Command Options

```powershell
# Full deployment (default)
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com"

# Skip assessment problems
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -SkipProblems

# Skip secure score degradation
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -SkipSecureScoreDegradation

# Preview mode (no changes)
./deploy-m365-lab.ps1 -TenantDomain "tenant.onmicrosoft.com" -WhatIf
```

---

## Cleanup/Restore

### Restore Security Settings
```powershell
./restore-secure-score.ps1 -TenantDomain "tenant.onmicrosoft.com"
```

### Remove Problem Accounts
```powershell
./cleanup-problems.ps1 -TenantDomain "tenant.onmicrosoft.com"
```

### Full Lab Removal
```powershell
./cleanup-lab.ps1 -TenantDomain "tenant.onmicrosoft.com"
```

---

## Verification

After deployment, verify:

1. **User Count:** `Get-MgUser -All | Measure-Object` → ~127 users
2. **Group Count:** `Get-MgGroup -All | Measure-Object` → ~35 groups
3. **Org Chart:** Microsoft 365 Admin Center → Users → Active users → Select user → View org chart
4. **Secure Score:** security.microsoft.com → Secure Score (wait 24-48 hours for update)

---

## Assessment Tools That Will Find Issues

- **Microsoft Secure Score** - Security posture gaps
- **Microsoft Defender for Identity** - Risky users, stale accounts
- **Azure AD Identity Governance** - Orphaned users, role issues
- **Microsoft Purview** - Compliance gaps, PII handling
- **Third-party tools:** Quest, AvePoint, ShareGate migration assessments

---

## Claude Prompt to Reproduce

Copy this prompt to have Claude recreate the lab in a new tenant:

```
Deploy an M365 demo lab environment to [YOUR-TENANT.onmicrosoft.com] with:

1. 100 users with pop-culture fictional names (Star Trek, Marvel, The Office, etc.)
2. 8 departments: Executive, Engineering, Product, Design, Sales, Marketing, Support, HR, Finance
3. 3 office locations: NYC (HQ), London, Phoenix
4. Full management hierarchy: CEO → C-Suite → VPs → Managers → Individual Contributors
5. 19+ groups (department, location, management, project teams)
6. 25 E5 licenses assigned to executives and managers
7. 36 assessment-findable issues (stale users, empty groups, over-privileged accounts, app registration problems)
8. 21 pre-migration issues (UPN mismatches, nested groups, legal holds, GDPR users)
9. Degraded secure score (disable security defaults, enable user consent, create unprotected admin)

Use a single authentication session. All changes should be made via Microsoft Graph PowerShell.
```

---

## Files Included

| File | Purpose |
|------|---------|
| `deploy-m365-lab.ps1` | **Main deployment script** - single session, all features |
| `restore-secure-score.ps1` | Restore security settings |
| `cleanup-problems.ps1` | Remove problem accounts/groups |
| `cleanup-lab.ps1` | Full environment cleanup |
| `verify-setup.ps1` | Verify deployment |
| `users-data.json` | User data (standalone reference) |
| `REPRODUCE.md` | This documentation |

---

## Troubleshooting

**Auth timeout:** Complete device login within 120 seconds of seeing the code.

**User creation fails:** Check if UPN already exists. The script handles existing users gracefully.

**License assignment fails:** Verify E5 Developer licenses are available in tenant.

**Group creation fails:** M365 groups require unique mail nicknames - duplicates are skipped.

**Secure Score not changing:** Wait 24-48 hours for Microsoft to recalculate.
