# Azure Security Assessment - Structured Web Content
**Jinks Labs Tenant | Assessment Date: 2026-01-22**

---

## Executive Summary

### Overview
This assessment evaluates the security posture of the Jinks Labs Azure tenant across seven critical domains. The environment consists of 5 Static Web Apps, 1 Storage Account, 1 Lab Plan, 1 Key Vault, and 1 Log Analytics workspace.

### Risk Rating
**MODERATE-HIGH**

### Environment Details
- **Tenant:** jinkslabs.com (5a62aa80-bceb-44d3-9879-b4a48deb66de)
- **Subscription:** Primary PAYG (86010fa7-268b-4d8e-95a6-6e0fab75c06c)
- **User Context:** Brad@jinkslabs.com (Owner + Security Admin)

---

## Key Metrics Dashboard

### Findings by Severity
| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 8 |
| Medium | 12 |
| Informational | 5 |

### Environment Inventory
- **Static Web Apps:** 5
- **Storage Accounts:** 1
- **Lab Plans:** 1
- **Key Vaults:** 1
- **Log Analytics Workspaces:** 1

### Secure Score
- **Current:** TBD
- **Target:** 80%+

---

## Cost Impact Summary

### Current Baseline
**$50-100/month**
- Key Vault (minimal usage)
- Storage Account (variable)
- Static Web Apps (Free or $9/app)
- Log Analytics (~$2.76/GB)
- Security Center Default (Free)

### Implementation Cost by Phase

| Phase | Description | Monthly Increase | Cumulative Monthly |
|-------|-------------|------------------|-------------------|
| **Phase 1** | Immediate Actions | +$18 | $68-118 |
| **Phase 2** | High Priority | +$21-34 | $89-152 |
| **Phase 3** | Medium Priority | +$0 | $89-152 |
| **Phase 4** | Optimization (no Front Door) | +$20 | $109-172 |
| **Phase 4** | Optimization (with Front Door) | +$350 | $439-502 |

### Recommended Path
**Implement Phases 1-3 immediately (~$89-152/month, ~80% increase)**
Defer Front Door/WAF decision until Static Web Apps reach production scale.

---

## Critical Findings

### C-IAM-01: No Conditional Access Policies Detected
- **Category:** Identity and Access Management
- **Risk Level:** CRITICAL
- **CVSS Score:** 8.1
- **Time to Remediate:** 4 hours
- **Cost Impact:** Included in existing licenses

**Impact:**
- No location-based access restrictions
- No device compliance requirements
- No application-specific controls
- Lack of defense-in-depth for privileged accounts

**Remediation Summary:**
Implement baseline Conditional Access policies including MFA for all users, MFA for Azure management, block legacy authentication, require compliant devices for privileged roles.

---

### C-IAM-02: No Break-Glass Account Configuration
- **Category:** Identity and Access Management
- **Risk Level:** CRITICAL
- **CVSS Score:** 7.5
- **Time to Remediate:** 1 hour
- **Cost Impact:** No cost

**Impact:**
- Risk of complete tenant lockout during CA policy errors
- No recovery mechanism if MFA services fail
- Extended downtime during authentication service disruptions

**Remediation Summary:**
Create 2 emergency access accounts with long randomly generated passwords, assign Global Administrator role, exclude from all Conditional Access policies.

---

### C-IAM-03: Privileged Identity Management Not Configured
- **Category:** Identity and Access Management
- **Risk Level:** CRITICAL
- **CVSS Score:** 8.2
- **Time to Remediate:** 4-6 hours
- **Cost Impact:** $9/user/month (Entra ID P2)

**Impact:**
- Permanent privileged access increases attack surface
- No time-bounded access to sensitive operations
- Lack of approval workflows for sensitive role activations
- Violates least privilege principle

**Remediation Summary:**
Enable Entra ID P2 licensing, configure PIM for Azure Resources and Entra ID roles, convert Owner and Security Admin roles to eligible assignments.

---

### C-MON-01: Microsoft Defender for Cloud Not Fully Enabled
- **Category:** Threat Detection and Monitoring
- **Risk Level:** CRITICAL
- **CVSS Score:** 8.5
- **Time to Remediate:** 30 minutes
- **Cost Impact:** $18/month

**Impact:**
- No vulnerability assessment
- Limited threat detection for PaaS services
- No malware scanning for Storage
- No suspicious access detection for Key Vault

**Remediation Summary:**
Enable Defender for Storage, Key Vault, Resource Manager, and DNS at Standard tier.

---

### C-MON-02: Microsoft Sentinel (SIEM) Not Deployed
- **Category:** Threat Detection and Monitoring
- **Risk Level:** CRITICAL
- **CVSS Score:** 8.3
- **Time to Remediate:** 6-8 hours
- **Cost Impact:** $12-25/month

**Impact:**
- No centralized security event correlation
- No automated incident creation
- No threat hunting capabilities
- Manual investigation required
- Limited detection of multi-stage attacks

**Remediation Summary:**
Deploy Microsoft Sentinel, configure data connectors (Activity Log, Entra ID, Defender for Cloud), enable priority analytics rules.

---

## Remediation Roadmap

### Phase 1: Immediate Actions (Week 1-2)
**Goal:** Reduce critical risk exposure
**Effort:** 8-10 hours | **Cost:** +$18/month

#### Priority 1.1: Identity Protection Foundation
- Create break-glass accounts (1 hour)
- Enable baseline Conditional Access policies (4 hours)
  - Start in report-only mode
  - Transition to enforced after 48-hour validation

#### Priority 1.2: Threat Detection Baseline
- Enable Defender for Cloud enhanced plans (30 minutes)
  - Storage, Key Vault, Resource Manager, DNS
- Configure critical alert rules (2 hours)
  - Key Vault access, mass deletion, failed MFA

#### Priority 1.3: Data Protection
- Enable blob soft delete and versioning (30 minutes)
- Implement resource locks (30 minutes)

---

### Phase 2: High Priority (Week 3-4)
**Goal:** Implement defense-in-depth and comprehensive monitoring
**Effort:** 25-30 hours | **Cost:** +$21-34/month

#### Priority 2.1: Privileged Access Management
- Enable Entra ID P2 licensing (1 hour)
- Configure PIM for Owner and Security Admin roles (4 hours)
- Implement quarterly access reviews (2 hours)

#### Priority 2.2: Network Security Hardening
- Configure Storage Account firewall (2 hours)
- Configure Key Vault network restrictions (1 hour)
- Review Static Web Apps access restrictions (2 hours per app)

#### Priority 2.3: Comprehensive Logging and SIEM
- Deploy Microsoft Sentinel (4 hours)
- Configure data connectors (2 hours)
- Enable priority analytics rules (4 hours)
- Enable diagnostic settings for all resources (2 hours)

---

### Phase 3: Medium Priority (Month 2)
**Goal:** Establish governance and compliance framework
**Effort:** 27 hours | **Cost:** +$0

#### Priority 3.1: Policy Governance
- Implement Azure Policy framework (8 hours)
- Configure deny policies for high-risk operations (4 hours)
- Establish policy compliance monitoring (2 hours)

#### Priority 3.2: Compliance Posture
- Enable regulatory compliance assessments (2 hours)
- Implement resource tagging strategy (4 hours)
- Configure cost anomaly detection (1 hour)

#### Priority 3.3: Identity Hardening
- Block legacy authentication protocols (2 hours)
- Configure password protection policies (1 hour)
- Implement sign-in and user risk policies (3 hours)

---

### Phase 4: Optimization (Month 3+)
**Goal:** Advanced security and operational excellence
**Effort:** 50 hours | **Cost:** +$20-355/month (variable)

#### Priority 4.1: Advanced Threat Detection
- Enable UEBA in Sentinel (2 hours)
- Configure custom threat hunting queries (8 hours)
- Develop SOAR playbooks for automated response (16 hours)

#### Priority 4.2: Network Defense in Depth
- Evaluate Azure Front Door + WAF ($330/month, optional)
- Implement Private Link for Key Vault and Storage ($15/month)

#### Priority 4.3: Advanced Data Protection
- Evaluate customer-managed encryption keys (optional)
- Implement data lifecycle management policies (2 hours)
- Configure immutable storage for compliance (optional)

---

## Quick Start Guide (5-6 Hours)

### What You'll Accomplish
- Create emergency access accounts
- Enable MFA enforcement
- Activate threat detection
- Protect against data loss
- Set up security alerts
- Restrict network access

### Total Cost Impact
**$18/month recurring**

### Step-by-Step Implementation

#### Step 1: Create Break-Glass Accounts (30 minutes)
**Why:** Prevents complete lockout if Conditional Access policies malfunction

```bash
# Generate strong passwords
PASSWORD1=$(openssl rand -base64 32)
PASSWORD2=$(openssl rand -base64 32)

# Create accounts
az ad user create \
  --display-name "Emergency Access Account 01" \
  --user-principal-name breakglass01@jinkslabs.com \
  --password "$PASSWORD1" \
  --force-change-password-next-sign-in false
```

**Critical:** Store passwords in physical safe or offline password manager

---

#### Step 2: Enable Conditional Access (2 hours)
**Why:** Enforces MFA for all users and blocks legacy authentication

**Portal Steps:**
1. Navigate to: Entra ID > Security > Conditional Access
2. Create policies:
   - CA-001: Require MFA for All Users
   - CA-002: Require MFA for Azure Management
   - CA-003: Block Legacy Authentication
3. Exclude break-glass accounts from all policies
4. Set to "Report-only" mode initially
5. Monitor for 48 hours
6. Switch to "Enabled"

---

#### Step 3: Enable Defender Plans (30 minutes)
**Why:** Provides threat detection for storage, Key Vault, and management operations
**Cost:** $18/month

```bash
# Enable all critical Defender plans
az security pricing create --name StorageAccounts --tier Standard
az security pricing create --name KeyVaults --tier Standard
az security pricing create --name Arm --tier Standard
az security pricing create --name Dns --tier Standard
```

---

#### Step 4: Apply Resource Locks (15 minutes)
**Why:** Prevents accidental deletion of critical infrastructure

```bash
RESOURCE_GROUP="<your-resource-group>"

# Lock Key Vault
az lock create \
  --name "PreventKVDeletion" \
  --lock-type CanNotDelete \
  --resource-group "$RESOURCE_GROUP" \
  --resource-name jinkslabs-vault \
  --resource-type Microsoft.KeyVault/vaults

# Lock Storage Account
az lock create \
  --name "PreventStorageDeletion" \
  --lock-type CanNotDelete \
  --resource-group "$RESOURCE_GROUP" \
  --resource-name oldshrimproad001 \
  --resource-type Microsoft.Storage/storageAccounts
```

---

#### Step 5: Enable Storage Protection (20 minutes)
**Why:** Protects against accidental deletion and enables recovery

```bash
STORAGE_ACCOUNT="oldshrimproad001"

# Enable blob soft delete (14-day retention)
az storage blob service-properties delete-policy update \
  --account-name "$STORAGE_ACCOUNT" \
  --enable true \
  --days-retained 14

# Enable blob versioning
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --enable-versioning true
```

---

#### Step 6: Configure Security Alerts (1 hour)
**Why:** Notifies you immediately when suspicious activity occurs

```bash
# Create Action Group
az monitor action-group create \
  --name SecurityAlerts \
  --resource-group <rg> \
  --short-name SecAlert \
  --email-receiver SecurityTeam SecurityContact Brad@jinkslabs.com

# Create critical alerts
az monitor activity-log alert create \
  --name "CRITICAL-BreakGlassAccountUsed" \
  --resource-group <rg> \
  --condition category=Administrative \
  --action-group <action-group-id>
```

---

#### Step 7: Restrict Network Access (30 minutes)
**Why:** Limits attack surface by restricting access to known IPs

```bash
# Get your current IP
MY_IP=$(curl -s ifconfig.me)

# Configure Storage Account firewall
az storage account update --name oldshrimproad001 --default-action Deny
az storage account network-rule add --account-name oldshrimproad001 --ip-address "$MY_IP"

# Configure Key Vault firewall
az keyvault update --name jinkslabs-vault --default-action Deny
az keyvault network-rule add --name jinkslabs-vault --ip-address "$MY_IP"
```

---

## Implementation Checklist

### Phase 1: Immediate Actions

#### Identity Protection Foundation
- [ ] Generate and securely store break-glass account passwords
- [ ] Create breakglass01@jinkslabs.com account
- [ ] Create breakglass02@jinkslabs.com account
- [ ] Assign Global Administrator role to both accounts
- [ ] Test authentication with break-glass accounts
- [ ] Store credentials in physical safe / offline password manager
- [ ] Create CA-001: Require MFA for All Users (report-only)
- [ ] Create CA-002: Require MFA for Azure Management (report-only)
- [ ] Create CA-003: Block Legacy Authentication (report-only)
- [ ] Exclude break-glass accounts from all CA policies
- [ ] Monitor CA policies in report-only mode for 48 hours
- [ ] Switch CA policies from report-only to enabled

#### Threat Detection Baseline
- [ ] Enable Defender for Storage (Standard tier)
- [ ] Enable Defender for Key Vault (Standard tier)
- [ ] Enable Defender for Resource Manager (Standard tier)
- [ ] Enable Defender for DNS (Standard tier)
- [ ] Verify all Defender plans are active
- [ ] Create Action Group: SecurityAlerts
- [ ] Configure alert: Break-Glass Account Usage
- [ ] Configure alert: Resource Deletion
- [ ] Configure alert: Privileged Role Assignment
- [ ] Test Action Group email delivery

#### Data Protection
- [ ] Enable blob soft delete (14-day retention)
- [ ] Enable blob versioning
- [ ] Enable container soft delete (14-day retention)
- [ ] Test blob soft delete recovery
- [ ] Apply CanNotDelete lock to Key Vault
- [ ] Apply CanNotDelete lock to Storage Account
- [ ] Apply CanNotDelete lock to Log Analytics workspace
- [ ] Verify all resource locks are active

#### Network Security (Optional)
- [ ] Document current public IP address
- [ ] Configure Storage Account firewall (default: Deny)
- [ ] Add authorized IP to Storage Account
- [ ] Enable Azure Services bypass for Storage Account
- [ ] Test Storage Account access after firewall config
- [ ] Configure Key Vault firewall (default: Deny)
- [ ] Add authorized IP to Key Vault
- [ ] Test Key Vault access after firewall config

---

## Command Reference Quick Guide

### Assessment and Validation
```bash
# Check Secure Score
az security secure-score-controls list --output table

# Get high-severity recommendations
az security assessment list \
  --query "[?status.code=='Unhealthy' && metadata.severity=='High']" -o table
```

### Identity and Access Management
```bash
# List Conditional Access policies
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{Name:displayName, State:state}" -o table

# List privileged role assignments
az role assignment list \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o table
```

### Defender for Cloud
```bash
# Check Defender plans status
az security pricing list --output table

# List security alerts
az security alert list \
  --query "[].{Name:alertDisplayName, Severity:severity, Status:status}" -o table
```

### Network Security
```bash
# Get your current public IP
curl -s ifconfig.me

# Configure Storage Account firewall
az storage account update --name oldshrimproad001 --default-action Deny
az storage account network-rule add --account-name oldshrimproad001 --ip-address "YOUR_IP/32"

# Configure Key Vault firewall
az keyvault update --name jinkslabs-vault --default-action Deny
az keyvault network-rule add --name jinkslabs-vault --ip-address "YOUR_IP/32"
```

### Data Protection
```bash
# Enable blob soft delete
az storage blob service-properties delete-policy update \
  --account-name oldshrimproad001 --enable true --days-retained 14

# Enable blob versioning
az storage account blob-service-properties update \
  --account-name oldshrimproad001 --enable-versioning true

# Check soft delete status
az storage blob service-properties delete-policy show \
  --account-name oldshrimproad001
```

### Resource Locks
```bash
# Apply lock to Key Vault
az lock create --name "PreventKVDeletion" --lock-type CanNotDelete \
  --resource-group <rg> --resource-name jinkslabs-vault \
  --resource-type Microsoft.KeyVault/vaults

# List all locks
az lock list --output table
```

### Monitoring and Alerts
```bash
# Create Action Group
az monitor action-group create --name SecurityAlerts --resource-group <rg> \
  --short-name SecAlert \
  --email-receiver SecurityTeam SecurityContact Brad@jinkslabs.com

# List all alert rules
az monitor activity-log alert list --output table
```

---

## Verification Checklist

After completing Phase 1, verify:

```bash
# Check Conditional Access policies
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{Name:displayName, State:state}" -o table

# Check Defender plans
az security pricing list --query "[?pricingTier=='Standard'].name" -o table

# Check resource locks
az lock list --query "[].{Name:name, Type:type, Resource:resourceId}" -o table

# Check storage protection
az storage blob service-properties delete-policy show \
  --account-name oldshrimproad001 \
  --query "{Enabled:deleteRetentionPolicy.enabled, Days:deleteRetentionPolicy.days}"

# Check alert rules
az monitor activity-log alert list --query "[].name" -o table
```

### Expected Results
- ✓ 3 Conditional Access policies in report-only or enabled state
- ✓ 4 Defender plans showing "Standard" tier
- ✓ 3 resource locks (Key Vault, Storage, Log Analytics)
- ✓ Blob soft delete enabled with 14-day retention
- ✓ 3-5 activity log alert rules configured

---

## Key Strengths (Preserve These)

1. **Key Vault Configuration** - Soft delete and purge protection already enabled
2. **Security Contact** - Brad@jinkslabs.com configured for high-severity alerts
3. **MFA Enabled** - Administrative account has MFA configured
4. **Storage Security** - HTTPS-only and TLS 1.2 enforced
5. **Centralized Logging** - Log Analytics workspace deployed
6. **Security Policies** - Basic Security Center policies active in audit mode

---

## Next Steps After Quick Start

### Week 3-4: Phase 2 Implementation
1. **Enable Entra ID P2 and Privileged Identity Management (PIM)**
   - Cost: ~$9/user/month
   - Time: 4-6 hours
   - Benefit: Just-in-time privileged access

2. **Deploy Microsoft Sentinel for SIEM**
   - Cost: ~$12-25/month
   - Time: 6-8 hours
   - Benefit: Security event correlation, threat hunting

3. **Enable Comprehensive Diagnostic Logging**
   - Cost: Included in Log Analytics
   - Time: 2-3 hours
   - Benefit: Full audit trail

---

## Troubleshooting Common Issues

### "Insufficient privileges" when creating Conditional Access policies
**Solution:** Ensure you have one of these roles:
- Global Administrator
- Security Administrator
- Conditional Access Administrator

```bash
# Check your current roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/me/memberOf" \
  --query "value[?contains(@odata.type, 'role')].displayName"
```

### Network rule blocks access to Storage/Key Vault
**Solution:** Add your current IP or temporarily allow all IPs:

```bash
# Allow all IPs temporarily
az storage account update --name oldshrimproad001 --default-action Allow
az keyvault update --name jinkslabs-vault --default-action Allow

# After fixing, revert to deny
az storage account update --name oldshrimproad001 --default-action Deny
az keyvault update --name jinkslabs-vault --default-action Deny
```

### Action Group test notification not received
**Solution:**
1. Check spam/junk folder
2. Verify email address configuration
3. Update if incorrect:

```bash
az monitor action-group update --name SecurityAlerts --resource-group <rg> \
  --add-action email SecurityContact Brad@jinkslabs.com
```

---

## Resources and Documentation

### Source Files
- **azure-security-assessment.md** (81KB) - Complete security assessment
- **QUICKSTART-SECURITY-REMEDIATION.md** - Fast-track guide
- **remediation-tracker.md** - Implementation checklist
- **COMMAND-REFERENCE.md** - CLI command reference

### Microsoft Documentation
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Conditional Access Overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)

---

**Last Updated:** 2026-01-22 | **Version:** 1.0 | **Next Review:** 2026-04-22
