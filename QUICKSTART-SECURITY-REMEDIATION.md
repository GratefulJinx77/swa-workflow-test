# Quick Start Guide: Azure Security Remediation for Jinks Labs

**Target Audience:** Brad Jinks (Brad@jinkslabs.com)
**Environment:** Jinks Labs Tenant (jinkslabs.com)
**Assessment Date:** 2026-01-22

---

## Executive Summary

Your Azure tenant has **3 critical** and **8 high-priority** security findings. This guide provides the fastest path to implement critical security controls.

**Time to secure:** 5-6 hours of focused work
**Cost impact:** ~$18/month recurring

---

## Step 1: Validate Current State (30 minutes)

Before implementing changes, collect current configuration data:

```bash
# Login to Azure
az login

# Run validation script
cd /home/wbj/swa-workflow-test
./azure-security-validation.sh <your-resource-group-name>

# Review summary
cat security-assessment-*/00-assessment-summary.txt
```

**What this does:** Collects current configuration across identity, network, data protection, and monitoring to validate assessment findings.

---

## Step 2: Create Emergency Access Accounts (30 minutes)

**WHY:** Prevents complete lockout if Conditional Access policies malfunction.

**RISK IF SKIPPED:** Complete tenant lockout requiring Microsoft support intervention.

### Instructions:

```bash
# Generate strong passwords (save these in a password manager!)
PASSWORD1=$(openssl rand -base64 32)
PASSWORD2=$(openssl rand -base64 32)

echo "Break-glass Account 1 Password: $PASSWORD1"
echo "Break-glass Account 2 Password: $PASSWORD2"

# Create first break-glass account
az ad user create \
  --display-name "Emergency Access Account 01" \
  --user-principal-name breakglass01@jinkslabs.com \
  --password "$PASSWORD1" \
  --force-change-password-next-sign-in false

# Create second break-glass account
az ad user create \
  --display-name "Emergency Access Account 02" \
  --user-principal-name breakglass02@jinkslabs.com \
  --password "$PASSWORD2" \
  --force-change-password-next-sign-in false

# Get Object IDs for role assignments
BG1_ID=$(az ad user show --id breakglass01@jinkslabs.com --query id -o tsv)
BG2_ID=$(az ad user show --id breakglass02@jinkslabs.com --query id -o tsv)

# Assign Global Administrator role (requires appropriate permissions)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body "{\"principalId\":\"$BG1_ID\",\"roleDefinitionId\":\"62e90394-69f5-4237-9190-012177145e10\",\"directoryScopeId\":\"/\"}"

az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body "{\"principalId\":\"$BG2_ID\",\"roleDefinitionId\":\"62e90394-69f5-4237-9190-012177145e10\",\"directoryScopeId\":\"/\"}"
```

### Post-Creation Steps:

1. **Store credentials securely:**
   - Save passwords in a physical safe or offline password manager
   - Document account names and storage location
   - Ensure backup admin can access credentials

2. **Test accounts:**
   - Open incognito browser window
   - Sign in with breakglass01@jinkslabs.com
   - Verify Global Administrator access in Entra ID
   - Sign out immediately

3. **Configure monitoring alert:**
   - You'll exclude these from Conditional Access in next step
   - Alert will be configured in Step 5 (Monitoring)

---

## Step 3: Enable Baseline Conditional Access (2 hours)

**WHY:** Enforces MFA for all users and blocks legacy authentication (bypasses MFA).

**RISK IF SKIPPED:** Compromised credentials can access tenant without MFA; legacy protocols bypass security.

### Policy 1: Require MFA for All Users

**Using Azure Portal (Recommended for first-time setup):**

1. Navigate to: **Entra ID > Security > Conditional Access > Policies**
2. Click **+ New policy**
3. Configure:
   - **Name:** CA-001: Require MFA for All Users
   - **Assignments > Users:**
     - Include: All users
     - Exclude:
       - breakglass01@jinkslabs.com
       - breakglass02@jinkslabs.com
   - **Cloud apps:** All cloud apps
   - **Grant:** Require multifactor authentication
   - **Enable policy:** Report-only

4. Click **Create**

**Using Azure CLI:**

```bash
# Get break-glass account Object IDs
BG1_ID=$(az ad user show --id breakglass01@jinkslabs.com --query id -o tsv)
BG2_ID=$(az ad user show --id breakglass02@jinkslabs.com --query id -o tsv)

# Create MFA policy (requires Microsoft Graph permissions)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --body "{
    \"displayName\": \"CA-001: Require MFA for All Users\",
    \"state\": \"enabledForReportingButNotEnforced\",
    \"conditions\": {
      \"applications\": {
        \"includeApplications\": [\"All\"]
      },
      \"users\": {
        \"includeUsers\": [\"All\"],
        \"excludeUsers\": [\"$BG1_ID\", \"$BG2_ID\"]
      }
    },
    \"grantControls\": {
      \"operator\": \"OR\",
      \"builtInControls\": [\"mfa\"]
    }
  }"
```

### Policy 2: Require MFA for Azure Management

**Portal Steps:**

1. **New policy**
2. Configure:
   - **Name:** CA-002: Require MFA for Azure Management
   - **Assignments > Users:** All users (exclude break-glass accounts)
   - **Cloud apps > Select apps:**
     - Microsoft Azure Management (797f4846-ba00-4fd7-ba43-dac1f8f63013)
   - **Grant:** Require multifactor authentication
   - **Enable policy:** Report-only

### Policy 3: Block Legacy Authentication

**Portal Steps:**

1. **New policy**
2. Configure:
   - **Name:** CA-003: Block Legacy Authentication
   - **Assignments > Users:** All users (exclude break-glass accounts)
   - **Cloud apps:** All cloud apps
   - **Conditions > Client apps:**
     - Configure: Yes
     - Select: Exchange ActiveSync clients, Other clients
   - **Grant:** Block access
   - **Enable policy:** Report-only

### Testing and Activation (CRITICAL):

1. **Monitor report-only mode for 48 hours:**
   ```bash
   # View sign-in logs to check CA policy impact
   az rest --method GET \
     --uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=conditionalAccessStatus eq 'success'" \
     --query "value[].{User:userPrincipalName, App:appDisplayName, CA:appliedConditionalAccessPolicies}" | head -20
   ```

2. **Check for any blocked sign-ins that shouldn't be blocked**
3. **After validation, switch policies to "On":**
   - Portal: Edit each policy > Enable policy: On
   - CLI: Update policy state to "enabled"

**WARNING:** Do NOT enable all policies immediately. Test in report-only mode first!

---

## Step 4: Enable Microsoft Defender for Cloud Plans (30 minutes)

**WHY:** Provides threat detection for storage, Key Vault, and management operations.

**RISK IF SKIPPED:** No detection for malware in storage, suspicious Key Vault access, or malicious ARM operations.

**COST:** ~$18/month

### Enable Defender Plans:

```bash
# Enable Defender for Storage
az security pricing create \
  --name StorageAccounts \
  --tier Standard

# Enable Defender for Key Vault
az security pricing create \
  --name KeyVaults \
  --tier Standard

# Enable Defender for Resource Manager (subscription-level protection)
az security pricing create \
  --name Arm \
  --tier Standard

# Enable Defender for DNS (tenant-level DNS protection)
az security pricing create \
  --name Dns \
  --tier Standard

# Verify enabled plans
az security pricing list --query "[].{Name:name, Tier:pricingTier}" -o table
```

### Validate Defender Alerts:

After 24 hours, check for security alerts:

```bash
# View recent security alerts
az security alert list --query "[].{Name:alertDisplayName, Severity:severity, Status:status}" -o table
```

---

## Step 5: Apply Resource Locks (15 minutes)

**WHY:** Prevents accidental deletion of critical infrastructure.

**RISK IF SKIPPED:** Compromised account or human error could delete Key Vault, storage, or logs.

### Apply Locks:

```bash
# Set variables (replace with your resource group name)
RESOURCE_GROUP="<your-resource-group>"
STORAGE_ACCOUNT="oldshrimproad001"
KEY_VAULT="jinkslabs-vault"
LOG_WORKSPACE="jinkslabs-logs"

# Lock Key Vault
az lock create \
  --name "PreventKVDeletion" \
  --lock-type CanNotDelete \
  --resource-group "$RESOURCE_GROUP" \
  --resource-name "$KEY_VAULT" \
  --resource-type Microsoft.KeyVault/vaults \
  --notes "Prevents accidental deletion of production Key Vault"

# Lock Storage Account
az lock create \
  --name "PreventStorageDeletion" \
  --lock-type CanNotDelete \
  --resource-group "$RESOURCE_GROUP" \
  --resource-name "$STORAGE_ACCOUNT" \
  --resource-type Microsoft.Storage/storageAccounts \
  --notes "Prevents accidental deletion of production storage"

# Lock Log Analytics Workspace
az lock create \
  --name "PreventLogsDeletion" \
  --lock-type CanNotDelete \
  --resource-group "$RESOURCE_GROUP" \
  --resource-name "$LOG_WORKSPACE" \
  --resource-type Microsoft.OperationalInsights/workspaces \
  --notes "Prevents accidental deletion of security logs"

# Verify locks
az lock list --resource-group "$RESOURCE_GROUP" -o table
```

**Note:** To delete a locked resource, you must first remove the lock. This is intentional.

---

## Step 6: Enable Storage Account Data Protection (20 minutes)

**WHY:** Protects against accidental deletion and enables recovery of deleted/overwritten data.

**RISK IF SKIPPED:** Permanent data loss from accidental deletion or ransomware.

### Enable Soft Delete and Versioning:

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

# Enable container soft delete
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --enable-container-delete-retention true \
  --container-delete-retention-days 14

# Verify configuration
az storage blob service-properties delete-policy show \
  --account-name "$STORAGE_ACCOUNT"
```

### Verify Protection:

```bash
# Test soft delete (optional - creates and deletes a test blob)
# Create test container
az storage container create \
  --name test-soft-delete \
  --account-name "$STORAGE_ACCOUNT"

# Upload test file
echo "Test data" > /tmp/test-file.txt
az storage blob upload \
  --account-name "$STORAGE_ACCOUNT" \
  --container-name test-soft-delete \
  --file /tmp/test-file.txt \
  --name test-file.txt

# Delete the blob
az storage blob delete \
  --account-name "$STORAGE_ACCOUNT" \
  --container-name test-soft-delete \
  --name test-file.txt

# List deleted blobs (should show test-file.txt)
az storage blob list \
  --account-name "$STORAGE_ACCOUNT" \
  --container-name test-soft-delete \
  --include d

# Restore the blob
az storage blob undelete \
  --account-name "$STORAGE_ACCOUNT" \
  --container-name test-soft-delete \
  --name test-file.txt

# Clean up test container
az storage container delete \
  --name test-soft-delete \
  --account-name "$STORAGE_ACCOUNT"
```

---

## Step 7: Configure Critical Security Alerts (1 hour)

**WHY:** Notifies you immediately when suspicious activity occurs.

**RISK IF SKIPPED:** Attackers can operate undetected; security incidents discovered days/weeks later.

### Create Action Group:

```bash
RESOURCE_GROUP="<your-resource-group>"

# Create Action Group for security alerts
az monitor action-group create \
  --name SecurityAlerts \
  --resource-group "$RESOURCE_GROUP" \
  --short-name SecAlert \
  --email-receiver SecurityTeam SecurityContact Brad@jinkslabs.com
```

### Configure Alert Rules:

**Alert 1: Break-Glass Account Usage**

```bash
ACTION_GROUP_ID=$(az monitor action-group show --name SecurityAlerts --resource-group "$RESOURCE_GROUP" --query id -o tsv)

az monitor activity-log alert create \
  --name "CRITICAL-BreakGlassAccountUsed" \
  --resource-group "$RESOURCE_GROUP" \
  --condition category=Administrative \
    and resourceId=/providers/Microsoft.AAD \
  --action-group "$ACTION_GROUP_ID" \
  --description "Alert when emergency access accounts authenticate"
```

**Alert 2: Resource Group or Critical Resource Deletion**

```bash
az monitor activity-log alert create \
  --name "CRITICAL-ResourceDeletion" \
  --resource-group "$RESOURCE_GROUP" \
  --condition category=Administrative \
    and operationName=Microsoft.Resources/subscriptions/resourceGroups/delete \
  --action-group "$ACTION_GROUP_ID" \
  --description "Alert when resource groups are deleted"
```

**Alert 3: Privileged Role Assignment**

```bash
az monitor activity-log alert create \
  --name "HIGH-PrivilegedRoleAssignment" \
  --resource-group "$RESOURCE_GROUP" \
  --condition category=Administrative \
    and operationName=Microsoft.Authorization/roleAssignments/write \
  --action-group "$ACTION_GROUP_ID" \
  --description "Alert when privileged roles are assigned"
```

### Verify Alerts:

```bash
# List all alert rules
az monitor activity-log alert list --resource-group "$RESOURCE_GROUP" -o table

# Test alert (optional - will send test email)
az monitor action-group test-notifications create \
  --action-group-name SecurityAlerts \
  --resource-group "$RESOURCE_GROUP" \
  --notification-type Email \
  --receiver-name SecurityContact
```

---

## Step 8: Restrict Network Access to Key Vault and Storage (30 minutes)

**WHY:** Limits attack surface by restricting access to known IP addresses.

**RISK IF SKIPPED:** Key Vault and Storage accessible from any internet IP address.

### Option A: Allow Only Your IP (Recommended)

```bash
STORAGE_ACCOUNT="oldshrimproad001"
KEY_VAULT="jinkslabs-vault"

# Get your current public IP
MY_IP=$(curl -s ifconfig.me)
echo "Your public IP: $MY_IP"

# Configure Storage Account firewall
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --default-action Deny

az storage account network-rule add \
  --account-name "$STORAGE_ACCOUNT" \
  --ip-address "$MY_IP"

# Allow Azure services (required for Azure integrations)
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --bypass AzureServices

# Configure Key Vault firewall
az keyvault update \
  --name "$KEY_VAULT" \
  --default-action Deny

az keyvault network-rule add \
  --name "$KEY_VAULT" \
  --ip-address "$MY_IP"
```

### Option B: Allow Specific IP Ranges (For Organizations)

```bash
# Add multiple IPs or CIDR ranges
az storage account network-rule add \
  --account-name "$STORAGE_ACCOUNT" \
  --ip-address "203.0.113.0/24"  # Replace with your organization's IP range

az keyvault network-rule add \
  --name "$KEY_VAULT" \
  --ip-address "203.0.113.0/24"
```

### Verify Network Configuration:

```bash
# Check Storage Account network rules
az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --query "networkRuleSet"

# Check Key Vault network rules
az keyvault show \
  --name "$KEY_VAULT" \
  --query "networkAcls"
```

**IMPORTANT:** After configuring firewall rules, test access:
- Try accessing Key Vault secrets via CLI
- Try uploading/downloading from Storage Account
- If access fails, your IP may have changed or need to be added

---

## Verification Checklist

After completing all steps, verify your security posture:

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

**Expected Results:**
- 3 Conditional Access policies in report-only or enabled state
- 4 Defender plans showing "Standard" tier
- 3 resource locks (Key Vault, Storage, Log Analytics)
- Blob soft delete enabled with 14-day retention
- 3-5 activity log alert rules configured

---

## Next Steps: Phase 2 Implementation (Week 2-4)

After completing this quick start, proceed to Phase 2:

1. **Enable Entra ID P2 and Privileged Identity Management (PIM)**
   - Cost: ~$9/user/month
   - Time: 4-6 hours
   - Benefit: Just-in-time privileged access, approval workflows

2. **Deploy Microsoft Sentinel for SIEM**
   - Cost: ~$12-25/month
   - Time: 6-8 hours
   - Benefit: Security event correlation, threat hunting, automated response

3. **Enable Comprehensive Diagnostic Logging**
   - Cost: Included in Log Analytics
   - Time: 2-3 hours
   - Benefit: Full audit trail for all Azure operations

**Full implementation guide:** See `/home/wbj/swa-workflow-test/azure-security-assessment.md`

---

## Troubleshooting

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

### "Cannot enable Defender plan due to quota"

**Solution:** Azure subscriptions have default quotas. Request increase:
- Navigate to: Azure Portal > Subscriptions > Usage + quotas
- Request increase for "Security Center" quota

### "Network rule blocks access to Storage/Key Vault"

**Solution:** Add your current IP or temporarily allow all IPs:

```bash
# Allow all IPs temporarily
az storage account update --name oldshrimproad001 --default-action Allow
az keyvault update --name jinkslabs-vault --default-action Allow

# After fixing, revert to deny
az storage account update --name oldshrimproad001 --default-action Deny
az keyvault update --name jinkslabs-vault --default-action Deny
```

### "Action Group test notification not received"

**Solution:**
1. Check spam/junk folder
2. Verify email address: `az monitor action-group show --name SecurityAlerts --resource-group <rg>`
3. Update if incorrect: `az monitor action-group update --name SecurityAlerts --resource-group <rg> --add-action email SecurityContact Brad@jinkslabs.com`

---

## Cost Summary After Quick Start

| Service | Monthly Cost | Purpose |
|---------|--------------|---------|
| Defender for Storage | ~$10 | Malware scanning, threat detection |
| Defender for Key Vault | ~$0.50 | Suspicious access detection |
| Defender for Resource Manager | ~$5 | Management operation threat detection |
| Defender for DNS | ~$2.50 | DNS-level threat detection |
| **Total New Cost** | **~$18/month** | **Critical threat detection** |

Existing costs (Log Analytics, Storage, Key Vault) remain unchanged.

---

## Support and Resources

- **Full Security Assessment Report:** `/home/wbj/swa-workflow-test/azure-security-assessment.md`
- **Validation Script:** `/home/wbj/swa-workflow-test/azure-security-validation.sh`
- **Microsoft Documentation:**
  - [Conditional Access Overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
  - [Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
  - [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)

**Questions or Issues?** Review the full assessment report for detailed remediation guidance and architectural considerations.

---

**Last Updated:** 2026-01-22
**Assessment Version:** 1.0
