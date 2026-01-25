# Azure Security Assessment - Command Reference Card

**Quick reference for common Azure CLI commands used in security assessment and remediation**

---

## ASSESSMENT AND VALIDATION

### Run Complete Assessment
```bash
# Run validation script (collects all configuration data)
./azure-security-validation.sh <resource-group-name>

# View summary
cat security-assessment-*/00-assessment-summary.txt

# Review checklist
cat security-assessment-*/00-validation-checklist.md
```

### Check Secure Score
```bash
# Get current Secure Score
az security secure-score-controls list --output table

# Get high-severity recommendations
az security assessment list \
  --query "[?status.code=='Unhealthy' && metadata.severity=='High']" -o table
```

---

## IDENTITY AND ACCESS MANAGEMENT

### Conditional Access Policies
```bash
# List all CA policies
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{Name:displayName, State:state}" -o table

# Check if Security Defaults enabled
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
```

### User and Role Management
```bash
# List all users
az ad user list --query "[].{UPN:userPrincipalName, Type:userType}" -o table

# List guest users
az ad user list --filter "userType eq 'Guest'" -o table

# List privileged role assignments
az role assignment list \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o table

# List service principals
az ad sp list --all --query "[].{AppId:appId, DisplayName:displayName}" -o table
```

### Create Break-Glass Account
```bash
# Generate strong password
PASSWORD=$(openssl rand -base64 32)
echo "Password: $PASSWORD"

# Create account
az ad user create \
  --display-name "Emergency Access Account 01" \
  --user-principal-name breakglass01@jinkslabs.com \
  --password "$PASSWORD" \
  --force-change-password-next-sign-in false

# Get Object ID
az ad user show --id breakglass01@jinkslabs.com --query id -o tsv
```

---

## DEFENDER FOR CLOUD

### Check Defender Plans
```bash
# List all Defender plans and their status
az security pricing list --output table

# Get plans that are enabled (Standard tier)
az security pricing list --query "[?pricingTier=='Standard'].name" -o table
```

### Enable Defender Plans
```bash
# Enable Defender for Storage
az security pricing create --name StorageAccounts --tier Standard

# Enable Defender for Key Vault
az security pricing create --name KeyVaults --tier Standard

# Enable Defender for Resource Manager
az security pricing create --name Arm --tier Standard

# Enable Defender for DNS
az security pricing create --name Dns --tier Standard
```

### Security Alerts
```bash
# List recent security alerts
az security alert list \
  --query "[].{Name:alertDisplayName, Severity:severity, Status:status}" -o table

# Get critical alerts
az security alert list \
  --query "[?severity=='High' || severity=='Critical']" -o table
```

---

## MICROSOFT SENTINEL

### Check Sentinel Status
```bash
# List Sentinel workspaces
az sentinel workspace list --output table

# List data connectors
az sentinel data-connector list \
  --resource-group <rg> \
  --workspace-name jinkslabs-logs
```

### Analytics Rules
```bash
# List analytics rules
az sentinel alert-rule list \
  --resource-group <rg> \
  --workspace-name jinkslabs-logs -o table
```

---

## NETWORK SECURITY

### Storage Account Network Configuration
```bash
STORAGE_ACCOUNT="oldshrimproad001"

# View network rules
az storage account show \
  --name $STORAGE_ACCOUNT \
  --query "{Name:name, DefaultAction:networkRuleSet.defaultAction, IPRules:networkRuleSet.ipRules}" -o json

# Set default action to Deny
az storage account update --name $STORAGE_ACCOUNT --default-action Deny

# Add IP address
az storage account network-rule add \
  --account-name $STORAGE_ACCOUNT \
  --ip-address "YOUR_IP/32"

# Remove IP address
az storage account network-rule remove \
  --account-name $STORAGE_ACCOUNT \
  --ip-address "YOUR_IP/32"
```

### Key Vault Network Configuration
```bash
KEY_VAULT="jinkslabs-vault"

# View network ACLs
az keyvault show \
  --name $KEY_VAULT \
  --query "{Name:name, DefaultAction:networkAcls.defaultAction, IPRules:networkAcls.ipRules}" -o json

# Set default action to Deny
az keyvault update --name $KEY_VAULT --default-action Deny

# Add IP address
az keyvault network-rule add --name $KEY_VAULT --ip-address "YOUR_IP/32"

# Remove IP address
az keyvault network-rule remove --name $KEY_VAULT --ip-address "YOUR_IP/32"
```

### Get Current Public IP
```bash
# Get your current public IP
curl -s ifconfig.me
```

---

## DATA PROTECTION

### Storage Account Protection
```bash
STORAGE_ACCOUNT="oldshrimproad001"

# Check soft delete status
az storage blob service-properties delete-policy show \
  --account-name $STORAGE_ACCOUNT

# Enable blob soft delete
az storage blob service-properties delete-policy update \
  --account-name $STORAGE_ACCOUNT \
  --enable true \
  --days-retained 14

# Enable blob versioning
az storage account blob-service-properties update \
  --account-name $STORAGE_ACCOUNT \
  --enable-versioning true

# Check versioning status
az storage account blob-service-properties show \
  --account-name $STORAGE_ACCOUNT \
  --query "isVersioningEnabled"

# Check encryption configuration
az storage account show \
  --name $STORAGE_ACCOUNT \
  --query "{EncryptionKeySource:encryption.keySource, KeyVault:encryption.keyVaultProperties}"
```

### Key Vault Protection
```bash
KEY_VAULT="jinkslabs-vault"

# Check soft delete and purge protection
az keyvault show \
  --name $KEY_VAULT \
  --query "{SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection}"

# List secrets (names only)
az keyvault secret list --vault-name $KEY_VAULT -o table

# List keys
az keyvault key list --vault-name $KEY_VAULT -o table
```

---

## RESOURCE LOCKS

### View Locks
```bash
# List all locks in subscription
az lock list --output table

# List locks for specific resource group
az lock list --resource-group <rg> -o table

# List locks for specific resource
az lock list \
  --resource-group <rg> \
  --resource-name jinkslabs-vault \
  --resource-type Microsoft.KeyVault/vaults
```

### Create Locks
```bash
RESOURCE_GROUP="<your-resource-group>"

# Lock Key Vault
az lock create \
  --name "PreventKVDeletion" \
  --lock-type CanNotDelete \
  --resource-group $RESOURCE_GROUP \
  --resource-name jinkslabs-vault \
  --resource-type Microsoft.KeyVault/vaults

# Lock Storage Account
az lock create \
  --name "PreventStorageDeletion" \
  --lock-type CanNotDelete \
  --resource-group $RESOURCE_GROUP \
  --resource-name oldshrimproad001 \
  --resource-type Microsoft.Storage/storageAccounts

# Lock Log Analytics
az lock create \
  --name "PreventLogsDeletion" \
  --lock-type CanNotDelete \
  --resource-group $RESOURCE_GROUP \
  --resource-name jinkslabs-logs \
  --resource-type Microsoft.OperationalInsights/workspaces
```

### Delete Locks
```bash
# Delete lock by name
az lock delete --name "PreventKVDeletion" --resource-group <rg>

# Delete lock by ID
az lock delete --ids <lock-resource-id>
```

---

## MONITORING AND LOGGING

### Diagnostic Settings
```bash
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --name jinkslabs-logs \
  --resource-group <rg> \
  --query id -o tsv)

# View diagnostic settings for Storage Account
az monitor diagnostic-settings list \
  --resource $(az storage account show --name oldshrimproad001 --resource-group <rg> --query id -o tsv)

# View diagnostic settings for Key Vault
az monitor diagnostic-settings list \
  --resource $(az keyvault show --name jinkslabs-vault --query id -o tsv)

# Check subscription activity log settings
az monitor diagnostic-settings subscription list
```

### Alert Rules
```bash
# List all activity log alerts
az monitor activity-log alert list --output table

# List metric alerts
az monitor metrics alert list --output table

# List action groups
az monitor action-group list -o table
```

### Create Action Group
```bash
# Create email action group
az monitor action-group create \
  --name SecurityAlerts \
  --resource-group <rg> \
  --short-name SecAlert \
  --email-receiver SecurityTeam SecurityContact Brad@jinkslabs.com
```

---

## AZURE POLICY

### View Policies
```bash
# List policy assignments
az policy assignment list --output table

# Check policy compliance
az policy state summarize

# List non-compliant resources
az policy state list \
  --filter "ComplianceState eq 'NonCompliant'" \
  --query "[].{Resource:resourceId, Policy:policyDefinitionName}" -o table
```

### Assign Built-in Policies
```bash
# Assign Azure Security Benchmark
az policy assignment create \
  --name "ASB-Enforce" \
  --display-name "Azure Security Benchmark - Enforce" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
```

---

## COMPLIANCE

### Regulatory Compliance
```bash
# List compliance standards
az security regulatory-compliance-standards list -o table

# View Azure Security Benchmark compliance
az security regulatory-compliance-assessments list \
  --standard-name "Azure-Security-Benchmark" -o table
```

---

## RESOURCE INVENTORY

### List Resources
```bash
# List all resources
az resource list -o table

# List resources with tags
az resource list \
  --query "[].{Name:name, Type:type, Tags:tags, Location:location}" -o json

# List resources without tags
az resource list \
  --query "[?tags==null].{Name:name, Type:type}" -o table
```

### Tag Resources
```bash
# Tag Static Web App
az staticwebapp update \
  --name old-shrimp-road-webapp \
  --tags Environment=Production Owner=Brad@jinkslabs.com

# Tag Storage Account
az storage account update \
  --name oldshrimproad001 \
  --tags Environment=Production Owner=Brad@jinkslabs.com DataClassification=Internal

# Tag Key Vault
az keyvault update \
  --name jinkslabs-vault \
  --tags Environment=Production Owner=Brad@jinkslabs.com DataClassification=Restricted
```

---

## STATIC WEB APPS

### View Configuration
```bash
# List all Static Web Apps
az staticwebapp list -o table

# View specific Static Web App
az staticwebapp show --name old-shrimp-road-webapp \
  --query "{Name:name, Hostname:defaultHostname, CustomDomains:customDomains}"

# Check all Static Web Apps
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  echo "=== $app ==="
  az staticwebapp show --name $app -o json
done
```

---

## SIGN-IN LOGS AND AUDIT

### Entra ID Sign-in Logs
```bash
# View recent sign-ins (requires Microsoft Graph permissions)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$top=20" \
  --query "value[].{User:userPrincipalName, App:appDisplayName, Status:status.errorCode, IP:ipAddress}"

# Check for failed MFA attempts
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=status/errorCode ne 0 and authenticationRequirement eq 'multiFactorAuthentication'"
```

### Entra ID Audit Logs
```bash
# View recent audit events
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$top=20" \
  --query "value[].{Activity:activityDisplayName, User:initiatedBy.user.userPrincipalName, Date:activityDateTime}"
```

---

## COST MANAGEMENT

### View Costs
```bash
# Get current month costs
az consumption usage list \
  --start-date $(date -d "1 month ago" +%Y-%m-%d) \
  --end-date $(date +%Y-%m-%d) \
  --query "[].{Date:usageEnd, Resource:instanceName, Cost:pretaxCost}" -o table

# List budgets
az consumption budget list -o table
```

### Create Budget Alert
```bash
# Create monthly budget
az consumption budget create \
  --budget-name monthly-budget \
  --amount 500 \
  --time-grain Monthly \
  --start-date $(date +%Y-%m-01) \
  --resource-group <rg>
```

---

## TROUBLESHOOTING

### Check Azure Login Status
```bash
# Check if logged in
az account show

# List available subscriptions
az account list -o table

# Set subscription
az account set --subscription "86010fa7-268b-4d8e-95a6-6e0fab75c06c"
```

### Check Permissions
```bash
# Check your role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) -o table

# Check your Entra ID roles
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/me/memberOf" \
  --query "value[?contains(@odata.type, 'role')].displayName"
```

### Clear Azure CLI Cache
```bash
# Clear CLI cache if experiencing issues
az cache purge
az cache delete
```

---

## QUICK TESTING

### Test Network Access
```bash
# Test Storage Account access
az storage blob list --account-name oldshrimproad001 --container-name <container>

# Test Key Vault access
az keyvault secret list --vault-name jinkslabs-vault

# Test with specific IP (add your IP first)
curl -s ifconfig.me
```

### Test Soft Delete Recovery
```bash
# Create test blob
echo "Test" > /tmp/test.txt
az storage blob upload \
  --account-name oldshrimproad001 \
  --container-name <container> \
  --file /tmp/test.txt \
  --name test.txt

# Delete blob
az storage blob delete \
  --account-name oldshrimproad001 \
  --container-name <container> \
  --name test.txt

# List deleted blobs
az storage blob list \
  --account-name oldshrimproad001 \
  --container-name <container> \
  --include d

# Restore blob
az storage blob undelete \
  --account-name oldshrimproad001 \
  --container-name <container> \
  --name test.txt
```

---

## ENVIRONMENT VARIABLES

Set these for convenience:

```bash
export SUBSCRIPTION_ID="86010fa7-268b-4d8e-95a6-6e0fab75c06c"
export RESOURCE_GROUP="<your-resource-group>"
export STORAGE_ACCOUNT="oldshrimproad001"
export KEY_VAULT="jinkslabs-vault"
export LOG_WORKSPACE="jinkslabs-logs"

# Then use in commands:
az storage account show --name $STORAGE_ACCOUNT -o table
```

---

## USEFUL JMESPATH QUERIES

```bash
# List resources by type
az resource list --query "[?type=='Microsoft.Storage/storageAccounts']"

# Count resources by type
az resource list --query "length([?type=='Microsoft.Web/staticSites'])"

# Filter and project specific fields
az resource list \
  --query "[?location=='eastus'].{Name:name, Type:type, Tags:tags}" \
  --output json
```

---

## COMMON TROUBLESHOOTING SCENARIOS

### "Insufficient privileges" Error
```bash
# Check your current roles
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)

# You need one of:
# - Global Administrator (for Entra ID changes)
# - Security Administrator (for security settings)
# - Owner or Contributor (for resource changes)
```

### Cannot Access Storage/Key Vault After Firewall Configuration
```bash
# Temporarily allow all access
az storage account update --name oldshrimproad001 --default-action Allow
az keyvault update --name jinkslabs-vault --default-action Allow

# Check your current IP
curl -s ifconfig.me

# Add your IP
az storage account network-rule add --account-name oldshrimproad001 --ip-address "YOUR_IP/32"
az keyvault network-rule add --name jinkslabs-vault --ip-address "YOUR_IP/32"

# Revert to deny
az storage account update --name oldshrimproad001 --default-action Deny
az keyvault update --name jinkslabs-vault --default-action Deny
```

### Resource Locked - Cannot Delete/Modify
```bash
# View locks
az lock list --resource-group <rg> -o table

# Remove lock (if authorized)
az lock delete --name "PreventKVDeletion" --resource-group <rg>

# Make changes, then re-apply lock
az lock create --name "PreventKVDeletion" --lock-type CanNotDelete --resource-group <rg> --resource-name jinkslabs-vault --resource-type Microsoft.KeyVault/vaults
```

---

**Last Updated:** 2026-01-22
**Assessment Version:** 1.0

For detailed remediation guidance, see: `azure-security-assessment.md`
For step-by-step implementation: `QUICKSTART-SECURITY-REMEDIATION.md`
