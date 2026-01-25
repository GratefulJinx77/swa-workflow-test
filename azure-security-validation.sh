#!/bin/bash
#############################################################################
# Azure Security Assessment - Validation Script
# Jinks Labs Tenant (jinkslabs.com)
#
# Purpose: Collect current configuration data to validate security assessment
# Subscription: Primary PAYG (86010fa7-268b-4d8e-95a6-6e0fab75c06c)
#
# Usage: ./azure-security-validation.sh [resource-group-name]
#############################################################################

set -euo pipefail

# Configuration
SUBSCRIPTION_ID="86010fa7-268b-4d8e-95a6-6e0fab75c06c"
STORAGE_ACCOUNT="oldshrimproad001"
KEY_VAULT="jinkslabs-vault"
LOG_ANALYTICS_WORKSPACE="jinkslabs-logs"
OUTPUT_DIR="./security-assessment-$(date +%Y%m%d-%H%M%S)"

# Static Web Apps
STATIC_WEB_APPS=("old-shrimp-road-webapp" "wb-arnaud-webapp" "gray-sutton" "artemis-lunar" "walter-tyrell")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Resource Group (from parameter or prompt)
RESOURCE_GROUP="${1:-}"

#############################################################################
# Helper Functions
#############################################################################

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

collect_data() {
    local description="$1"
    local command="$2"
    local output_file="$3"

    echo -n "  Collecting $description... "

    if eval "$command" > "$OUTPUT_DIR/$output_file" 2>&1; then
        if [ -s "$OUTPUT_DIR/$output_file" ]; then
            print_success "Done"
            return 0
        else
            print_warning "Empty result"
            return 1
        fi
    else
        print_error "Failed"
        return 1
    fi
}

#############################################################################
# Pre-flight Checks
#############################################################################

print_header "Azure Security Assessment - Data Collection"
echo "Subscription ID: $SUBSCRIPTION_ID"
echo "Output Directory: $OUTPUT_DIR"
echo "Start Time: $(date)"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_error "Azure CLI not found. Please install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null; then
    print_error "Not logged in to Azure. Run: az login"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
print_success "Created output directory: $OUTPUT_DIR"

# Set subscription context
print_info "Setting subscription context..."
if az account set --subscription "$SUBSCRIPTION_ID" &> /dev/null; then
    print_success "Subscription set: $SUBSCRIPTION_ID"
else
    print_error "Failed to set subscription context"
    exit 1
fi

# Get resource group if not provided
if [ -z "$RESOURCE_GROUP" ]; then
    print_info "Detecting resource groups..."
    RESOURCE_GROUPS=$(az group list --query "[].name" -o tsv)

    if [ -z "$RESOURCE_GROUPS" ]; then
        print_error "No resource groups found"
        exit 1
    fi

    echo -e "\nAvailable Resource Groups:"
    echo "$RESOURCE_GROUPS" | nl
    echo ""
    read -p "Enter resource group name (or press Enter for first): " RESOURCE_GROUP

    if [ -z "$RESOURCE_GROUP" ]; then
        RESOURCE_GROUP=$(echo "$RESOURCE_GROUPS" | head -n1)
    fi
fi

print_info "Using Resource Group: $RESOURCE_GROUP"
echo ""

#############################################################################
# Section 1: Identity and Access Management
#############################################################################

print_header "Section 1: Identity and Access Management"

# Conditional Access Policies
collect_data "Conditional Access policies" \
    "az rest --method GET --uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'" \
    "01-conditional-access-policies.json"

# Security Defaults
collect_data "Security Defaults status" \
    "az rest --method GET --uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'" \
    "01-security-defaults.json"

# Users and MFA status
collect_data "User accounts" \
    "az ad user list --query '[].{UPN:userPrincipalName, Type:userType, Enabled:accountEnabled}'" \
    "01-users.json"

# Guest users
collect_data "Guest users" \
    "az ad user list --filter \"userType eq 'Guest'\" --query '[].{UPN:userPrincipalName, Created:createdDateTime}'" \
    "01-guest-users.json"

# Role assignments (subscription level)
collect_data "Subscription role assignments" \
    "az role assignment list --scope '/subscriptions/$SUBSCRIPTION_ID' --query '[].{Principal:principalName, Role:roleDefinitionName, Type:principalType}'" \
    "01-role-assignments-subscription.json"

# Privileged role assignments
collect_data "Privileged role assignments" \
    "az role assignment list --scope '/subscriptions/$SUBSCRIPTION_ID' --query \"[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator']\"" \
    "01-privileged-roles.json"

# Service principals
collect_data "Service principals" \
    "az ad sp list --all --query '[].{AppId:appId, DisplayName:displayName, Enabled:accountEnabled}'" \
    "01-service-principals.json"

# PIM configuration (if available)
collect_data "PIM role assignments" \
    "az rest --method GET --uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'" \
    "01-pim-assignments.json"

# Authentication methods policy
collect_data "Authentication methods policy" \
    "az rest --method GET --uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'" \
    "01-auth-methods-policy.json"

echo ""

#############################################################################
# Section 2: Defender for Cloud and Threat Detection
#############################################################################

print_header "Section 2: Defender for Cloud and Threat Detection"

# Defender plans
collect_data "Defender for Cloud plans" \
    "az security pricing list" \
    "02-defender-plans.json"

# Security assessments
collect_data "Security assessments" \
    "az security assessment list --query '[].{Name:displayName, Status:status.code, Severity:metadata.severity}'" \
    "02-security-assessments.json"

# High severity unhealthy assessments
collect_data "Critical security findings" \
    "az security assessment list --query \"[?status.code=='Unhealthy' && metadata.severity=='High']\"" \
    "02-critical-findings.json"

# Secure Score
collect_data "Secure Score" \
    "az security secure-score-controls list" \
    "02-secure-score.json"

# Security contacts
collect_data "Security contacts" \
    "az security contact list" \
    "02-security-contacts.json"

echo ""

#############################################################################
# Section 3: Network Security
#############################################################################

print_header "Section 3: Network Security"

# Network Security Groups
collect_data "Network Security Groups" \
    "az network nsg list" \
    "03-nsgs.json"

# Virtual Networks
collect_data "Virtual Networks" \
    "az network vnet list" \
    "03-vnets.json"

# DDoS Protection Plans
collect_data "DDoS Protection Plans" \
    "az network ddos-protection list" \
    "03-ddos-plans.json"

# Network Watcher
collect_data "Network Watcher status" \
    "az network watcher list" \
    "03-network-watcher.json"

# Storage Account network rules
collect_data "Storage Account network configuration" \
    "az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query '{Name:name, NetworkRules:networkRuleSet, PublicAccess:publicNetworkAccess}'" \
    "03-storage-network.json"

# Key Vault network rules
collect_data "Key Vault network configuration" \
    "az keyvault show --name $KEY_VAULT --query '{Name:name, NetworkAcls:networkAcls, PublicAccess:publicNetworkAccess}'" \
    "03-keyvault-network.json"

# Private endpoints
collect_data "Private Endpoints" \
    "az network private-endpoint list" \
    "03-private-endpoints.json"

echo ""

#############################################################################
# Section 4: Data Protection - Storage Account
#############################################################################

print_header "Section 4: Data Protection - Storage Account"

# Storage Account configuration
collect_data "Storage Account configuration" \
    "az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP" \
    "04-storage-account-config.json"

# Storage encryption configuration
collect_data "Storage encryption settings" \
    "az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query '{Name:name, EncryptionKeySource:encryption.keySource, KeyVaultProperties:encryption.keyVaultProperties}'" \
    "04-storage-encryption.json"

# Blob soft delete
collect_data "Blob soft delete configuration" \
    "az storage blob service-properties delete-policy show --account-name $STORAGE_ACCOUNT" \
    "04-blob-soft-delete.json"

# Container soft delete
collect_data "Container soft delete configuration" \
    "az storage account blob-service-properties show --account-name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query '{ContainerDeleteRetentionEnabled:containerDeleteRetentionPolicy.enabled, Days:containerDeleteRetentionPolicy.days}'" \
    "04-container-soft-delete.json"

# Blob versioning
collect_data "Blob versioning configuration" \
    "az storage account blob-service-properties show --account-name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query '{VersioningEnabled:isVersioningEnabled}'" \
    "04-blob-versioning.json"

# Lifecycle management policy
collect_data "Storage lifecycle management" \
    "az storage account management-policy show --account-name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP" \
    "04-storage-lifecycle.json"

# Storage redundancy
collect_data "Storage redundancy configuration" \
    "az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query '{Name:name, SKU:sku.name, PrimaryLocation:primaryLocation, SecondaryLocation:secondaryLocation}'" \
    "04-storage-redundancy.json"

echo ""

#############################################################################
# Section 5: Data Protection - Key Vault
#############################################################################

print_header "Section 5: Data Protection - Key Vault"

# Key Vault configuration
collect_data "Key Vault configuration" \
    "az keyvault show --name $KEY_VAULT" \
    "05-keyvault-config.json"

# Key Vault soft delete and purge protection
collect_data "Key Vault protection settings" \
    "az keyvault show --name $KEY_VAULT --query '{Name:name, SoftDeleteEnabled:properties.enableSoftDelete, PurgeProtectionEnabled:properties.enablePurgeProtection}'" \
    "05-keyvault-protection.json"

# Key Vault secrets (names only, not values)
collect_data "Key Vault secrets list" \
    "az keyvault secret list --vault-name $KEY_VAULT --query '[].{Name:name, Enabled:attributes.enabled, Created:attributes.created}'" \
    "05-keyvault-secrets.json"

# Key Vault keys
collect_data "Key Vault keys list" \
    "az keyvault key list --vault-name $KEY_VAULT --query '[].{Name:name, Enabled:attributes.enabled, KeyType:kty}'" \
    "05-keyvault-keys.json"

# Key Vault RBAC vs Access Policies
collect_data "Key Vault permission model" \
    "az keyvault show --name $KEY_VAULT --query '{Name:name, EnableRbacAuthorization:properties.enableRbacAuthorization}'" \
    "05-keyvault-rbac.json"

echo ""

#############################################################################
# Section 6: Monitoring and Logging
#############################################################################

print_header "Section 6: Monitoring and Logging"

# Log Analytics workspace configuration
collect_data "Log Analytics workspace" \
    "az monitor log-analytics workspace show --workspace-name $LOG_ANALYTICS_WORKSPACE --resource-group $RESOURCE_GROUP --query '{Name:name, RetentionInDays:retentionInDays, DailyCap:workspaceCapping.dailyQuotaGb, SKU:sku.name}'" \
    "06-log-analytics-config.json"

# Sentinel workspace (if enabled)
collect_data "Microsoft Sentinel workspaces" \
    "az sentinel workspace list" \
    "06-sentinel-workspaces.json"

# Diagnostic settings - Subscription Activity Log
collect_data "Activity Log diagnostic settings" \
    "az monitor diagnostic-settings subscription list" \
    "06-activity-log-diagnostics.json"

# Diagnostic settings - Storage Account
collect_data "Storage Account diagnostic settings" \
    "az monitor diagnostic-settings list --resource \$(az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query id -o tsv)" \
    "06-storage-diagnostics.json"

# Diagnostic settings - Key Vault
collect_data "Key Vault diagnostic settings" \
    "az monitor diagnostic-settings list --resource \$(az keyvault show --name $KEY_VAULT --query id -o tsv)" \
    "06-keyvault-diagnostics.json"

# Alert rules - Metric alerts
collect_data "Metric alert rules" \
    "az monitor metrics alert list" \
    "06-metric-alerts.json"

# Alert rules - Activity log alerts
collect_data "Activity log alert rules" \
    "az monitor activity-log alert list" \
    "06-activity-log-alerts.json"

# Alert rules - Log query alerts
collect_data "Log query alert rules" \
    "az monitor scheduled-query list" \
    "06-scheduled-query-alerts.json"

# Action groups
collect_data "Action groups" \
    "az monitor action-group list" \
    "06-action-groups.json"

echo ""

#############################################################################
# Section 7: Static Web Apps
#############################################################################

print_header "Section 7: Static Web Apps Configuration"

for app in "${STATIC_WEB_APPS[@]}"; do
    collect_data "Static Web App: $app" \
        "az staticwebapp show --name $app --query '{Name:name, DefaultHostname:defaultHostname, CustomDomains:customDomains, StagingEnvPolicy:stagingEnvironmentPolicy}'" \
        "07-staticwebapp-${app}.json"
done

echo ""

#############################################################################
# Section 8: Azure Policy and Governance
#############################################################################

print_header "Section 8: Azure Policy and Governance"

# Policy assignments
collect_data "Policy assignments" \
    "az policy assignment list" \
    "08-policy-assignments.json"

# Policy compliance summary
collect_data "Policy compliance summary" \
    "az policy state summarize --query 'results.policyAssignments[].{Name:policyAssignmentName, NonCompliant:results.nonCompliantResources, Compliant:results.compliantResources}'" \
    "08-policy-compliance-summary.json"

# Non-compliant resources
collect_data "Non-compliant resources" \
    "az policy state list --filter \"ComplianceState eq 'NonCompliant'\" --query '[].{Resource:resourceId, Policy:policyDefinitionName, Reason:complianceReasonCode}'" \
    "08-non-compliant-resources.json"

# Custom policy definitions
collect_data "Custom policy definitions" \
    "az policy definition list --query \"[?policyType=='Custom']\"" \
    "08-custom-policies.json"

# Management groups
collect_data "Management group hierarchy" \
    "az account management-group list" \
    "08-management-groups.json"

echo ""

#############################################################################
# Section 9: Compliance and Regulatory
#############################################################################

print_header "Section 9: Compliance and Regulatory Standards"

# Regulatory compliance standards
collect_data "Compliance standards" \
    "az security regulatory-compliance-standards list" \
    "09-compliance-standards.json"

# Compliance assessments for Azure Security Benchmark
collect_data "Azure Security Benchmark compliance" \
    "az security regulatory-compliance-assessments list --standard-name 'Azure-Security-Benchmark'" \
    "09-asb-compliance.json"

echo ""

#############################################################################
# Section 10: Resource Inventory and Locks
#############################################################################

print_header "Section 10: Resource Inventory and Protection"

# Resource locks
collect_data "Resource locks" \
    "az lock list" \
    "10-resource-locks.json"

# All resources with tags
collect_data "Resource inventory" \
    "az resource list --query '[].{Name:name, Type:type, Location:location, ResourceGroup:resourceGroup, Tags:tags}'" \
    "10-resource-inventory.json"

# Resources without tags
collect_data "Untagged resources" \
    "az resource list --query \"[?tags==null].{Name:name, Type:type, ResourceGroup:resourceGroup}\"" \
    "10-untagged-resources.json"

# Cost budgets
collect_data "Cost budgets" \
    "az consumption budget list" \
    "10-cost-budgets.json"

echo ""

#############################################################################
# Section 11: Additional Resource Configurations
#############################################################################

print_header "Section 11: Additional Resource Configurations"

# Lab Plan configuration
collect_data "Lab Plan configuration" \
    "az resource list --resource-type Microsoft.LabServices/labPlans" \
    "11-lab-plans.json"

# Recovery Services Vaults
collect_data "Recovery Services Vaults" \
    "az backup vault list" \
    "11-recovery-vaults.json"

# Application Insights
collect_data "Application Insights instances" \
    "az monitor app-insights component list" \
    "11-app-insights.json"

echo ""

#############################################################################
# Generate Summary Report
#############################################################################

print_header "Generating Summary Report"

SUMMARY_FILE="$OUTPUT_DIR/00-assessment-summary.txt"

cat > "$SUMMARY_FILE" << EOF
Azure Security Assessment - Data Collection Summary
====================================================

Assessment Date: $(date)
Subscription ID: $SUBSCRIPTION_ID
Resource Group: $RESOURCE_GROUP
Output Directory: $OUTPUT_DIR

Resources Assessed:
-------------------
- Storage Account: $STORAGE_ACCOUNT
- Key Vault: $KEY_VAULT
- Log Analytics Workspace: $LOG_ANALYTICS_WORKSPACE
- Static Web Apps: ${#STATIC_WEB_APPS[@]} applications

Data Collection Results:
------------------------
EOF

# Count collected files
TOTAL_FILES=$(find "$OUTPUT_DIR" -name "*.json" | wc -l)
EMPTY_FILES=$(find "$OUTPUT_DIR" -name "*.json" -size 0 | wc -l)
COLLECTED_FILES=$((TOTAL_FILES - EMPTY_FILES))

echo "Total data files collected: $COLLECTED_FILES" >> "$SUMMARY_FILE"
echo "Empty results: $EMPTY_FILES" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "Collected Data Files:" >> "$SUMMARY_FILE"
echo "--------------------" >> "$SUMMARY_FILE"
find "$OUTPUT_DIR" -name "*.json" -printf "%f\n" | sort >> "$SUMMARY_FILE"

print_success "Summary report generated: $SUMMARY_FILE"

#############################################################################
# Completion
#############################################################################

echo ""
print_header "Data Collection Complete"
echo ""
print_info "Results location: $OUTPUT_DIR"
print_info "Summary report: $SUMMARY_FILE"
echo ""
print_info "Next Steps:"
echo "  1. Review collected data files for validation"
echo "  2. Compare findings with security assessment report"
echo "  3. Prioritize remediation based on risk ratings"
echo "  4. Begin Phase 1 implementation (break-glass accounts, Defender plans)"
echo ""
print_success "Assessment data collection completed successfully"
echo ""

# Create a findings checklist
CHECKLIST_FILE="$OUTPUT_DIR/00-validation-checklist.md"

cat > "$CHECKLIST_FILE" << 'EOF'
# Security Assessment Validation Checklist

## Critical Findings to Validate

### Identity and Access Management
- [ ] **C-IAM-01**: Check `01-conditional-access-policies.json` - Are CA policies configured?
- [ ] **C-IAM-02**: Review `01-users.json` - Are break-glass accounts present?
- [ ] **C-IAM-03**: Check `01-pim-assignments.json` - Is PIM configured for privileged roles?

### Threat Detection and Monitoring
- [ ] **C-MON-01**: Review `02-defender-plans.json` - Which Defender plans are enabled?
- [ ] **C-MON-02**: Check `06-sentinel-workspaces.json` - Is Sentinel deployed?
- [ ] **C-MON-03**: Validate centralized logging configuration

### High Priority Validations

#### Identity
- [ ] **H-IAM-01**: Review `01-auth-methods-policy.json` - Password protection configured?
- [ ] **H-IAM-02**: Check `01-conditional-access-policies.json` - Legacy auth blocked?
- [ ] **H-IAM-03**: Review `01-security-defaults.json` - Security defaults status?
- [ ] **H-IAM-04**: Check `01-service-principals.json` - Service principal audit?
- [ ] **H-IAM-05**: Validate risk-based policies in CA configuration

#### Network Security
- [ ] **H-NET-01**: Check `03-storage-network.json` and `03-keyvault-network.json` - Network restrictions?
- [ ] **H-NET-02**: Evaluate need for WAF based on Static Web Apps usage
- [ ] **H-NET-03**: Review `03-ddos-plans.json` - DDoS protection level?

#### Data Protection
- [ ] **H-DATA-01**: Evaluate DLP requirements (requires Microsoft 365)
- [ ] **H-DATA-02**: Check `04-storage-encryption.json` - Customer-managed keys?
- [ ] **H-DATA-03**: Review `04-blob-soft-delete.json` and `04-blob-versioning.json` - Protection enabled?
- [ ] **H-DATA-04**: Validate information protection requirements

#### Monitoring
- [ ] **H-MON-01**: Check diagnostic settings files - All resources logging to Log Analytics?
- [ ] **H-MON-02**: Review `06-*-alerts.json` - Are security alert rules configured?
- [ ] **H-MON-03**: Evaluate threat intelligence integration needs
- [ ] **H-MON-04**: Check if UEBA is enabled in Sentinel

#### Compliance
- [ ] **H-COMP-01**: Review `09-compliance-standards.json` - Compliance assessments enabled?
- [ ] **H-COMP-02**: Check `08-policy-assignments.json` - Policies in enforce mode?
- [ ] **H-COMP-03**: Review `10-resource-inventory.json` - Consistent tagging?

#### Misconfigurations
- [ ] **H-MISC-01**: Review `07-staticwebapp-*.json` - Static Web Apps security configuration?
- [ ] **H-MISC-02**: Check `10-resource-locks.json` - Critical resources locked?
- [ ] **H-MISC-03**: Review `01-privileged-roles.json` - RBAC assignments appropriate?
- [ ] **H-MISC-04**: Check `02-secure-score.json` - Current Secure Score and trends?

## Validation Instructions

1. Open each JSON file mentioned in the checklist
2. Compare actual configuration against expected baseline from assessment report
3. Mark items as validated or requiring remediation
4. Document any deviations from the assessment assumptions
5. Update the remediation roadmap based on validated findings

## Priority Actions After Validation

### Immediate (Week 1)
- [ ] Create break-glass accounts if missing
- [ ] Enable Defender for Cloud plans (Storage, Key Vault, Resource Manager, DNS)
- [ ] Apply resource locks to Key Vault, Storage Account, Log Analytics workspace
- [ ] Configure baseline Conditional Access policy (report-only mode initially)

### Short Term (Week 2-4)
- [ ] Enable Entra ID P2 and configure PIM
- [ ] Deploy Microsoft Sentinel and configure data connectors
- [ ] Enable comprehensive diagnostic logging
- [ ] Configure security alert rules

### Medium Term (Month 2)
- [ ] Implement Azure Policy governance framework
- [ ] Block legacy authentication
- [ ] Configure compliance assessments
- [ ] Implement resource tagging strategy

---

**Assessment Date:** $(date)
**Validated By:** _______________________
**Validation Date:** _______________________

EOF

print_success "Validation checklist created: $CHECKLIST_FILE"

echo ""
print_info "To review the assessment report and collected data:"
echo "  cd $OUTPUT_DIR"
echo "  cat 00-assessment-summary.txt"
echo "  cat 00-validation-checklist.md"
echo ""
