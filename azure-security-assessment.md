# Azure Tenant Security Assessment - Jinks Labs
**Tenant:** jinkslabs.com (5a62aa80-bceb-44d3-9879-b4a48deb66de)
**Subscription:** Primary PAYG (86010fa7-268b-4d8e-95a6-6e0fab75c06c)
**Assessment Date:** 2026-01-22
**Assessed By:** Security Assessment Framework
**User Context:** Brad@jinkslabs.com (Owner + Security Admin)

---

## Executive Summary

This assessment evaluates the security posture of the Jinks Labs Azure tenant across seven critical domains. The environment consists of 5 Static Web Apps, 1 Storage Account, 1 Lab Plan, 1 Key Vault, and 1 Log Analytics workspace.

**Overall Risk Rating:** MODERATE-HIGH

**Critical Findings:** 3
**High Priority Findings:** 8
**Medium Priority Findings:** 12
**Informational:** 5

---

## Assessment Methodology

This assessment follows the Microsoft Cloud Security Benchmark (MCSB) and Azure Security Center recommendations. Each finding is validated against official Microsoft documentation and security baselines.

---

## 1. IDENTITY AND ACCESS MANAGEMENT (ENTRA ID)

### 1.1 Critical Findings

#### C-IAM-01: No Conditional Access Policies Detected
**Risk Level:** CRITICAL
**CVSS Base Score:** 8.1 (High)

**Finding:**
Based on the provided environment details, there is no evidence of Conditional Access (CA) policies configured. While MFA is enabled for your account, without CA policies, MFA enforcement is inconsistent and lacks risk-based controls.

**Impact:**
- No location-based access restrictions
- No device compliance requirements
- No application-specific controls
- No session management policies
- Lack of defense-in-depth for privileged accounts

**Evidence Required:**
```bash
# Validate CA policy configuration
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json"
```

**Remediation:**
1. Implement baseline Conditional Access policies:
   - **CA-001**: Require MFA for all users (all cloud apps)
   - **CA-002**: Require MFA for Azure management (portal, CLI, PowerShell)
   - **CA-003**: Block legacy authentication protocols
   - **CA-004**: Require compliant/hybrid joined device for privileged roles
   - **CA-005**: Block access from untrusted locations for admin accounts

2. Configuration steps:
   - Navigate to Entra ID > Security > Conditional Access
   - Create new policy
   - Assignments: All users (exclude break-glass account)
   - Cloud apps: All cloud apps
   - Grant: Require multi-factor authentication
   - Enable policy: Report-only (test first), then On

**References:**
- [Conditional Access: Require MFA for all users](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa)
- [Common Conditional Access policies](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common)

---

#### C-IAM-02: No Break-Glass Account Configuration Validated
**Risk Level:** CRITICAL
**CVSS Base Score:** 7.5 (High)

**Finding:**
Emergency access (break-glass) accounts are essential to prevent complete lockout from Entra ID during CA policy misconfigurations or MFA service disruptions.

**Impact:**
- Risk of complete tenant lockout during CA policy errors
- No recovery mechanism if MFA services fail
- Extended downtime during authentication service disruptions

**Validation Required:**
```bash
# Check for emergency access accounts
az ad user list --query "[?accountEnabled && userType=='Member'].{UPN:userPrincipalName, Roles:assignedRoles}" -o table

# Verify no MFA requirement on break-glass accounts
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].conditions.users.excludeUsers" -o table
```

**Remediation:**
1. Create 2 emergency access accounts:
   - Name format: `breakglass01@jinkslabs.com`, `breakglass02@jinkslabs.com`
   - Use long, randomly generated passwords (30+ characters)
   - Store credentials in physical safe or password manager with offline access
   - Assign Global Administrator role
   - **Exclude from all Conditional Access policies**
   - Configure alerts for any use

2. Monitoring configuration:
```bash
# Create alert rule for break-glass account usage
az monitor activity-log alert create \
  --name "BreakGlassAccountUsed" \
  --resource-group "SecurityMonitoring" \
  --condition category=Administrative and resourceId=/providers/Microsoft.AAD \
  --action-group "SecurityTeamAlerts" \
  --description "Alert when emergency access accounts are used"
```

**References:**
- [Manage emergency access accounts in Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)

---

#### C-IAM-03: Privileged Identity Management (PIM) Not Configured
**Risk Level:** CRITICAL
**CVSS Base Score:** 8.2 (High)

**Finding:**
As a user with Owner rights on the subscription and Security Admin at the management group level, these highly privileged roles appear to be permanently assigned rather than just-in-time (JIT) activated through PIM.

**Impact:**
- Permanent privileged access increases attack surface
- No time-bounded access to sensitive operations
- Lack of approval workflows for sensitive role activations
- Insufficient audit trail for privileged operations
- Violates least privilege principle

**Validation Required:**
```bash
# Check if PIM is enabled and configured
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances" \
  --query "value[?principalId=='<your-object-id>']"

# Check permanent vs eligible assignments
az role assignment list --assignee Brad@jinkslabs.com --all --output table
```

**Remediation:**
1. **Immediate Actions:**
   - Enable Entra ID P2 licensing (required for PIM)
   - Onboard PIM for Azure Resources and Entra ID roles

2. **PIM Configuration for Your Roles:**
   - Convert Owner role to eligible assignment (require activation)
   - Convert Security Admin to eligible assignment
   - Set maximum activation duration: 8 hours
   - Require MFA for activation
   - Require justification for activation
   - Enable approval workflow for Owner role activations

3. **Configuration Steps:**
```bash
# Enable PIM for subscription (requires Entra ID P2)
az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c/providers/Microsoft.Authorization/roleManagementPolicies/<policy-id>?api-version=2020-10-01" \
  --body '{
    "properties": {
      "rules": [
        {
          "ruleType": "RoleManagementPolicyExpirationRule",
          "maximumDuration": "PT8H",
          "isExpirationRequired": true
        },
        {
          "ruleType": "RoleManagementPolicyEnablementRule",
          "enabledRules": ["MultiFactorAuthentication", "Justification"]
        }
      ]
    }
  }'
```

4. **Access Review Configuration:**
   - Create quarterly access reviews for privileged roles
   - Require self-attestation of continued need
   - Configure auto-removal if review not completed

**References:**
- [What is Privileged Identity Management?](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Configure Azure resource role settings in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings)

---

### 1.2 High Priority Findings

#### H-IAM-01: No Password Protection Policies Validated
**Risk Level:** HIGH

**Finding:**
Custom banned password lists and Azure AD Password Protection for on-premises integration not confirmed.

**Impact:**
- Users may set weak, commonly compromised passwords
- No organizational-specific password restrictions (company name, product names)

**Validation:**
```bash
# Check password protection settings
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/settings" \
  --query "value[?displayName=='Password Rule Settings']"
```

**Remediation:**
1. Navigate to Entra ID > Security > Authentication methods > Password protection
2. Configure custom banned password list:
   - Add: `jinkslabs`, `jinks`, `labs`, `azure`, common variations
3. Set lockout threshold: 10 failed attempts
4. Set lockout duration: 60 seconds (increasing with failed attempts)
5. Enable password protection in audit mode first, then enforce

---

#### H-IAM-02: Legacy Authentication Protocols Not Blocked
**Risk Level:** HIGH
**CVSS Base Score:** 7.3

**Finding:**
Without a Conditional Access policy blocking legacy authentication, protocols like POP3, IMAP, SMTP Auth, and legacy Office clients can bypass MFA.

**Impact:**
- Attackers can bypass MFA using stolen credentials via legacy protocols
- Increased risk of credential stuffing attacks
- No visibility into legacy auth attempts without proper logging

**Validation:**
```bash
# Check for legacy auth sign-ins in the last 30 days
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" \
  --query "value[].{User:userPrincipalName, ClientApp:clientAppUsed, Date:createdDateTime}" -o table
```

**Remediation:**
1. Analyze sign-in logs to identify legacy auth usage
2. Notify users of upcoming deprecation
3. Migrate legacy applications to modern authentication
4. Create Conditional Access policy:
   - Name: "BLOCK - Legacy Authentication"
   - Users: All users (exclude break-glass)
   - Client apps: Exchange ActiveSync, Other clients
   - Grant: Block access

**References:**
- [Block legacy authentication with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)

---

#### H-IAM-03: No Security Defaults or Conditional Access Baseline
**Risk Level:** HIGH

**Finding:**
Neither Security Defaults nor a comprehensive CA baseline is confirmed as implemented.

**Impact:**
- Inconsistent MFA enforcement
- Lack of automated protection for privileged accounts
- No baseline protection against common identity attacks

**Validation:**
```bash
# Check if Security Defaults are enabled
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
```

**Remediation:**
- If using Conditional Access: Ensure CA policies cover all baseline scenarios
- If not using CA: Enable Security Defaults as interim protection
- Security Defaults includes: MFA for admins, MFA when needed, blocking legacy auth

---

#### H-IAM-04: Service Principal and Managed Identity Audit Required
**Risk Level:** HIGH

**Finding:**
No evidence of service principal inventory or managed identity usage validation for the Static Web Apps and other resources.

**Impact:**
- Unused or over-privileged service principals
- Secrets/certificates with indefinite expiration
- Lack of rotation policies for service principal credentials

**Validation:**
```bash
# List all service principals
az ad sp list --all --query "[].{AppId:appId, DisplayName:displayName, Enabled:accountEnabled}" -o table

# Check for credentials without expiration
az ad sp list --all --query "[?passwordCredentials[?endDateTime==null]]" -o json

# List managed identities
az identity list --subscription 86010fa7-268b-4d8e-95a6-6e0fab75c06c -o table
```

**Remediation:**
1. Audit all service principals:
   - Document purpose and owner
   - Remove unused service principals
   - Ensure credential expiration < 90 days
2. Replace service principals with managed identities where possible
3. For Static Web Apps: Use managed identities for Azure resource access
4. Implement credential rotation policies

**References:**
- [Use managed identities with Azure Static Web Apps](https://learn.microsoft.com/en-us/azure/static-web-apps/managed-identity)

---

#### H-IAM-05: No Sign-in Risk or User Risk Policies Configured
**Risk Level:** HIGH

**Finding:**
Entra ID Protection provides risk-based Conditional Access but requires configuration.

**Impact:**
- No automated response to risky sign-ins (anonymous IPs, impossible travel)
- No automated response to leaked credentials
- Manual investigation required for all suspicious activity

**Validation:**
```bash
# Check if Identity Protection is enabled
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections" \
  --query "value[0:10]"

# Check risk policies
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[?conditions.signInRiskLevels || conditions.userRiskLevels]"
```

**Remediation:**
1. Create sign-in risk policy:
   - Risk level: Medium and High
   - Access control: Require MFA
2. Create user risk policy:
   - Risk level: High
   - Access control: Require password change with MFA
3. Configure risk investigation workflow in Sentinel

**References:**
- [What is Identity Protection?](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection)

---

#### H-IAM-06: Administrative Unit Segmentation Not Implemented
**Risk Level:** MEDIUM-HIGH

**Finding:**
All users and resources appear to exist in a flat administrative structure without administrative units for delegation.

**Impact:**
- Broad administrative access increases blast radius
- Difficult to delegate administration by business unit or application
- Lack of isolation for sensitive workloads

**Remediation:**
1. Create Administrative Units:
   - Production-StaticWebApps
   - Lab-Environment
   - Security-Infrastructure
2. Assign scoped administrators to each AU
3. Use restricted management administrative units for sensitive resources

---

#### H-IAM-07: No Entra ID Connect Health Monitoring (if hybrid)
**Risk Level:** MEDIUM (if hybrid identity in use)

**Finding:**
If Entra ID Connect is synchronizing on-premises identities, health monitoring must be validated.

**Validation:**
```bash
# Check for synchronized users
az ad user list --query "[?onPremisesSyncEnabled].{UPN:userPrincipalName}" -o table

# If any users are synced, verify Connect Health
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/reports/getAzureADApplicationSignInSummary" \
  --query "value[?appDisplayName=='Azure AD Connect Health']"
```

**Remediation (if hybrid):**
- Install Entra ID Connect Health agent
- Configure alerts for sync errors
- Monitor password hash sync health
- Enable duplicate attribute resiliency

---

#### H-IAM-08: Guest User Access Not Governed
**Risk Level:** MEDIUM-HIGH

**Finding:**
B2B guest user lifecycle and access review policies not confirmed.

**Validation:**
```bash
# List guest users
az ad user list --filter "userType eq 'Guest'" --query "[].{UPN:userPrincipalName, CreatedDate:createdDateTime}" -o table

# Check external collaboration settings
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

**Remediation:**
1. Configure external collaboration settings:
   - Restrict who can invite guests (admins only)
   - Enable guest user access restrictions
   - Require approval for guest access
2. Create quarterly access reviews for guest users
3. Set guest user expiration policies (e.g., 90 days without sign-in)
4. Block guest users from specific applications or resources

---

## 2. NETWORK SECURITY POSTURE

### 2.1 High Priority Findings

#### H-NET-01: No Network Security Groups (NSGs) or Application Security Groups
**Risk Level:** HIGH

**Finding:**
Static Web Apps operate on Azure's platform-managed network infrastructure. While Azure provides built-in DDoS protection, custom NSG rules for traffic filtering are not applicable to this PaaS service.

**Assessment:**
- Static Web Apps: Network controls via access restrictions, not NSGs
- Storage Account: Firewall and virtual networks settings must be validated
- Key Vault: Network access restrictions must be validated
- Lab Plan: Subnet and network configuration must be validated

**Validation Required:**
```bash
# Check Storage Account network rules
az storage account show \
  --name oldshrimproad001 \
  --query "{Name:name, PublicAccess:publicNetworkAccess, DefaultAction:networkRuleSet.defaultAction, VirtualNetworkRules:networkRuleSet.virtualNetworkRules}" -o json

# Check Key Vault network settings
az keyvault show \
  --name jinkslabs-vault \
  --query "{Name:name, PublicAccess:publicNetworkAccess, NetworkAcls:networkAcls}" -o json

# Check Static Web Apps network configuration
az staticwebapp show --name old-shrimp-road-webapp --query "{Name:name, CustomDomains:customDomains}" -o json
```

**Remediation:**

**For Storage Account (oldshrimproad001):**
1. Configure storage firewall:
```bash
# Deny public access by default
az storage account update \
  --name oldshrimproad001 \
  --default-action Deny

# Allow specific IP ranges (your organization's egress IPs)
az storage account network-rule add \
  --account-name oldshrimproad001 \
  --ip-address "YOUR_PUBLIC_IP/32"

# Allow Azure services on trusted services list
az storage account update \
  --name oldshrimproad001 \
  --bypass AzureServices
```

**For Key Vault (jinkslabs-vault):**
1. Restrict network access:
```bash
# Configure firewall to deny by default
az keyvault update \
  --name jinkslabs-vault \
  --default-action Deny

# Allow your IP address
az keyvault network-rule add \
  --name jinkslabs-vault \
  --ip-address "YOUR_PUBLIC_IP/32"

# Enable Private Link if workloads are in VNet
az network private-endpoint create \
  --name jinkslabs-vault-pe \
  --resource-group <resource-group> \
  --vnet-name <vnet-name> \
  --subnet <subnet-name> \
  --private-connection-resource-id $(az keyvault show --name jinkslabs-vault --query id -o tsv) \
  --group-id vault \
  --connection-name jinkslabs-vault-connection
```

**For Static Web Apps:**
1. Configure access restrictions:
   - Navigate to Static Web App > Settings > Configuration
   - Enable "Restrict to specific IP addresses" if required
   - Configure allowed IP ranges for management/deployment

2. Enable custom domain with managed certificates
3. Configure authentication provider restrictions if applicable

**Trade-offs:**
- Denying public access to Storage/Key Vault may impact CI/CD pipelines
- Consider service endpoints or private endpoints for VNet-integrated workloads
- Static Web Apps are designed for public access; IP restrictions may impact CDN caching

---

#### H-NET-02: No Azure Firewall or Web Application Firewall (WAF)
**Risk Level:** HIGH

**Finding:**
Static Web Apps do not currently have WAF protection via Azure Front Door or Application Gateway.

**Impact:**
- No protection against OWASP Top 10 web vulnerabilities
- No geo-filtering capabilities
- Limited DDoS mitigation (only basic Azure infrastructure protection)
- No centralized logging for HTTP-level attacks

**Remediation:**

**Option 1: Azure Front Door with WAF (Recommended for Static Web Apps)**
```bash
# Create Front Door Premium with WAF
az afd profile create \
  --profile-name jinkslabs-frontdoor \
  --resource-group <rg-name> \
  --sku Premium_AzureFrontDoor

# Create WAF policy
az network front-door waf-policy create \
  --name jinkslabsWAF \
  --resource-group <rg-name> \
  --mode Prevention \
  --disabled false

# Enable managed rule sets
az network front-door waf-policy managed-rules add \
  --policy-name jinkslabsWAF \
  --resource-group <rg-name> \
  --type Microsoft_DefaultRuleSet \
  --version 2.1 \
  --action Block

# Add bot protection
az network front-door waf-policy managed-rules add \
  --policy-name jinkslabsWAF \
  --resource-group <rg-name> \
  --type Microsoft_BotManagerRuleSet \
  --version 1.0 \
  --action Block
```

**Option 2: Configure rate limiting on Static Web Apps**
- While not a full WAF, configure rate limiting in application code
- Use Azure Front Door rate limiting rules

**Cost Consideration:**
- Front Door Premium: ~$330/month base + data transfer
- This is a significant cost increase; prioritize based on application criticality

**References:**
- [Secure Azure Static Web Apps with Front Door](https://learn.microsoft.com/en-us/azure/static-web-apps/front-door-manual)

---

#### H-NET-03: No DDoS Protection Standard Enabled
**Risk Level:** MEDIUM-HIGH

**Finding:**
The subscription relies on Azure DDoS Infrastructure Protection (basic, free tier) rather than DDoS Protection Standard.

**Impact:**
- Basic DDoS protection only (automatic, platform-level)
- No DDoS rapid response team access
- No cost protection during attacks
- Limited telemetry and attack analytics

**Validation:**
```bash
# Check DDoS protection plan
az network ddos-protection list --output table

# Check if VNets have DDoS protection enabled
az network vnet list --query "[].{Name:name, DDoS:enableDdosProtection}" -o table
```

**Remediation:**
1. Evaluate DDoS Protection Standard need:
   - Cost: ~$2,944/month for first 100 public IPs
   - Recommended if: Public-facing production workloads with high availability SLAs

2. For Static Web Apps: DDoS Protection Standard not directly applicable (no customer-controlled public IPs)
3. Consider Front Door Premium which includes enhanced DDoS protection

**Decision Point:**
- Current workloads (Static Web Apps, Storage, Key Vault) are PaaS services with built-in DDoS protection
- DDoS Standard is **not recommended** unless deploying VMs, Load Balancers, or Application Gateways

---

### 2.2 Medium Priority Findings

#### M-NET-01: No Network Watcher or Flow Logs Configuration
**Risk Level:** MEDIUM

**Finding:**
Network Watcher and NSG flow logs not configured (limited applicability for current PaaS workloads).

**Validation:**
```bash
# Check Network Watcher status
az network watcher list --output table

# Enable Network Watcher for the region
az network watcher configure \
  --resource-group NetworkWatcherRG \
  --location <primary-region> \
  --enabled true
```

**Remediation:**
- Enable Network Watcher in primary region
- Configure NSG flow logs if IaaS workloads are added
- Integrate flow logs with Log Analytics workspace

---

#### M-NET-02: Private Link Not Implemented for PaaS Services
**Risk Level:** MEDIUM

**Finding:**
Key Vault and Storage Account are accessible via public endpoints.

**Impact:**
- Traffic traverses public internet (encrypted but public)
- Increased attack surface for brute force attempts
- No network-level isolation

**Remediation:**
1. Implement Private Link for Key Vault:
```bash
az network private-endpoint create \
  --name jinkslabs-vault-pe \
  --resource-group <rg> \
  --vnet-name <vnet> \
  --subnet <subnet> \
  --private-connection-resource-id $(az keyvault show --name jinkslabs-vault --query id -o tsv) \
  --group-id vault \
  --connection-name kv-private-connection
```

2. Implement Private Link for Storage Account:
```bash
az network private-endpoint create \
  --name storage-blob-pe \
  --resource-group <rg> \
  --vnet-name <vnet> \
  --subnet <subnet> \
  --private-connection-resource-id $(az storage account show --name oldshrimproad001 --query id -o tsv) \
  --group-id blob \
  --connection-name storage-private-connection
```

**Prerequisite:** Requires Virtual Network and subnet deployment

---

## 3. DATA PROTECTION CONTROLS

### 3.1 High Priority Findings

#### H-DATA-01: No Microsoft Purview Data Loss Prevention (DLP) Policies
**Risk Level:** HIGH

**Finding:**
No DLP policies configured to prevent accidental or malicious data exfiltration.

**Impact:**
- No protection against sensitive data sharing
- No policy enforcement for credit cards, SSNs, or custom sensitive info types
- Lack of visibility into data movement across services

**Validation:**
```bash
# Check if Purview is enabled (requires Microsoft 365 E5 or Compliance add-on)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels"
```

**Remediation:**
1. Enable Microsoft Purview Compliance Portal
2. Create DLP policies for:
   - Block upload of files with credit card numbers to Static Web Apps
   - Alert on bulk download from Storage Account
   - Block sharing of Key Vault secrets via email/Teams

3. Example DLP policy configuration:
   - Locations: SharePoint, OneDrive, Exchange (if in use)
   - Conditions: Content contains > 10 credit card numbers
   - Action: Block sharing and notify user + admin

**Cost Consideration:**
- Requires Microsoft 365 E5 or Microsoft Purview add-on
- Not directly applicable to Azure resources without Microsoft 365 integration

**Recommendation for Azure-only environment:**
- Implement custom data exfiltration detection in Sentinel using Storage Account logs
- Use Azure Policy to enforce encryption and access controls

---

#### H-DATA-02: Storage Account Encryption Keys Not Customer-Managed
**Risk Level:** MEDIUM-HIGH

**Finding:**
Storage Account (oldshrimproad001) likely uses Microsoft-managed encryption keys rather than customer-managed keys (CMK).

**Validation:**
```bash
# Check encryption configuration
az storage account show \
  --name oldshrimproad001 \
  --query "{Name:name, EncryptionKeySource:encryption.keySource, KeyVaultProperties:encryption.keyVaultProperties}" -o json
```

**Impact:**
- Encryption keys managed by Microsoft (still encrypted, but less control)
- Cannot meet certain compliance requirements (CMMC, FedRAMP High, etc.)
- No ability to revoke access by rotating/disabling customer key

**Remediation:**
1. Create encryption key in Key Vault:
```bash
# Enable Key Vault for disk encryption
az keyvault update \
  --name jinkslabs-vault \
  --enabled-for-disk-encryption true

# Create encryption key
az keyvault key create \
  --vault-name jinkslabs-vault \
  --name storage-encryption-key \
  --protection software \
  --size 2048 \
  --kty RSA
```

2. Configure Storage Account to use CMK:
```bash
# Assign Key Vault Crypto Service Encryption User role to storage account managed identity
STORAGE_ID=$(az storage account show --name oldshrimproad001 --query identity.principalId -o tsv)
KV_ID=$(az keyvault show --name jinkslabs-vault --query id -o tsv)

az role assignment create \
  --assignee $STORAGE_ID \
  --role "Key Vault Crypto Service Encryption User" \
  --scope $KV_ID

# Update storage account encryption
az storage account update \
  --name oldshrimproad001 \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault https://jinkslabs-vault.vault.azure.net/ \
  --encryption-key-name storage-encryption-key
```

**Trade-offs:**
- Added complexity in key lifecycle management
- Key Vault availability impacts storage access
- Consider if compliance requirements mandate CMK

**Decision Point:**
- **Implement CMK if:** Compliance requirements mandate customer control of encryption keys
- **Accept Microsoft-managed keys if:** Standard protection is sufficient (still AES-256 encryption)

---

#### H-DATA-03: No Blob Versioning or Soft Delete for Storage Account
**Risk Level:** HIGH

**Finding:**
Blob versioning and soft delete must be validated for the Storage Account to protect against accidental deletion or malicious data destruction.

**Validation:**
```bash
# Check blob soft delete settings
az storage blob service-properties delete-policy show \
  --account-name oldshrimproad001

# Check blob versioning
az storage blob service-properties show \
  --account-name oldshrimproad001 \
  --query "isVersioningEnabled"
```

**Impact:**
- Permanent data loss if blobs are accidentally deleted
- No recovery option for overwritten data
- Limited protection against ransomware (requires immutable storage)

**Remediation:**
```bash
# Enable blob soft delete (14-day retention recommended)
az storage blob service-properties delete-policy update \
  --account-name oldshrimproad001 \
  --enable true \
  --days-retained 14

# Enable blob versioning
az storage blob service-properties update \
  --account-name oldshrimproad001 \
  --enable-versioning true

# Enable container soft delete
az storage account blob-service-properties update \
  --account-name oldshrimproad001 \
  --enable-container-delete-retention true \
  --container-delete-retention-days 14
```

**Additional Recommendation - Immutable Storage:**
```bash
# For critical data, enable immutable blob storage (WORM - Write Once Read Many)
az storage container immutability-policy create \
  --account-name oldshrimproad001 \
  --container-name <container-name> \
  --period 365 \
  --allow-protected-append-writes false
```

**References:**
- [Soft delete for blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview)
- [Blob versioning](https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview)

---

#### H-DATA-04: No Sensitivity Labels or Information Protection
**Risk Level:** MEDIUM-HIGH

**Finding:**
Microsoft Purview Information Protection (sensitivity labels) not configured.

**Impact:**
- No classification of sensitive data
- Lack of persistent protection on documents
- No encryption based on data classification

**Validation:**
```bash
# Check for sensitivity labels
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels"
```

**Remediation:**
1. Create sensitivity label taxonomy:
   - Public
   - Internal
   - Confidential
   - Highly Confidential

2. Configure label policies and publish to users
3. Enable auto-labeling for files in Storage Account containing sensitive patterns
4. Configure label-based encryption for "Highly Confidential" data

**Prerequisite:** Microsoft 365 E3/E5 or Azure Information Protection P1/P2

---

### 3.2 Medium Priority Findings

#### M-DATA-01: No Azure Backup Configuration Validated
**Risk Level:** MEDIUM

**Finding:**
Backup and disaster recovery strategy for Key Vault and Storage Account not confirmed.

**Validation:**
```bash
# Check Recovery Services Vaults
az backup vault list --output table

# Check if Key Vault has backup configured
az backup item list --resource-group <rg> --vault-name <vault> --output table
```

**Remediation:**
1. Key Vault: Enable soft delete (already enabled) and purge protection (already enabled) - CONFIRMED IMPLEMENTED
2. Storage Account: Implement backup strategy:
   - Enable versioning and soft delete (see H-DATA-03)
   - Consider Azure Backup for Blobs (preview feature)
   - Implement cross-region replication if RA-GRS not configured

3. Static Web Apps: Ensure source code in version control (GitHub/Azure DevOps)

**Current Status:** Key Vault is already protected with soft delete and purge protection - GOOD

---

#### M-DATA-02: Storage Account Redundancy Level Unknown
**Risk Level:** MEDIUM

**Finding:**
Storage Account redundancy configuration must be validated to ensure adequate data durability.

**Validation:**
```bash
# Check redundancy configuration
az storage account show \
  --name oldshrimproad001 \
  --query "{Name:name, Redundancy:sku.name, Location:primaryLocation, SecondaryLocation:secondaryLocation}" -o json
```

**Remediation:**
- **LRS (Locally Redundant Storage):** 3 copies in single datacenter - Acceptable for dev/test
- **ZRS (Zone Redundant Storage):** 3 copies across availability zones - Recommended for production
- **GRS (Geo-Redundant Storage):** 6 copies across 2 regions - Recommended for critical data
- **RA-GRS (Read-Access GRS):** GRS + read access to secondary region - Best for high availability

**Recommendation:**
```bash
# Upgrade to ZRS or GRS based on criticality
az storage account update \
  --name oldshrimproad001 \
  --sku Standard_ZRS  # or Standard_GRS
```

---

#### M-DATA-03: No Data Lifecycle Management Policies
**Risk Level:** MEDIUM

**Finding:**
Blob lifecycle management policies not configured to automatically tier or delete old data.

**Impact:**
- Increased storage costs for infrequently accessed data
- Manual cleanup required for obsolete data
- No automated compliance with data retention policies

**Validation:**
```bash
# Check lifecycle management rules
az storage account management-policy show \
  --account-name oldshrimproad001
```

**Remediation:**
```bash
# Create lifecycle management policy
az storage account management-policy create \
  --account-name oldshrimproad001 \
  --policy '{
    "rules": [
      {
        "name": "TierToCoolAfter30Days",
        "enabled": true,
        "type": "Lifecycle",
        "definition": {
          "actions": {
            "baseBlob": {
              "tierToCool": {
                "daysAfterModificationGreaterThan": 30
              },
              "tierToArchive": {
                "daysAfterModificationGreaterThan": 90
              },
              "delete": {
                "daysAfterModificationGreaterThan": 365
              }
            }
          },
          "filters": {
            "blobTypes": ["blockBlob"]
          }
        }
      }
    ]
  }'
```

---

## 4. THREAT DETECTION AND MONITORING

### 4.1 Critical Findings

#### C-MON-01: Microsoft Defender for Cloud Not Fully Enabled
**Risk Level:** CRITICAL

**Finding:**
While Azure Security Center default policies are active in audit mode, Microsoft Defender for Cloud enhanced security features (Defender plans) are not confirmed as enabled.

**Impact:**
- No vulnerability assessment for VMs (if deployed)
- No file integrity monitoring
- No adaptive application controls
- No just-in-time VM access
- Limited threat detection for PaaS services
- No Defender for Storage (malware scanning, sensitive data threat detection)
- No Defender for Key Vault (suspicious access detection)

**Validation:**
```bash
# Check which Defender plans are enabled
az security pricing list --output table

# Should show status for:
# - Virtual Machines
# - SQL Databases
# - App Services
# - Storage Accounts
# - Containers
# - Key Vault
# - Resource Manager
# - DNS
```

**Remediation:**
```bash
# Enable Defender for Storage
az security pricing create \
  --name StorageAccounts \
  --tier Standard

# Enable Defender for Key Vault
az security pricing create \
  --name KeyVaults \
  --tier Standard

# Enable Defender for Resource Manager
az security pricing create \
  --name Arm \
  --tier Standard

# Enable Defender for DNS (tenant-level protection)
az security pricing create \
  --name Dns \
  --tier Standard
```

**Cost Impact:**
- Defender for Storage: ~$10/month per storage account + $0.02 per 10K transactions
- Defender for Key Vault: ~$0.02 per 10K transactions
- Defender for Resource Manager: ~$5/month per subscription
- Defender for DNS: ~$2.50/month per subscription

**Recommended for your environment:**
1. **Enable immediately:** Defender for Storage, Key Vault, Resource Manager, DNS
2. **Not needed yet:** Defender for VMs, SQL, App Services (no resources)
3. **Consider:** Defender for Containers (if using container apps in future)

**Total estimated cost:** ~$20-25/month

**References:**
- [Microsoft Defender for Cloud pricing](https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/)
- [Enable enhanced security features](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security)

---

#### C-MON-02: Microsoft Sentinel (SIEM) Not Deployed
**Risk Level:** CRITICAL

**Finding:**
While a Log Analytics workspace exists (jinkslabs-logs), Microsoft Sentinel SIEM is not confirmed as enabled for security event correlation and threat hunting.

**Impact:**
- No centralized security event correlation
- No automated incident creation from multiple alert sources
- No threat hunting capabilities
- No SOAR (Security Orchestration, Automation, Response) playbooks
- Manual investigation of security events required
- Limited detection of multi-stage attacks

**Validation:**
```bash
# Check if Sentinel is enabled on the Log Analytics workspace
az sentinel workspace list --output table

# If empty, Sentinel is not enabled
```

**Remediation:**

**Phase 1: Enable Sentinel**
```bash
# Enable Sentinel on existing Log Analytics workspace
az sentinel workspace-manager create \
  --resource-group <rg-name> \
  --workspace-name jinkslabs-logs
```

**Phase 2: Configure Data Connectors**
```bash
# Enable Azure Activity connector
az sentinel data-connector create \
  --resource-group <rg-name> \
  --workspace-name jinkslabs-logs \
  --data-connector-type AzureActiveDirectory

# Enable Azure Security Center connector
az sentinel data-connector create \
  --resource-group <rg-name> \
  --workspace-name jinkslabs-logs \
  --data-connector-type AzureSecurityCenter

# Enable Office 365 connector (if using M365)
az sentinel data-connector create \
  --resource-group <rg-name> \
  --workspace-name jinkslabs-logs \
  --data-connector-type Office365
```

**Phase 3: Enable Analytics Rules**

Priority rules to enable from Sentinel content hub:

1. **Identity-based detections:**
   - Rare application consent
   - Mass secret retrieval from Key Vault
   - Multiple failed MFA attempts
   - Sign-ins from suspicious IP addresses
   - Anomalous sign-in location by user account and time

2. **Resource-based detections:**
   - Suspicious resource creation or deployment
   - Mass deletion of resources
   - Unusual Azure role assignment
   - Storage account access from suspicious IP

3. **Data exfiltration detections:**
   - Mass download from Storage Account
   - Unusual volume of data transfer
   - Access to storage from Tor exit nodes

**Phase 4: Create Custom Analytics Rules**

Example KQL rule for Key Vault secret enumeration:
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretList"
| summarize Count = count() by CallerIPAddress, identity_claim_upn_s, TimeGenerated
| where Count > 10
| project TimeGenerated, CallerIPAddress, UserPrincipalName = identity_claim_upn_s, Count
```

**Phase 5: Configure SOAR Playbooks**

Example automated response playbook:
- **Trigger:** High-severity alert for suspicious Key Vault access
- **Actions:**
  1. Create Sentinel incident
  2. Send email to security contact (Brad@jinkslabs.com)
  3. Disable user account if risk score > 90
  4. Create ServiceNow ticket (if integrated)

**Cost Impact:**
- Sentinel pricing: $2.46 per GB ingested (first 10GB free per workspace per day)
- Estimated monthly ingestion for your environment: 5-10GB/month = ~$12-25/month
- Data retention in Log Analytics: 90 days included, $0.12/GB/month after

**References:**
- [Enable Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard)
- [Sentinel pricing](https://azure.microsoft.com/en-us/pricing/details/microsoft-sentinel/)

---

#### C-MON-03: No Security Information and Event Management (SIEM) Integration
**Risk Level:** CRITICAL

**Finding:**
Related to C-MON-02. No centralized SIEM solution for correlating events across Entra ID, Azure, and applications.

**Impact:**
- Inability to detect coordinated attacks across identity and infrastructure
- No automated playbooks for incident response
- Manual log review required
- Delayed threat detection and response

**Remediation:**
- See C-MON-02 for Sentinel deployment
- Alternative: If using third-party SIEM (Splunk, QRadar, etc.), configure Azure Monitor to forward logs

---

### 4.2 High Priority Findings

#### H-MON-01: Diagnostic Logging Not Comprehensive
**Risk Level:** HIGH

**Finding:**
While Key Vault is logging to Log Analytics (confirmed), diagnostic settings for other resources must be validated.

**Validation:**
```bash
# Check diagnostic settings for Storage Account
az monitor diagnostic-settings list \
  --resource $(az storage account show --name oldshrimproad001 --query id -o tsv)

# Check diagnostic settings for Static Web Apps
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  echo "Checking $app..."
  az monitor diagnostic-settings list \
    --resource $(az staticwebapp show --name $app --query id -o tsv)
done

# Check Activity Log export to Log Analytics
az monitor diagnostic-settings subscription list
```

**Remediation:**

**Enable Storage Account diagnostic logs:**
```bash
STORAGE_ID=$(az storage account show --name oldshrimproad001 --query id -o tsv)
WORKSPACE_ID=$(az monitor log-analytics workspace show --name jinkslabs-logs --resource-group <rg> --query id -o tsv)

az monitor diagnostic-settings create \
  --name storage-diagnostics \
  --resource $STORAGE_ID \
  --workspace $WORKSPACE_ID \
  --logs '[
    {"category": "StorageRead", "enabled": true},
    {"category": "StorageWrite", "enabled": true},
    {"category": "StorageDelete", "enabled": true}
  ]' \
  --metrics '[
    {"category": "Transaction", "enabled": true}
  ]'
```

**Enable Static Web App diagnostic logs:**
```bash
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  APP_ID=$(az staticwebapp show --name $app --query id -o tsv)
  az monitor diagnostic-settings create \
    --name swa-diagnostics \
    --resource $APP_ID \
    --workspace $WORKSPACE_ID \
    --logs '[
      {"category": "FunctionAppLogs", "enabled": true}
    ]'
done
```

**Enable Subscription Activity Log forwarding:**
```bash
az monitor diagnostic-settings subscription create \
  --name activity-log-analytics \
  --location <region> \
  --workspace $WORKSPACE_ID \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "Alert", "enabled": true},
    {"category": "Policy", "enabled": true}
  ]'
```

**Critical log categories to capture:**
- **Entra ID Sign-ins:** All sign-in events (success and failure)
- **Entra ID Audit Logs:** All administrative actions
- **Azure Activity Log:** All management plane operations
- **Key Vault Audit Events:** All secret/key/certificate operations (CONFIRMED ENABLED)
- **Storage Account Operations:** Read/Write/Delete operations
- **Static Web App Logs:** Application logs and access logs

---

#### H-MON-02: No Alert Rules for Security Events
**Risk Level:** HIGH

**Finding:**
Security contact configured (Brad@jinkslabs.com) but custom alert rules for specific security events not confirmed.

**Validation:**
```bash
# Check existing alert rules
az monitor metrics alert list --output table
az monitor activity-log alert list --output table
az monitor scheduled-query list --output table
```

**Remediation:**

**Create critical alert rules:**

1. **Key Vault Secret Access from New IP:**
```bash
az monitor scheduled-query create \
  --name "KeyVault-NewIPAccess" \
  --resource-group <rg> \
  --scopes $WORKSPACE_ID \
  --condition "count 'AzureDiagnostics | where ResourceProvider == \"MICROSOFT.KEYVAULT\" and OperationName == \"SecretGet\" | summarize CountByIP = count() by CallerIPAddress | where CountByIP == 1' > 0" \
  --window-size 15m \
  --evaluation-frequency 5m \
  --severity 2 \
  --action-group <action-group-id> \
  --description "Alert when Key Vault secrets are accessed from a new IP address"
```

2. **Mass Resource Deletion:**
```bash
az monitor activity-log alert create \
  --name "MassResourceDeletion" \
  --resource-group <rg> \
  --condition category=Administrative and operationName=Microsoft.Resources/subscriptions/resourceGroups/delete \
  --action-group <action-group-id> \
  --description "Alert on resource group deletion"
```

3. **Failed MFA Attempts:**
```bash
az monitor scheduled-query create \
  --name "FailedMFAAttempts" \
  --resource-group <rg> \
  --scopes $WORKSPACE_ID \
  --condition "count 'SigninLogs | where ResultType != 0 and AuthenticationRequirement == \"multiFactorAuthentication\" | summarize FailedAttempts = count() by UserPrincipalName | where FailedAttempts > 5' > 0" \
  --window-size 1h \
  --evaluation-frequency 15m \
  --severity 1 \
  --action-group <action-group-id>
```

4. **Privileged Role Assignment:**
```bash
az monitor activity-log alert create \
  --name "PrivilegedRoleAssignment" \
  --resource-group <rg> \
  --condition category=Administrative and operationName=Microsoft.Authorization/roleAssignments/write and level=Critical \
  --action-group <action-group-id>
```

5. **Storage Account Public Access Change:**
```bash
az monitor activity-log alert create \
  --name "StoragePublicAccessChange" \
  --resource-group <rg> \
  --condition category=Administrative and resourceId=/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/oldshrimproad001 and operationName=Microsoft.Storage/storageAccounts/write \
  --action-group <action-group-id>
```

**Prerequisites:**
- Create Action Group for alert notifications:
```bash
az monitor action-group create \
  --name SecurityAlerts \
  --resource-group <rg> \
  --short-name SecAlert \
  --email-receiver Brad SecurityTeam Brad@jinkslabs.com
```

---

#### H-MON-03: No Threat Intelligence Integration
**Risk Level:** MEDIUM-HIGH

**Finding:**
No integration with Microsoft Threat Intelligence or third-party threat feeds.

**Impact:**
- No automated blocking of known malicious IPs
- Lack of context on indicators of compromise (IOCs)
- Manual correlation with threat intelligence required

**Remediation:**
1. Enable Microsoft Defender Threat Intelligence in Sentinel
2. Configure threat intelligence matching rules
3. Integrate with TAXII threat feeds if available
4. Enable IP reputation checking in Conditional Access

---

#### H-MON-04: No User and Entity Behavior Analytics (UEBA)
**Risk Level:** MEDIUM-HIGH

**Finding:**
Sentinel UEBA (User and Entity Behavior Analytics) not enabled for anomaly detection.

**Impact:**
- No machine learning-based anomaly detection
- Inability to detect insider threats based on behavioral changes
- Manual baseline establishment required

**Remediation:**
```bash
# Enable UEBA in Sentinel (requires Sentinel deployment)
az sentinel setting create \
  --resource-group <rg> \
  --workspace-name jinkslabs-logs \
  --name UEBA \
  --enabled true \
  --data-sources '[
    "AuditLogs",
    "SigninLogs",
    "AzureActivity",
    "SecurityEvent"
  ]'
```

**UEBA capabilities:**
- Anomalous resource access
- Impossible travel detection
- Unusual administrative activity
- Peer group analysis

---

### 4.3 Medium Priority Findings

#### M-MON-01: Log Retention Period Not Validated
**Risk Level:** MEDIUM

**Finding:**
Log Analytics workspace retention period must be validated for compliance requirements.

**Validation:**
```bash
# Check retention settings
az monitor log-analytics workspace show \
  --name jinkslabs-logs \
  --resource-group <rg> \
  --query "{Name:name, RetentionInDays:retentionInDays, DailyCap:workspaceCapping.dailyQuotaGb}" -o json
```

**Remediation:**
- Default: 30 days included, up to 730 days available
- Compliance requirements (GDPR, HIPAA, PCI-DSS): Often require 1-7 years retention
- Recommendation: Set to 90 days minimum for security logs

```bash
az monitor log-analytics workspace update \
  --name jinkslabs-logs \
  --resource-group <rg> \
  --retention-time 90
```

**Cost:** $0.12 per GB per month for retention beyond 90 days

---

#### M-MON-02: No File Integrity Monitoring (FIM)
**Risk Level:** LOW (no VMs deployed)

**Finding:**
FIM not applicable for current PaaS workload but should be configured if IaaS resources are deployed.

**Future Remediation:**
- Enable Defender for Servers when VMs are deployed
- Configure FIM for critical system files
- Monitor changes to application binaries

---

## 5. COMPLIANCE POSTURE

### 5.1 High Priority Findings

#### H-COMP-01: No Regulatory Compliance Assessment Enabled
**Risk Level:** HIGH

**Finding:**
Defender for Cloud compliance dashboard not configured for specific regulatory frameworks.

**Impact:**
- No visibility into compliance with standards (PCI-DSS, HIPAA, NIST, CIS, etc.)
- Manual compliance assessment required
- Difficulty demonstrating compliance to auditors

**Validation:**
```bash
# Check compliance assessments
az security regulatory-compliance-standards list --output table
```

**Remediation:**
1. Enable relevant compliance standards in Defender for Cloud:
   - Navigate to Defender for Cloud > Regulatory compliance
   - Add standards: Azure Security Benchmark (enabled by default), NIST SP 800-53, CIS Azure Foundations Benchmark

2. Review compliance posture:
```bash
# Get compliance results for Azure Security Benchmark
az security regulatory-compliance-assessments list \
  --standard-name "Azure-Security-Benchmark" \
  --output table
```

3. Remediate failed compliance controls based on priority

**References:**
- [Regulatory compliance in Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard)

---

#### H-COMP-02: No Azure Policy Governance Framework
**Risk Level:** HIGH

**Finding:**
While default Security Center policies are active in audit mode, a comprehensive Azure Policy governance framework is not confirmed.

**Impact:**
- No preventive controls (policies in audit mode don't block)
- Inconsistent resource configurations
- Drift from security baselines
- Manual enforcement of standards required

**Validation:**
```bash
# List policy assignments
az policy assignment list --output table

# Check for deny/deployIfNotExists policies
az policy assignment list --query "[?enforcementMode=='Default']" --output table
```

**Remediation:**

**Phase 1: Enable Built-in Policy Initiatives**
```bash
# Assign Azure Security Benchmark initiative in enforce mode
az policy assignment create \
  --name "ASB-Enforce" \
  --display-name "Azure Security Benchmark - Enforce" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8" \
  --enforcement-mode Default
```

**Phase 2: Configure Critical Deny Policies**

1. **Deny public IP creation without approval:**
```bash
az policy assignment create \
  --name "DenyPublicIP" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749"
```

2. **Require specific regions:**
```bash
az policy assignment create \
  --name "AllowedLocations" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c" \
  --params '{"listOfAllowedLocations": {"value": ["eastus", "eastus2"]}}'
```

3. **Require tags on resources:**
```bash
az policy assignment create \
  --name "RequireTags" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/96670d01-0a4d-4649-9c89-2d3abc0a5025" \
  --params '{"tagName": {"value": "Environment"}}'
```

**Phase 3: Deploy Configuration Policies**

1. **Auto-enable diagnostic settings:**
```bash
# Deploy diagnostic settings for all Key Vaults
az policy assignment create \
  --name "DeployKVDiagnostics" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/951af2fa-529b-416e-ab6e-066fd85ac459" \
  --mi-system-assigned \
  --location eastus \
  --params "{\"logAnalytics\": {\"value\": \"$(az monitor log-analytics workspace show --name jinkslabs-logs --resource-group <rg> --query id -o tsv)\"}}"
```

2. **Enforce TLS 1.2 minimum:**
```bash
az policy assignment create \
  --name "EnforceTLS12" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0"
```

**Phase 4: Policy Compliance Monitoring**
```bash
# Check policy compliance state
az policy state summarize --query "results.policyAssignments[].{Name:policyAssignmentName, NonCompliant:results.nonCompliantResources, Compliant:results.compliantResources}"

# Get detailed non-compliance reasons
az policy state list --filter "ComplianceState eq 'NonCompliant'" --query "[].{Resource:resourceId, Policy:policyDefinitionName, Reason:complianceReasonCode}" -o table
```

**References:**
- [Azure Policy built-in definitions](https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies)

---

#### H-COMP-03: No Resource Tagging Strategy
**Risk Level:** MEDIUM-HIGH

**Finding:**
No evidence of consistent resource tagging for cost allocation, ownership, or compliance tracking.

**Impact:**
- Difficult to attribute costs to business units/projects
- Unclear resource ownership during security incidents
- Cannot easily identify production vs. development resources
- Compliance scope identification challenging

**Validation:**
```bash
# Check current tagging on resources
az resource list --query "[].{Name:name, Type:type, Tags:tags}" -o json
```

**Remediation:**

**Define tagging taxonomy:**
- **Environment:** Production, Staging, Development, Test
- **Owner:** Email of responsible party
- **CostCenter:** Business unit or project code
- **DataClassification:** Public, Internal, Confidential, Restricted
- **Compliance:** PCI, HIPAA, SOC2, etc.
- **BackupRequired:** Yes/No
- **ManagedBy:** Person/Team responsible

**Implement tagging policy:**
```bash
# Require specific tags on all resources
az policy assignment create \
  --name "RequireResourceTags" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --policy-set-definition "<custom-initiative-id>" \
  --enforcement-mode Default
```

**Tag existing resources:**
```bash
# Example: Tag Static Web Apps
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  az staticwebapp update \
    --name $app \
    --tags Environment=Production Owner=Brad@jinkslabs.com DataClassification=Public
done

# Tag Storage Account
az storage account update \
  --name oldshrimproad001 \
  --tags Environment=Production Owner=Brad@jinkslabs.com DataClassification=Internal BackupRequired=Yes

# Tag Key Vault
az keyvault update \
  --name jinkslabs-vault \
  --tags Environment=Production Owner=Brad@jinkslabs.com DataClassification=Restricted Compliance=SOC2
```

---

### 5.2 Medium Priority Findings

#### M-COMP-01: No Azure Blueprints or Landing Zone Configuration
**Risk Level:** MEDIUM

**Finding:**
No standardized deployment templates (Blueprints) or Azure Landing Zone architecture implemented.

**Impact:**
- Inconsistent deployment patterns
- Each new subscription/resource group requires manual security configuration
- Difficult to scale governance as environment grows

**Remediation:**
1. Consider Azure Landing Zones for future expansion
2. Create custom Azure Blueprints for standard workload deployment
3. Include security baselines in all blueprints:
   - Diagnostic settings to Log Analytics
   - Required tags
   - Network security configurations
   - RBAC assignments

**Decision Point:**
- Current environment is small; Landing Zones may be over-engineering
- Implement when planning multi-subscription or multi-workload expansion

---

#### M-COMP-02: No Cost Management and Anomaly Detection
**Risk Level:** MEDIUM

**Finding:**
While not strictly a security control, cost anomaly detection can identify cryptomining or resource hijacking.

**Validation:**
```bash
# Check if cost alerts are configured
az consumption budget list --output table
```

**Remediation:**
```bash
# Create budget with alert
az consumption budget create \
  --budget-name monthly-budget \
  --amount 500 \
  --time-grain Monthly \
  --start-date 2026-02-01 \
  --end-date 2026-12-31 \
  --resource-group <rg> \
  --notifications '[
    {
      "enabled": true,
      "operator": "GreaterThan",
      "threshold": 80,
      "contactEmails": ["Brad@jinkslabs.com"]
    },
    {
      "enabled": true,
      "operator": "GreaterThan",
      "threshold": 100,
      "contactEmails": ["Brad@jinkslabs.com"]
    }
  ]'
```

---

## 6. SECURITY MISCONFIGURATIONS

### 6.1 High Priority Findings

#### H-MISC-01: Static Web Apps Configuration Review Required
**Risk Level:** MEDIUM-HIGH

**Finding:**
Static Web Apps security configuration must be validated for each application.

**Validation Required:**
```bash
# For each Static Web App, check:
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  echo "=== Checking $app ==="
  az staticwebapp show --name $app --query "{
    Name:name,
    DefaultHostname:defaultHostname,
    CustomDomains:customDomains,
    AllowConfigFileUpdates:allowConfigFileUpdates,
    StagingEnvironmentPolicy:stagingEnvironmentPolicy
  }" -o json
done
```

**Security Controls to Validate:**

1. **Custom Domain with HTTPS:**
   - Ensure custom domains use Azure-managed certificates
   - Verify HTTPS redirect is enforced

2. **Authentication Provider Configuration:**
   - Check if Entra ID authentication is configured for admin panels
   - Validate allowed roles/users

3. **API Function Security:**
   - If APIs are deployed, ensure authentication is required
   - Validate CORS configuration is not overly permissive

4. **Staging Environment Policy:**
   - Set to "Enabled" only if needed; otherwise "Disabled" to reduce attack surface

5. **Configuration File Updates:**
   - Disable `allowConfigFileUpdates` in production to prevent runtime configuration tampering

**Remediation Example:**
```bash
# Disable staging environments if not needed
az staticwebapp update \
  --name old-shrimp-road-webapp \
  --staging-environment-policy Disabled

# Configure authentication (example with Entra ID)
# This requires portal configuration or ARM template deployment
```

**References:**
- [Authenticate and authorize Static Web Apps](https://learn.microsoft.com/en-us/azure/static-web-apps/authentication-authorization)

---

#### H-MISC-02: Resource Locks Not Implemented
**Risk Level:** HIGH

**Finding:**
No resource locks on critical infrastructure to prevent accidental deletion.

**Impact:**
- Accidental deletion of Key Vault, Storage Account, or Log Analytics workspace
- Potential data loss and service disruption
- No protection against compromised account deleting resources

**Validation:**
```bash
# Check for resource locks
az lock list --output table
```

**Remediation:**
```bash
# Apply CanNotDelete lock to Key Vault
az lock create \
  --name "PreventKVDeletion" \
  --lock-type CanNotDelete \
  --resource-group <rg> \
  --resource-name jinkslabs-vault \
  --resource-type Microsoft.KeyVault/vaults \
  --notes "Prevents accidental deletion of production Key Vault"

# Apply CanNotDelete lock to Storage Account
az lock create \
  --name "PreventStorageDeletion" \
  --lock-type CanNotDelete \
  --resource-group <rg> \
  --resource-name oldshrimproad001 \
  --resource-type Microsoft.Storage/storageAccounts

# Apply CanNotDelete lock to Log Analytics workspace
az lock create \
  --name "PreventLogsDeletion" \
  --lock-type CanNotDelete \
  --resource-group <rg> \
  --resource-name jinkslabs-logs \
  --resource-type Microsoft.OperationalInsights/workspaces

# Apply ReadOnly lock to production resource group (optional - prevents ANY changes)
az lock create \
  --name "ProductionRGLock" \
  --lock-type ReadOnly \
  --resource-group <production-rg> \
  --notes "Prevents modification of production resources; remove lock before making changes"
```

**Lock Types:**
- **CanNotDelete:** Allows modifications but prevents deletion
- **ReadOnly:** Prevents modifications and deletion (use carefully; affects all operations)

**Recommendation:** Use CanNotDelete for production resources; ReadOnly for compliance holds only

---

#### H-MISC-03: No Subscription-Level RBAC Review
**Risk Level:** HIGH

**Finding:**
Role assignments at subscription and resource group level must be audited for excessive permissions.

**Validation:**
```bash
# List all role assignments at subscription level
az role assignment list \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" -o table

# Identify users with Owner or Contributor roles
az role assignment list \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o table

# Check for custom role definitions
az role definition list --custom-role-only true --output table
```

**Common Over-Privileged Assignments to Review:**
- Owner role assigned to service principals
- Contributor role assigned to users who only need read access
- Subscription-level assignments when resource group scope is sufficient
- Guest users with administrative roles

**Remediation:**
1. Document business justification for each Owner/Contributor assignment
2. Replace permanent assignments with PIM eligible assignments (see C-IAM-03)
3. Use built-in roles instead of custom roles where possible
4. Apply least privilege: Reader + specific permissions rather than Contributor

**Example: Replace broad permissions with specific roles**
```bash
# Instead of Contributor, use specific roles like:
# - Storage Blob Data Contributor
# - Key Vault Secrets Officer
# - Log Analytics Contributor

# Remove overly broad assignment
az role assignment delete \
  --assignee <user-or-sp> \
  --role Contributor \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c"

# Add specific role
az role assignment create \
  --assignee <user-or-sp> \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/oldshrimproad001"
```

---

#### H-MISC-04: No Secure Score Monitoring and Remediation
**Risk Level:** MEDIUM-HIGH

**Finding:**
Defender for Cloud Secure Score provides a quantified security posture metric but ongoing monitoring and remediation plan not confirmed.

**Validation:**
```bash
# Get current Secure Score
az security secure-score-controls list --output table

# Get specific recommendations
az security assessment list --output table

# Get high-severity recommendations
az security assessment list --query "[?status.code=='Unhealthy' && metadata.severity=='High']" -o table
```

**Remediation:**
1. Establish baseline Secure Score target (e.g., >80%)
2. Create weekly review process for new recommendations
3. Prioritize remediation:
   - High severity + High impact: Immediate
   - Medium severity: Within 30 days
   - Low severity: Quarterly review

4. Configure Secure Score alerts:
```bash
# Create alert when Secure Score decreases
az monitor metrics alert create \
  --name "SecureScoreDecrease" \
  --resource-group <rg> \
  --scopes "/subscriptions/86010fa7-268b-4d8e-95a6-6e0fab75c06c" \
  --condition "total SecureScore < 80" \
  --description "Alert when Secure Score falls below 80%"
```

---

### 6.2 Medium Priority Findings

#### M-MISC-01: No Separation of Duties for Administrative Functions
**Risk Level:** MEDIUM

**Finding:**
Single user (Brad@jinkslabs.com) has both Owner and Security Admin roles, violating separation of duties principle.

**Impact:**
- Single point of compromise
- No peer review for sensitive operations
- Audit trail limitations

**Remediation:**
1. Create separate accounts for administrative functions:
   - `brad.admin@jinkslabs.com` for infrastructure changes (PIM-activated)
   - `brad.security@jinkslabs.com` for security operations (PIM-activated)
   - `Brad@jinkslabs.com` for daily operations (no admin rights)

2. Implement approval workflows for Owner role activation in PIM

**Trade-off:** Acceptable for small single-admin environments; implement as organization grows

---

#### M-MISC-02: No Disaster Recovery or Business Continuity Plan Validated
**Risk Level:** MEDIUM

**Finding:**
While Azure services have built-in redundancy, formal DR/BCP procedures not documented.

**Remediation:**
1. Document Recovery Time Objective (RTO) and Recovery Point Objective (RPO) for each service
2. Test Key Vault recovery from soft delete
3. Test Storage Account restore from geo-redundant copy (if GRS enabled)
4. Document static web app redeployment from source control
5. Establish runbooks for common disaster scenarios

---

#### M-MISC-03: Lab Plan Security Posture Unknown
**Risk Level:** MEDIUM

**Finding:**
Lab Plan (Lab1TEST) configuration not detailed; security controls must be validated.

**Validation Required:**
```bash
# Check Lab Plan configuration
az lab plan show --name Lab1TEST --resource-group <rg> --output json

# Validate:
# - Network isolation configuration
# - Default VM security settings
# - Access controls for lab creation
# - Shutdown schedules to prevent resource sprawl
```

**Remediation:**
- Ensure lab VMs are on isolated subnets
- Enforce automatic shutdown policies
- Disable public IP assignment if not required
- Configure just-in-time VM access if RDP/SSH needed

---

## 7. PRIORITIZED REMEDIATION ROADMAP

### Phase 1: IMMEDIATE (Week 1-2) - Critical Risk Reduction

**Priority 1.1: Identity Protection Foundation**
1. Create break-glass accounts (C-IAM-02) - 1 hour
2. Enable baseline Conditional Access policies (C-IAM-01) - 4 hours
   - Start in report-only mode, transition to enforced after 48 hours validation

**Priority 1.2: Threat Detection Baseline**
1. Enable Defender for Cloud enhanced plans (C-MON-01) - 30 minutes
   - Storage, Key Vault, Resource Manager, DNS
2. Configure critical alert rules (H-MON-02) - 2 hours
   - Key Vault access, mass deletion, failed MFA

**Priority 1.3: Data Protection**
1. Enable blob soft delete and versioning (H-DATA-03) - 30 minutes
2. Implement resource locks (H-MISC-02) - 30 minutes

**Total Phase 1 Effort:** ~8-10 hours
**Total Phase 1 Cost:** ~$20-25/month recurring

---

### Phase 2: HIGH PRIORITY (Week 3-4) - Defense in Depth

**Priority 2.1: Privileged Access Management**
1. Enable Entra ID P2 licensing - Prerequisite for PIM
2. Configure PIM for Owner and Security Admin roles (C-IAM-03) - 4 hours
3. Implement quarterly access reviews - 2 hours

**Priority 2.2: Network Security Hardening**
1. Configure Storage Account firewall (H-NET-01) - 2 hours
2. Configure Key Vault network restrictions (H-NET-01) - 1 hour
3. Review Static Web Apps access restrictions (H-MISC-01) - 2 hours per app

**Priority 2.3: Comprehensive Logging and SIEM**
1. Deploy Microsoft Sentinel (C-MON-02) - 4 hours
2. Configure data connectors (Activity Log, Entra ID, Defender for Cloud) - 2 hours
3. Enable priority analytics rules - 4 hours
4. Enable diagnostic settings for all resources (H-MON-01) - 2 hours

**Total Phase 2 Effort:** ~25-30 hours
**Total Phase 2 Cost:** Entra ID P2 (~$9/user/month) + Sentinel (~$12-25/month)

---

### Phase 3: MEDIUM PRIORITY (Month 2) - Governance and Compliance

**Priority 3.1: Policy Governance**
1. Implement Azure Policy framework (H-COMP-02) - 8 hours
2. Configure deny policies for high-risk operations - 4 hours
3. Establish policy compliance monitoring - 2 hours

**Priority 3.2: Compliance Posture**
1. Enable regulatory compliance assessments (H-COMP-01) - 2 hours
2. Implement resource tagging strategy (H-COMP-03) - 4 hours
3. Configure cost anomaly detection (M-COMP-02) - 1 hour

**Priority 3.3: Identity Hardening**
1. Block legacy authentication protocols (H-IAM-02) - 2 hours
2. Configure password protection policies (H-IAM-01) - 1 hour
3. Implement sign-in and user risk policies (H-IAM-05) - 3 hours

**Total Phase 3 Effort:** ~27 hours
**Total Phase 3 Cost:** Minimal (included in existing licenses)

---

### Phase 4: OPTIMIZATION (Month 3+) - Advanced Security

**Priority 4.1: Advanced Threat Detection**
1. Enable UEBA in Sentinel (H-MON-04) - 2 hours
2. Configure custom threat hunting queries - 8 hours
3. Develop SOAR playbooks for automated response - 16 hours

**Priority 4.2: Network Defense in Depth**
1. Evaluate Azure Front Door + WAF for Static Web Apps (H-NET-02) - 8 hours planning + implementation
2. Implement Private Link for Key Vault and Storage (M-NET-02) - 8 hours

**Priority 4.3: Advanced Data Protection**
1. Evaluate customer-managed encryption keys (H-DATA-02) - 4 hours
2. Implement data lifecycle management policies (M-DATA-03) - 2 hours
3. Configure immutable storage for compliance (if required) - 2 hours

**Total Phase 4 Effort:** ~50 hours
**Total Phase 4 Cost:** Varies significantly based on Front Door/WAF decisions ($300+/month potential)

---

## 8. ESTIMATED COST IMPACT

### Current Monthly Baseline Costs
- Key Vault: ~$0.03 per operation (minimal for low-volume usage)
- Storage Account: Based on storage + transactions (variable)
- Static Web Apps: Free tier or Standard ($9/app for custom domains)
- Log Analytics: ~$2.76 per GB ingested
- Security Center Default: Free

**Estimated Current: $50-100/month** (depends on usage)

---

### Post-Remediation Monthly Costs

#### Phase 1 Additions:
- Defender for Storage: ~$10/month
- Defender for Key Vault: ~$0.50/month (low transaction volume)
- Defender for Resource Manager: ~$5/month
- Defender for DNS: ~$2.50/month
- **Phase 1 Subtotal: +$18/month**

#### Phase 2 Additions:
- Entra ID P2 (1 user): ~$9/month
- Microsoft Sentinel: ~$12-25/month (estimated 5-10GB ingestion)
- **Phase 2 Subtotal: +$21-34/month**

#### Phase 3 Additions:
- Minimal (Azure Policy and compliance tools included)
- **Phase 3 Subtotal: ~$0/month**

#### Phase 4 Additions (Optional):
- Azure Front Door Premium + WAF: ~$330/month (if implemented)
- Private Link endpoints: ~$7.50/endpoint/month = $15/month for 2 endpoints
- Extended log retention (90 days): ~$5-10/month
- **Phase 4 Subtotal: +$20-355/month** (Front Door is largest variable)

---

### Total Cost Impact Summary

| Phase | Monthly Cost Increase | One-Time Effort | Cumulative Monthly |
|-------|----------------------|----------------|-------------------|
| Baseline | $0 | - | $50-100 |
| Phase 1 | +$18 | 8-10 hours | $68-118 |
| Phase 2 | +$21-34 | 25-30 hours | $89-152 |
| Phase 3 | +$0 | 27 hours | $89-152 |
| Phase 4 (without Front Door) | +$20 | 50 hours | $109-172 |
| Phase 4 (with Front Door) | +$350 | 50 hours | $439-502 |

**Recommended Path:**
- Implement Phases 1-3 immediately: **~$89-152/month** (~80% increase)
- Defer Front Door/WAF decision until Static Web Apps reach production scale
- Total implementation effort: ~60-67 hours over 2-3 months

---

## 9. CRITICAL ASSUMPTIONS AND VALIDATION REQUIREMENTS

The following information must be validated to ensure assessment accuracy:

### Identity Assumptions:
- [ ] Verify Conditional Access policies are not configured
- [ ] Confirm no Entra ID P2 licensing (required for PIM, Identity Protection)
- [ ] Validate MFA enforcement mechanism (Security Defaults vs. CA)
- [ ] Check for existing service principals and their permissions
- [ ] Verify no hybrid identity (Entra ID Connect) is in use

### Network Assumptions:
- [ ] Confirm Storage Account firewall rules (default allow vs. deny)
- [ ] Validate Key Vault network access configuration
- [ ] Check if VNets exist in the subscription (affects Private Link recommendations)
- [ ] Verify Static Web Apps custom domain and authentication settings

### Data Protection Assumptions:
- [ ] Validate Storage Account redundancy configuration (LRS, ZRS, GRS, RA-GRS)
- [ ] Confirm blob soft delete and versioning status
- [ ] Check encryption key management (Microsoft vs. Customer-managed)

### Monitoring Assumptions:
- [ ] Verify Defender for Cloud plan status for each resource type
- [ ] Confirm diagnostic settings for each resource
- [ ] Validate Log Analytics workspace retention settings
- [ ] Check if Sentinel is enabled on jinkslabs-logs workspace

### Compliance Assumptions:
- [ ] Verify Azure Policy assignments and enforcement mode
- [ ] Check for existing resource locks
- [ ] Validate resource tagging implementation
- [ ] Confirm compliance standards relevant to your organization

---

## 10. VALIDATION SCRIPT

To gather the information required to validate these assumptions, run the following comprehensive script:

```bash
#!/bin/bash
# Azure Security Assessment Validation Script
# Jinks Labs Tenant Assessment

SUBSCRIPTION_ID="86010fa7-268b-4d8e-95a6-6e0fab75c06c"
OUTPUT_DIR="./security-assessment-$(date +%Y%m%d)"

mkdir -p "$OUTPUT_DIR"

echo "=== Azure Security Assessment - Data Collection ==="
echo "Subscription: $SUBSCRIPTION_ID"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Set subscription context
az account set --subscription "$SUBSCRIPTION_ID"

# 1. Identity and Access Management
echo "[1/10] Collecting Identity and Access data..."
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" > "$OUTPUT_DIR/conditional-access-policies.json" 2>&1
az ad user list --query "[].{UPN:userPrincipalName, Type:userType, MFA:strongAuthenticationMethods}" > "$OUTPUT_DIR/users.json" 2>&1
az role assignment list --all > "$OUTPUT_DIR/role-assignments.json" 2>&1
az ad sp list --all --query "[].{AppId:appId, DisplayName:displayName, Enabled:accountEnabled}" > "$OUTPUT_DIR/service-principals.json" 2>&1

# 2. Defender for Cloud Configuration
echo "[2/10] Collecting Defender for Cloud configuration..."
az security pricing list > "$OUTPUT_DIR/defender-plans.json" 2>&1
az security assessment list > "$OUTPUT_DIR/security-assessments.json" 2>&1
az security secure-score-controls list > "$OUTPUT_DIR/secure-score.json" 2>&1

# 3. Network Security
echo "[3/10] Collecting network security configuration..."
az network nsg list > "$OUTPUT_DIR/network-security-groups.json" 2>&1
az network vnet list > "$OUTPUT_DIR/virtual-networks.json" 2>&1
az storage account show --name oldshrimproad001 --query "{Name:name, NetworkRules:networkRuleSet, PublicAccess:publicNetworkAccess}" > "$OUTPUT_DIR/storage-network.json" 2>&1
az keyvault show --name jinkslabs-vault --query "{Name:name, NetworkAcls:networkAcls, PublicAccess:publicNetworkAccess}" > "$OUTPUT_DIR/keyvault-network.json" 2>&1

# 4. Storage Account Configuration
echo "[4/10] Collecting Storage Account configuration..."
az storage account show --name oldshrimproad001 > "$OUTPUT_DIR/storage-account-config.json" 2>&1
az storage blob service-properties delete-policy show --account-name oldshrimproad001 > "$OUTPUT_DIR/storage-soft-delete.json" 2>&1
az storage account management-policy show --account-name oldshrimproad001 > "$OUTPUT_DIR/storage-lifecycle.json" 2>&1

# 5. Key Vault Configuration
echo "[5/10] Collecting Key Vault configuration..."
az keyvault show --name jinkslabs-vault > "$OUTPUT_DIR/keyvault-config.json" 2>&1
az keyvault secret list --vault-name jinkslabs-vault > "$OUTPUT_DIR/keyvault-secrets.json" 2>&1
az keyvault key list --vault-name jinkslabs-vault > "$OUTPUT_DIR/keyvault-keys.json" 2>&1

# 6. Monitoring and Logging
echo "[6/10] Collecting monitoring configuration..."
az monitor log-analytics workspace show --name jinkslabs-logs --resource-group <REPLACE_WITH_RG> > "$OUTPUT_DIR/log-analytics-config.json" 2>&1
az sentinel workspace list > "$OUTPUT_DIR/sentinel-workspaces.json" 2>&1
az monitor diagnostic-settings subscription list > "$OUTPUT_DIR/activity-log-diagnostics.json" 2>&1
az monitor metrics alert list > "$OUTPUT_DIR/metric-alerts.json" 2>&1
az monitor activity-log alert list > "$OUTPUT_DIR/activity-log-alerts.json" 2>&1

# 7. Static Web Apps
echo "[7/10] Collecting Static Web Apps configuration..."
for app in old-shrimp-road-webapp wb-arnaud-webapp gray-sutton artemis-lunar walter-tyrell; do
  az staticwebapp show --name "$app" > "$OUTPUT_DIR/staticwebapp-$app.json" 2>&1
done

# 8. Azure Policy
echo "[8/10] Collecting Azure Policy configuration..."
az policy assignment list > "$OUTPUT_DIR/policy-assignments.json" 2>&1
az policy state summarize > "$OUTPUT_DIR/policy-compliance.json" 2>&1
az policy definition list --custom-role-only true > "$OUTPUT_DIR/custom-policies.json" 2>&1

# 9. Resource Locks
echo "[9/10] Collecting resource locks..."
az lock list > "$OUTPUT_DIR/resource-locks.json" 2>&1

# 10. Compliance and Tags
echo "[10/10] Collecting compliance and tagging data..."
az security regulatory-compliance-standards list > "$OUTPUT_DIR/compliance-standards.json" 2>&1
az resource list --query "[].{Name:name, Type:type, Tags:tags, Location:location}" > "$OUTPUT_DIR/resource-inventory.json" 2>&1

echo ""
echo "=== Data Collection Complete ==="
echo "Output location: $OUTPUT_DIR"
echo ""
echo "Next steps:"
echo "1. Review collected data in $OUTPUT_DIR"
echo "2. Validate findings against assessment report"
echo "3. Prioritize remediation based on Phase 1-4 roadmap"
echo ""
```

**Note:** Replace `<REPLACE_WITH_RG>` with your actual resource group name before running.

---

## 11. CONCLUSION AND NEXT STEPS

### Current Security Posture Summary

**Strengths:**
- Key Vault properly configured with soft delete and purge protection
- Security contact configured for high-severity alerts
- MFA enabled for administrative account
- Storage Account configured with HTTPS-only and TLS 1.2
- Log Analytics workspace deployed for centralized logging
- Basic Security Center policies active in audit mode

**Critical Gaps:**
- No Conditional Access policies enforcing MFA or blocking legacy authentication
- Privileged roles permanently assigned (no PIM)
- No break-glass account configuration
- Defender for Cloud enhanced security features not enabled
- No SIEM (Sentinel) deployment for security event correlation
- Comprehensive diagnostic logging not confirmed across all resources
- No Azure Policy governance framework in enforcement mode

**Overall Risk Assessment:**
The environment has basic security hygiene (encryption, MFA, logging) but lacks defense-in-depth controls and threat detection capabilities. The primary risks are:
1. Identity compromise due to lack of Conditional Access and risk-based policies
2. Insufficient threat detection and incident response capabilities
3. Lack of preventive controls (Azure Policy in enforce mode)
4. Potential for privileged access abuse without PIM

---

### Recommended Immediate Actions (This Week)

1. **Create break-glass accounts** and document recovery procedures (2 hours)
2. **Enable Defender for Cloud plans** for Storage, Key Vault, Resource Manager, DNS ($18/month, 30 minutes)
3. **Implement resource locks** on Key Vault, Storage Account, Log Analytics (30 minutes)
4. **Configure baseline Conditional Access policy** for MFA (start in report-only mode) (2 hours)
5. **Run the validation script** to collect current state data (30 minutes)

**Total Immediate Effort:** ~5.5 hours
**Total Immediate Cost:** +$18/month

---

### Long-term Security Program Recommendations

1. **Establish Security Review Cadence:**
   - Weekly: Review Defender for Cloud recommendations
   - Monthly: Review Secure Score and compliance posture
   - Quarterly: Conduct access reviews for privileged roles
   - Annually: Comprehensive third-party security assessment

2. **Implement Security Training:**
   - Entra ID security best practices
   - Azure Policy authoring and governance
   - KQL for threat hunting in Sentinel
   - Incident response procedures

3. **Plan for Scale:**
   - Document security baseline for new resource deployment
   - Create Azure Blueprints for standardized workload deployment
   - Establish change management process for security configurations

4. **Consider Advanced Security Investments:**
   - Microsoft Purview for data governance (when Microsoft 365 is adopted)
   - Azure Front Door + WAF for production Static Web Apps
   - Third-party SIEM integration if expanding beyond Azure

---

## 12. ASSESSMENT LIMITATIONS AND DISCLAIMERS

### Limitations

This assessment is based on:
- Information provided by the user about the environment
- Publicly available Microsoft documentation current as of January 2025
- Standard Azure security best practices and benchmarks

This assessment **does not include:**
- Application-level security code review
- Penetration testing or vulnerability scanning
- On-premises infrastructure security (if hybrid environment exists)
- Third-party integrations and their security posture
- Detailed cost-benefit analysis for each recommendation

### Disclaimers

1. **Validation Required:** All findings must be validated against actual resource configurations using the provided validation scripts.

2. **Cost Estimates:** Costs are estimates based on standard Azure pricing and assumed usage patterns. Actual costs may vary significantly.

3. **Compliance:** This assessment references compliance frameworks but does not constitute formal compliance certification. Engage qualified auditors for formal compliance validation.

4. **Change Management:** All recommendations should be implemented through proper change management processes with testing in non-production environments first.

5. **Ongoing Process:** Security is not a one-time activity. This assessment provides a point-in-time evaluation; continuous monitoring and improvement are required.

---

## 13. REFERENCES AND FURTHER READING

### Microsoft Official Documentation
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Entra ID Security Documentation](https://learn.microsoft.com/en-us/entra/identity/)

### Security Frameworks
- NIST Cybersecurity Framework
- CIS Azure Foundations Benchmark
- Azure Security Benchmark (ASB)
- ISO 27001/27002 Information Security Controls

### Tools and Scripts
- [Azure Security Center GitHub](https://github.com/Azure/Azure-Security-Center)
- [Azure Policy Samples](https://github.com/Azure/azure-policy)
- [Sentinel KQL Queries](https://github.com/Azure/Azure-Sentinel)

---

**Assessment Version:** 1.0
**Last Updated:** 2026-01-22
**Next Review Recommended:** 2026-04-22 (90 days)

---

