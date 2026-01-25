# Microsoft 365 Tenant Security Audit Report
**Jinks Labs (jinkslabs.com)**

**Audit Date:** January 22, 2026
**Tenant ID:** 5a62aa80-bceb-44d3-9879-b4a48deb66de
**Conducted By:** Brad Jinks (Brad@jinkslabs.com)

---

## Executive Summary

This comprehensive review of the Jinks Labs Microsoft 365 tenant reveals a mature deployment with **13 verified domains** and a diverse licensing portfolio including Microsoft 365 Copilot and Information Protection & Governance licenses. While the tenant shows several strengths, including recent implementation of break-glass accounts, there are **critical security gaps** that require immediate attention, particularly around Conditional Access policies and privileged account protection.

### Key Findings

**Strengths:**
- Break-glass accounts properly configured (created Jan 22, 2026)
- Multiple M365 services actively provisioned
- Audit logging enabled and functioning
- Multiple verified custom domains managed

**Critical Concerns:**
- No Conditional Access policies configured
- Break-glass accounts lack licensing (cannot sign in)
- 4 Global Administrators (excessive privileged access)
- No security defaults or MFA enforcement visible
- Guest users with elevated permissions
- Disabled user accounts not removed from directory

---

## 1. Microsoft 365 Licensing and Services

### Current License Inventory

| License SKU | Quantity | Consumed | Key Services |
|-------------|----------|----------|--------------|
| **O365_BUSINESS_PREMIUM** | 3 | 3 | Exchange, SharePoint, Teams, Office Apps |
| **Microsoft_365_Copilot** | 1 | 1 | Copilot for M365, Business Chat, Intelligent Search |
| **M365_INFO_PROTECTION_GOVERNANCE** | 2 | 2 | DLP, Records Management, Defender for Cloud Apps |
| **MICROSOFT_INTUNE_SUITE_FOR_FLW** | 1 | 1 | Intune P2, Remote Help, Cloud PKI |
| **POWER_BI_STANDARD** | 1M | 2 | Power BI Free |
| **FLOW_FREE** | 10K | 2 | Power Automate (viral) |
| **POWERAPPS_DEV** | 10K | 2 | Power Apps Developer (viral) |
| **CCIBOTS_PRIVPREV_VIRAL** | 10K | 1 | Copilot Studio bots (viral) |
| **CPC_B_2C_8RAM_128GB** | 1 | 1 | Windows 365 Cloud PC |
| **WINDOWS_STORE** | 50 | 0 | Windows Store for Business |
| **RMSBASIC** | 1 | 0 | Azure Rights Management Basic |

### Licensed Users

**Actively Licensed:**
- **Brad@jinkslabs.com (William Jinks):** 8 licenses including Copilot, Info Protection, Intune Suite, Business Premium
- **Dawne@gratefuljinks.com:** 6 licenses including Windows 365, Info Protection, Business Premium
- **casey@jinkslabs.com:** 1 license (Business Premium)

**Assessment:**
- Total licensed capacity: 3 Business Premium seats consumed
- Microsoft 365 Copilot deployed to 1 user (Brad)
- Advanced compliance features (DLP, Records Management) available to 2 users
- Multiple viral/free licenses auto-provisioned from Power Platform usage

---

## 2. Microsoft Entra ID (Azure AD) Configuration

### Tenant Overview

- **Tenant Age:** 10+ years (Created April 29, 2015)
- **Directory Quota:** 841 objects used of 300,000 limit (0.3%)
- **On-Premises Sync:** Enabled but not actively syncing
- **Authentication:** Cloud-managed (no hybrid sync detected)

### User Accounts Summary

| Category | Count | Details |
|----------|-------|---------|
| **Total Users** | 17 | Including guest and member accounts |
| **Active Members** | 8 | Enabled internal users |
| **Disabled Members** | 4 | wb@, william@, srenfro@, Gray@ |
| **Guest Users** | 5 | 3 active, 2 disabled |
| **Recently Deleted** | 1 | gray@graysutton.com (deleted Jan 18) |

### Active User Accounts

1. **Brad@jinkslabs.com (William Jinks)** - Global Admin, Primary Account
2. **brad_jinks_hotmail.com#EXT#** - Global Admin (external account in tenant)
3. **breakglass1@jinkslabs.com** - Global Admin (unlicensed)
4. **breakglass2@jinkslabs.com** - Global Admin (unlicensed)
5. **casey@jinkslabs.com** - Regular user
6. **Dawne@gratefuljinks.com** - Regular user
7. **efitz@jinkslabs.com (Edward Fitzgerald)** - Regular user
8. **Information@jinkslabs.com** - Service mailbox
9. **lfitz@jinkslabs.com (Lorraine Fitzgerald)** - Regular user

### Guest Users

**Active Guests:**
- bjinx27_hotmail.com#EXT# (created Dec 16, 2025)
- mmcpherson_countyems.org#EXT# (created Jan 4, 2026)
- ccblanchard_gmail.com#EXT# (created Jan 4, 2026)

**Disabled Guests:**
- swilliams_samdwilliams.com#EXT# (inactive since 2020)
- josh_SoldInTheKeys.com#EXT# (inactive since 2016)

### Administrative Roles

**Global Administrators (4 total):**
1. Brad@jinkslabs.com (William Jinks)
2. brad_jinks_hotmail.com#EXT# (Brad Jinks - external account)
3. breakglass1@jinkslabs.com
4. breakglass2@jinkslabs.com

**Other Activated Roles:**
- Directory Readers
- Authentication Policy Administrator
- Azure AD Joined Device Local Administrator
- Helpdesk Administrator

### Authorization Policy Settings

- **Guest invite permissions:** Everyone can invite
- **Email verified users can join:** Enabled (self-service signup)
- **Users can create apps:** Yes
- **Users can create security groups:** Yes
- **Users can create tenants:** Yes
- **Guest role restrictions:** Restricted access (10dae51f-b6af-4016-8d66-8c2a99b929b3)

---

## 3. Security Configuration

### Conditional Access Policies

**Status:** NONE CONFIGURED

This is a critical security gap. No policies are enforcing:
- MFA requirements
- Device compliance
- Location-based access controls
- App protection
- Risk-based authentication

### Security Defaults

**Unable to verify status** due to API permissions, but given the lack of Conditional Access policies, Security Defaults may be disabled or not enforced.

### MFA Status

- **Primary User (Brad@jinkslabs.com):** MFA reported as enabled
- **Other Users:** Status could not be verified due to lack of Azure AD Premium P1/P2 license required for reporting APIs
- **Break-glass accounts:** No MFA (by design for emergency access)

### Recent Security-Related Audit Events

**Jan 22, 2026 - Break-glass Account Setup:**
- 17:41:27 UTC: breakglass1@jinkslabs.com created
- 17:41:43 UTC: breakglass2@jinkslabs.com created
- 17:42:08-09 UTC: Both accounts assigned Global Administrator role
- Initiated by: Brad@jinkslabs.com from IP 129.222.0.219

### Application Registrations

6 registered applications found:
- ChatGPT Integration (Oct 2025)
- Jinks-PnP-Interactive (Oct 2025)
- PnP Prompt Library Provisioner (Oct 2025)
- Copilot 1 (Power Virtual Agents) (Dec 2023)
- Linkedin (Oct 2022)
- P2P Server (Feb 2018)

**Assessment:** Review application permissions and service principals to ensure least-privilege access.

---

## 4. Domain Configuration

### Verified Domains (13 total)

| Domain | Default | Initial | Services | Status |
|--------|---------|---------|----------|--------|
| **jinkslabs.com** | Yes | No | Email, Teams, Auth | Verified |
| jinkslabs.onmicrosoft.com | No | Yes | Email, Teams | Verified |
| tyrelltales.com | No | No | Email, Teams, Intune | Verified |
| gratefuljinks.com | No | No | Email, Teams, Intune | Verified |
| ancestralinvestigation.com | No | No | Email, Teams, Intune | Verified |
| mvannieoshea.com | No | No | Email, Teams, Intune | Verified |
| wbarnaud.com | No | No | Email, Teams, Intune | Verified |
| oldshrimproad.com | No | No | Email, Teams, Intune | Verified |
| oldshrimproad.press | No | No | Email, Teams, Intune | Verified |
| readersplace.org | No | No | Email, Teams, Intune | Verified |
| graysutton.com | No | No | Email, Intune | Verified |
| discendenza.com | No | No | Email, Intune | Verified |
| jinkslabs.mail.onmicrosoft.com | No | No | - | Verified |

**Password Policy:**
- Notification window: 14 days before expiration
- Validity period: 2147483647 days (essentially never expire)

---

## 5. Exchange Online Configuration

### Service Status

- **Exchange Online Standard** provisioned and enabled
- **Service Principal:** Office 365 Exchange Online active
- Multiple mail-enabled domains configured

### Mail Flow Architecture

Based on domain configuration, the following domains support email:
- Primary: jinkslabs.com
- Additional: tyrelltales.com, gratefuljinks.com, ancestralinvestigation.com, mvannieoshea.com, wbarnaud.com, oldshrimproad.com, oldshrimproad.press, readersplace.org, graysutton.com, discendenza.com

### Exchange Features Available

From assigned service plans:
- Exchange Online Protection
- Data Loss Prevention (M365 Info Protection license)
- Premium Encryption
- Information Governance
- Customer Key capability
- Microsoft Purview Audit Platform
- Records Management

### Groups and Distribution Lists

**15 groups identified:**
- **Microsoft 365 Groups (Unified):** 8 groups
  - Enterprise Architecture Playbook (Jan 2026)
  - Gray Sutton (Jan 2026)
  - William Jinks (Oct 2025)
  - W.B. Arnaud (Oct 2025)
  - Annie O'Shea (Mar 2024)
  - Consulting (Feb 2024)
  - Project Italia (Jun 2023)
  - Jinks Home (Sep 2021)
  - Office 365 Technical (Jan 2020)
  - All Company (May 2020)

- **Distribution Groups:** 3 groups
  - Test1, Test2, test3 (Mar 2023)

- **Security Groups:** 2 groups
  - SecTest (mail-enabled security group)
  - test (security only)

**Assessment:** Unable to access Exchange admin endpoints directly via Graph API without additional permissions. Recommend checking:
- Mail flow rules
- Anti-spam/anti-malware policies
- Safe Links/Safe Attachments (if Defender for Office 365 licensed)
- Accepted domains and connectors
- Mailbox retention policies

---

## 6. SharePoint Online and OneDrive

### Service Status

SharePoint Online services provisioned:
- SharePoint Standard (SHAREPOINTSTANDARD)
- SharePoint WAC (Web Application Companion - Office Online)
- Nucleus (SharePoint framework)
- Microsoft Loop
- Clipchamp (video editor)

### SharePoint Features Available

- Microsoft 365 Groups integration (Teams-connected sites)
- OneDrive for Business
- Co-authoring and real-time collaboration
- Microsoft Loop components
- Viva Engage (Yammer) integration

### OneDrive Configuration

Based on Business Premium licenses, OneDrive is available to:
- Brad@jinkslabs.com (1TB+)
- Dawne@gratefuljinks.com (1TB+)
- casey@jinkslabs.com (1TB+)

**Assessment:** Unable to retrieve SharePoint tenant settings via Graph API due to permission restrictions. Recommend checking:
- External sharing settings (Anyone links, Guest access)
- Default storage quotas
- Site creation permissions
- Sync client restrictions
- Information barriers

---

## 7. Microsoft Teams Configuration

### Service Status

Teams services provisioned:
- Teams (TEAMS1)
- Microsoft Communications Online (MCOSTANDARD)
- Microsoft 365 Copilot for Teams (M365_COPILOT_TEAMS)
- Mesh avatars for Teams
- Meeting features (Bookings, Forms integration)

### Teams Features Available

- Team collaboration with M365 Groups
- Meetings and calling
- Power Platform integration (Power Virtual Agents, Forms)
- Viva Learning (seeded)
- Copilot in Teams (for Brad@jinkslabs.com)

### Teams-Connected Groups

Based on Microsoft 365 Groups, at least 8 Teams may exist:
- Enterprise Architecture Playbook
- Gray Sutton
- William Jinks
- W.B. Arnaud
- Annie O'Shea
- Consulting
- Project Italia
- Jinks Home

**Assessment:** Unable to access Teams admin settings directly. Recommend reviewing:
- Guest access policies
- Meeting policies (anonymous join, recording, transcription)
- Messaging policies
- App permission policies
- External access (federation)
- Data loss prevention integration

---

## 8. Security and Compliance (Microsoft Purview)

### Microsoft Purview Services Enabled

From M365 Info Protection & Governance licenses (2 users):

**Data Loss Prevention:**
- Endpoint DLP (MICROSOFTENDPOINTDLP)
- Communications DLP (COMMUNICATIONS_DLP)
- MIP for Exchange (MIP_S_Exchange)

**Information Protection:**
- Advanced Information Protection (MIP_S_CLP2)
- Azure Information Rights Management Premium 2 (RMS_S_PREMIUM2)
- Premium Encryption

**Records Management:**
- Records Management (RECORDS_MANAGEMENT)
- Information Governance (INFO_GOVERNANCE)

**Advanced Compliance:**
- Machine Learning Classification (ML_CLASSIFICATION)
- Microsoft Defender for Cloud Apps (ADALLOM_S_STANDALONE)
- Content Explorer
- Microsoft Purview Audit Platform (M365_AUDIT_PLATFORM)
- Purview Discovery

**Data Security:**
- Customer Key capability (tenant-managed encryption keys)

### Audit Logging

**Status:** ENABLED

Recent audit events successfully retrieved, including:
- Role assignment changes
- User creation events
- Administrative actions

**Retention:** Based on licensing, audit log retention is available but specific retention policies not verified.

### Compliance Policies Status

**Unable to verify the following due to API permissions:**
- Active DLP policies
- Retention policies and labels
- Sensitivity labels
- eDiscovery cases
- Insider Risk Management policies
- Communication Compliance policies

**Recommendation:** Access Microsoft Purview compliance portal directly at https://compliance.microsoft.com to review:
1. Data Loss Prevention policies
2. Retention policies (Exchange, SharePoint, OneDrive, Teams)
3. Sensitivity labels configuration
4. Alert policies
5. Content search and eDiscovery setup

---

## 9. Microsoft Defender and Security Services

### Defender for Cloud Apps

**Status:** ENABLED (via M365 Info Protection license)
- Service Plan: ADALLOM_S_STANDALONE
- Available to: Brad@jinkslabs.com, Dawne@gratefuljinks.com

### Other Security Services

- **Windows Security:** Windows 10 ESU (extended security updates)
- **Intune Suite:** Advanced endpoint analytics, Remote Help, Cloud PKI, 3rd-party app patching
- **Microsoft Secure Score:** Unable to retrieve (insufficient permissions)

### Security Monitoring

**Audit Log Access:** Functioning
**Security Alerts:** Unable to retrieve recent alerts (requires SecurityAlert.Read.All scope)

**Recommendation:** Enable and configure:
1. Microsoft Defender for Office 365 (not currently licensed)
2. Microsoft Defender for Endpoint (available in Intune Suite)
3. Alert policies in compliance portal
4. Automated investigation and response

---

## 10. Critical Security Concerns

### HIGH PRIORITY

#### 1. No Conditional Access Policies Configured
**Risk Level:** CRITICAL

**Finding:** Zero Conditional Access policies are deployed, meaning:
- No enforced MFA for privileged accounts
- No location-based restrictions
- No device compliance requirements
- No app protection policies
- No session controls

**Impact:** Any compromised credential can access the entire tenant from anywhere, on any device.

**Recommendation:**
Implement Conditional Access policies immediately:

**Policy 1: Require MFA for Administrators**
- Users: All admin roles
- Conditions: All cloud apps
- Grant: Require MFA
- State: Report-only → Enabled after testing

**Policy 2: Block Legacy Authentication**
- Users: All users (exclude break-glass)
- Conditions: Legacy authentication clients
- Grant: Block access
- State: Enabled

**Policy 3: Require Compliant Devices for Privileged Access**
- Users: All admin roles
- Conditions: All cloud apps
- Grant: Require device compliance OR hybrid Azure AD joined device
- State: Report-only → Enabled after testing

**Policy 4: Require MFA for All Users**
- Users: All users (exclude break-glass)
- Conditions: All cloud apps
- Grant: Require MFA
- Exclusions: Break-glass accounts
- State: Report-only → Enabled after testing

**Required License:** Azure AD Premium P1 (included in Microsoft 365 Business Premium)

---

#### 2. Break-Glass Accounts Not Licensed
**Risk Level:** HIGH

**Finding:**
- breakglass1@jinkslabs.com - No licenses assigned
- breakglass2@jinkslabs.com - No licenses assigned

**Impact:** These accounts cannot sign in to perform emergency administrative tasks because they lack Exchange Online or other service licenses required for authentication.

**Recommendation:**
1. Assign at least Microsoft 365 Business Basic or Business Premium licenses to both break-glass accounts
2. Test sign-in capability immediately
3. Store credentials in secure vault (Azure Key Vault or physical safe)
4. Exclude from all Conditional Access policies
5. Monitor for any usage via alerts
6. Document break-glass procedures

**Action Required:** Assign licenses within 24 hours.

---

#### 3. Excessive Global Administrator Assignments
**Risk Level:** HIGH

**Finding:** 4 Global Administrator accounts detected:
1. Brad@jinkslabs.com (justified - primary admin)
2. brad_jinks_hotmail.com#EXT# (external account - questionable)
3. breakglass1@jinkslabs.com (emergency access - justified)
4. breakglass2@jinkslabs.com (emergency access - justified)

**Impact:**
- External account (brad_jinks_hotmail.com) with Global Admin is a security risk
- No Privileged Identity Management (PIM) for time-limited access
- Permanent elevation increases attack surface

**Recommendation:**
1. Remove Global Admin from brad_jinks_hotmail.com#EXT# account
2. Consider removing this external account entirely
3. Implement Azure AD Privileged Identity Management (requires P2)
4. Use just-in-time admin access for day-to-day operations
5. Assign least-privilege admin roles (Exchange Admin, SharePoint Admin, etc.) instead of Global Admin

**Best Practice:** Maximum 2 break-glass accounts + 1-2 active admins using PIM.

---

### MEDIUM PRIORITY

#### 4. Guest User Account Hygiene
**Risk Level:** MEDIUM

**Finding:**
- 2 disabled guest accounts from 2016 and 2020 still in directory
- 3 active guest users with unknown permission levels
- Guest invite setting: "Everyone can invite"

**Impact:**
- Stale accounts increase attack surface
- Uncontrolled guest invitations can lead to data leakage
- Guest permissions not verified

**Recommendation:**
1. Remove disabled guest accounts: swilliams_samdwilliams.com#EXT#, josh_SoldInTheKeys.com#EXT#
2. Review active guest permissions:
   - bjinx27_hotmail.com#EXT#
   - mmcpherson_countyems.org#EXT#
   - ccblanchard_gmail.com#EXT#
3. Change authorization policy: Restrict guest invites to admins or specific roles
4. Implement guest user access reviews (requires Azure AD Premium P2)
5. Set guest account expiration policies

---

#### 5. Disabled User Accounts Retention
**Risk Level:** MEDIUM

**Finding:** 4 disabled member accounts still in directory:
- wb@jinkslabs.com (disabled Nov 2025)
- william@jinkslabs.com (disabled Nov 2025)
- srenfro@jinkslabs.com (disabled Jan 2026)
- Gray@jinkslabs.com (disabled Jan 2026)

**Impact:**
- Licenses may be consumed
- Mailbox/OneDrive data retention unclear
- Compliance and legal hold implications

**Recommendation:**
1. Review each account for data retention requirements
2. Export/archive mailbox and OneDrive data if needed
3. Remove accounts or convert to shared mailboxes if required
4. Implement offboarding workflow with defined retention period

---

#### 6. On-Premises Sync Enabled But Not Active
**Risk Level:** LOW-MEDIUM

**Finding:** Organization shows "onPremisesSyncEnabled: true" but no users are syncing from on-premises directory.

**Impact:**
- Configuration drift
- Potential for unauthorized sync if connector reactivated
- Unclear hybrid identity posture

**Recommendation:**
1. Verify if Azure AD Connect is installed anywhere
2. If not in use, disable hybrid sync setting
3. If in use, verify sync health and connector security
4. Document hybrid architecture if intentional

---

### LOW PRIORITY

#### 7. Technical Notification Email Uses External Address
**Risk Level:** LOW

**Finding:** Technical notifications go to brad_jinks@hotmail.com (external email)

**Impact:**
- Service health alerts may be missed
- Password reset notifications sent outside organization

**Recommendation:** Change to Brad@jinkslabs.com (internal account)

---

#### 8. Security Compliance Notification Emails Not Configured
**Risk Level:** LOW

**Finding:** securityComplianceNotificationMails is empty array

**Impact:** Security and compliance alerts not being sent to designated recipients

**Recommendation:** Configure security notification emails in Microsoft 365 admin center to ensure awareness of compliance issues.

---

## 11. Recommendations Summary

### Immediate Actions (0-7 days)

**Priority 1: Conditional Access**
- [ ] Create CA policy: Require MFA for all administrators
- [ ] Create CA policy: Block legacy authentication
- [ ] Test policies in Report-Only mode
- [ ] Enable policies for production

**Priority 2: Break-Glass Accounts**
- [ ] Assign Microsoft 365 licenses to breakglass1@ and breakglass2@
- [ ] Test sign-in capability
- [ ] Exclude from Conditional Access policies
- [ ] Document emergency access procedures
- [ ] Store credentials in secure vault

**Priority 3: Global Administrator Cleanup**
- [ ] Review necessity of brad_jinks_hotmail.com#EXT# as Global Admin
- [ ] Remove Global Admin or delete account if not needed
- [ ] Document remaining admin accounts

### Short-Term Actions (7-30 days)

**Identity and Access:**
- [ ] Review and remove disabled user accounts
- [ ] Remove stale guest accounts
- [ ] Implement guest access reviews
- [ ] Restrict guest invitation permissions
- [ ] Verify MFA enrollment for all active users

**Compliance and Data Protection:**
- [ ] Review DLP policies in Purview portal
- [ ] Configure retention policies for Exchange, SharePoint, Teams
- [ ] Implement sensitivity labels
- [ ] Enable alert policies for suspicious activity

**Monitoring and Visibility:**
- [ ] Configure security notification emails
- [ ] Review Microsoft Secure Score recommendations
- [ ] Enable Cloud App Security monitoring
- [ ] Configure alert rules for privileged role changes

### Long-Term Improvements (30-90 days)

**Advanced Security:**
- [ ] Implement Azure AD Privileged Identity Management (requires P2)
- [ ] Deploy additional Conditional Access policies (location-based, device compliance)
- [ ] Consider Microsoft Defender for Office 365 (Plan 1 or 2)
- [ ] Implement Insider Risk Management

**Governance:**
- [ ] Establish Azure AD access reviews for privileged roles
- [ ] Document admin role assignment procedures
- [ ] Create offboarding workflow for users
- [ ] Implement guest user lifecycle management

**Application Security:**
- [ ] Review application registrations and permissions
- [ ] Implement app consent policies
- [ ] Audit service principal permissions

---

## 12. Licensing Gaps and Opportunities

### Current State
- Microsoft 365 Business Premium: Core productivity and security
- Microsoft 365 Copilot: AI-powered productivity (1 user)
- M365 Info Protection & Governance: Advanced compliance (2 users)
- Intune Suite: Advanced endpoint management (1 user)

### Identified Gaps

**Azure AD Premium P1 Features (Included in Business Premium - verify usage):**
- Conditional Access (not deployed)
- Self-service group management
- Dynamic groups
- Cloud app discovery

**Azure AD Premium P2 Features (Not licensed):**
- Privileged Identity Management
- Azure AD Identity Protection
- Access Reviews

**Microsoft Defender for Office 365 (Not licensed):**
- Safe Links
- Safe Attachments
- Anti-phishing policies
- Advanced threat protection

**Recommendation:**
- Verify Business Premium includes Azure AD Premium P1 (should be included)
- Consider Azure AD Premium P2 for PIM and Identity Protection
- Evaluate Defender for Office 365 Plan 1 for email security

---

## Conclusion

The Jinks Labs Microsoft 365 tenant demonstrates a solid foundation with diverse licensing and recent security improvements (break-glass accounts). However, critical security controls are not deployed, particularly Conditional Access policies, which leaves the tenant vulnerable to credential-based attacks.

The immediate priority is implementing Conditional Access policies to enforce MFA and modern authentication, followed by licensing the break-glass accounts and reducing Global Administrator assignments.

With these corrections, the tenant will align with Microsoft security best practices and significantly reduce identity-based risk.

---

## Appendices

### Appendix A: API Limitations Encountered

The following information could not be retrieved due to Azure CLI permissions or licensing restrictions:

1. Security Defaults enforcement status (AccessDenied)
2. User MFA registration details (Premium license required)
3. Sign-in logs (Premium license required)
4. Microsoft Secure Score (insufficient permissions)
5. Security alerts (SecurityAlert.Read.All scope required)
6. SharePoint tenant settings (admin API access required)
7. Exchange Online admin settings (PowerShell or admin center required)
8. Authentication methods per user (access denied)
9. Service health issues (permission denied)

**Recommendation:** Re-run portions of this audit using:
- Microsoft 365 Admin Center (https://admin.microsoft.com)
- Azure AD Admin Center (https://aad.portal.azure.com)
- Microsoft Purview Compliance Portal (https://compliance.microsoft.com)
- Exchange Admin Center (https://admin.exchange.microsoft.com)
- SharePoint Admin Center (https://admin.microsoft.com/sharepoint)

### Appendix B: Domains and DNS

All 13 domains are verified and managed. Confirm DNS records on each domain include:
- MX records pointing to *.mail.protection.outlook.com
- SPF records authorizing Microsoft 365
- DKIM selectors configured
- DMARC policy published

Based on prior knowledge, tyrelltales.com is properly configured. Verify remaining 12 domains.

### Appendix C: Service Plan Reference

Key service plan IDs encountered in this audit:

- **Microsoft 365 Copilot:** 639dec6b-bb19-468b-871c-c5c441c4b0cb
- **M365 Info Protection & Governance:** 2bc9d149-a1dc-4d8f-bcd8-e9c5750a59b5
- **M365 Business Premium:** f245ecc8-75af-4f8e-b61f-27d8114de5f3
- **Intune Suite FLW:** 74692dbc-34aa-41db-b4eb-15e374fcb0e6
- **Windows 365 Cloud PC:** 71f21848-f89b-4aaa-a2dc-780c8e8aac5b

Full service plan documentation: https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

---

**Report Generated:** 2026-01-22 18:30 UTC
**Next Review Recommended:** 2026-04-22 (90 days)
