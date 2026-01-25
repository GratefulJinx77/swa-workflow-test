# Azure Security Remediation Tracker - Jinks Labs

**Tenant:** jinkslabs.com (5a62aa80-bceb-44d3-9879-b4a48deb66de)
**Assessment Date:** 2026-01-22
**Owner:** Brad Jinks (Brad@jinkslabs.com)

---

## How to Use This Tracker

1. Mark tasks with `[x]` when completed
2. Add completion date in the "Completed" column
3. Note any deviations or issues in the "Notes" column
4. Update status weekly during implementation

---

## PHASE 1: IMMEDIATE ACTIONS (Week 1-2)

**Goal:** Reduce critical risk exposure
**Estimated Effort:** 8-10 hours
**Estimated Cost Impact:** +$18/month

### Priority 1.1: Identity Protection Foundation

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Generate and securely store break-glass account passwords | [ ] | | |
| Create breakglass01@jinkslabs.com account | [ ] | | |
| Create breakglass02@jinkslabs.com account | [ ] | | |
| Assign Global Administrator role to both accounts | [ ] | | |
| Test authentication with break-glass accounts | [ ] | | |
| Document break-glass account recovery procedure | [ ] | | |
| Store credentials in physical safe / offline password manager | [ ] | | |
| Create CA-001: Require MFA for All Users (report-only) | [ ] | | |
| Create CA-002: Require MFA for Azure Management (report-only) | [ ] | | |
| Create CA-003: Block Legacy Authentication (report-only) | [ ] | | |
| Exclude break-glass accounts from all CA policies | [ ] | | |
| Monitor CA policies in report-only mode for 48 hours | [ ] | | |
| Switch CA policies from report-only to enabled | [ ] | | |

**Phase 1.1 Completion Date:** _______________

---

### Priority 1.2: Threat Detection Baseline

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Enable Defender for Storage (Standard tier) | [ ] | | |
| Enable Defender for Key Vault (Standard tier) | [ ] | | |
| Enable Defender for Resource Manager (Standard tier) | [ ] | | |
| Enable Defender for DNS (Standard tier) | [ ] | | |
| Verify all Defender plans are active | [ ] | | |
| Create Action Group: SecurityAlerts | [ ] | | |
| Configure alert: Break-Glass Account Usage | [ ] | | |
| Configure alert: Resource Deletion | [ ] | | |
| Configure alert: Privileged Role Assignment | [ ] | | |
| Test Action Group email delivery | [ ] | | |

**Phase 1.2 Completion Date:** _______________

---

### Priority 1.3: Data Protection

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Enable blob soft delete (14-day retention) | [ ] | | |
| Enable blob versioning | [ ] | | |
| Enable container soft delete (14-day retention) | [ ] | | |
| Test blob soft delete recovery | [ ] | | |
| Apply CanNotDelete lock to Key Vault | [ ] | | |
| Apply CanNotDelete lock to Storage Account | [ ] | | |
| Apply CanNotDelete lock to Log Analytics workspace | [ ] | | |
| Verify all resource locks are active | [ ] | | |

**Phase 1.3 Completion Date:** _______________

---

### Priority 1.4: Network Security Hardening (Optional - May Impact Access)

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Document current public IP address | [ ] | | IP: _____________ |
| Configure Storage Account firewall (default: Deny) | [ ] | | |
| Add authorized IP to Storage Account | [ ] | | |
| Enable Azure Services bypass for Storage Account | [ ] | | |
| Test Storage Account access after firewall config | [ ] | | |
| Configure Key Vault firewall (default: Deny) | [ ] | | |
| Add authorized IP to Key Vault | [ ] | | |
| Test Key Vault access after firewall config | [ ] | | |

**Phase 1.4 Completion Date:** _______________

---

**PHASE 1 OVERALL STATUS:**
- [ ] All Phase 1 tasks completed
- [ ] Validation script run and results reviewed
- [ ] Secure Score improvement documented: Before: _____ After: _____
- [ ] Cost tracking confirmed: Expected $18/month, Actual: $_____

**Phase 1 Completion Date:** _______________

---

## PHASE 2: HIGH PRIORITY (Week 3-4)

**Goal:** Implement defense-in-depth and comprehensive monitoring
**Estimated Effort:** 25-30 hours
**Estimated Cost Impact:** +$21-34/month

### Priority 2.1: Privileged Access Management

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Purchase Entra ID P2 license | [ ] | | Cost: ~$9/user/month |
| Assign Entra ID P2 license to Brad@jinkslabs.com | [ ] | | |
| Enable PIM for Azure Resources | [ ] | | |
| Configure PIM settings for Owner role | [ ] | | |
| - Set activation duration: 8 hours | [ ] | | |
| - Require MFA for activation | [ ] | | |
| - Require justification | [ ] | | |
| - Enable approval workflow (optional) | [ ] | | |
| Configure PIM settings for Security Admin role | [ ] | | |
| Convert Owner assignment to eligible (not permanent) | [ ] | | |
| Convert Security Admin to eligible (not permanent) | [ ] | | |
| Test PIM activation workflow | [ ] | | |
| Create quarterly access review for privileged roles | [ ] | | |
| Document PIM emergency access procedure | [ ] | | |

**Phase 2.1 Completion Date:** _______________

---

### Priority 2.2: Network Security Hardening (Advanced)

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Review Static Web Apps security configuration | [ ] | | |
| - old-shrimp-road-webapp | [ ] | | |
| - wb-arnaud-webapp | [ ] | | |
| - gray-sutton | [ ] | | |
| - artemis-lunar | [ ] | | |
| - walter-tyrell | [ ] | | |
| Disable staging environments (if not needed) | [ ] | | |
| Configure custom domains with managed certificates | [ ] | | |
| Enable authentication providers (if applicable) | [ ] | | |
| Evaluate Azure Front Door + WAF requirement | [ ] | | Decision: ____________ |

**Phase 2.2 Completion Date:** _______________

---

### Priority 2.3: Comprehensive Logging and SIEM

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Enable Microsoft Sentinel on jinkslabs-logs workspace | [ ] | | |
| Configure data connector: Azure Activity | [ ] | | |
| Configure data connector: Entra ID Sign-ins | [ ] | | |
| Configure data connector: Entra ID Audit Logs | [ ] | | |
| Configure data connector: Defender for Cloud | [ ] | | |
| Enable diagnostic settings: Storage Account | [ ] | | |
| Enable diagnostic settings: All Static Web Apps | [ ] | | |
| Enable diagnostic settings: Subscription Activity Log | [ ] | | |
| Verify Key Vault logging (already enabled) | [ ] | | |
| Enable priority analytics rules (identity-based) | [ ] | | |
| - Rare application consent | [ ] | | |
| - Mass secret retrieval from Key Vault | [ ] | | |
| - Multiple failed MFA attempts | [ ] | | |
| - Sign-ins from suspicious IPs | [ ] | | |
| Enable priority analytics rules (resource-based) | [ ] | | |
| - Suspicious resource creation | [ ] | | |
| - Mass deletion of resources | [ ] | | |
| - Unusual role assignment | [ ] | | |
| Create custom KQL query: Key Vault enumeration | [ ] | | |
| Test Sentinel incident creation | [ ] | | |
| Document incident response playbook | [ ] | | |

**Phase 2.3 Completion Date:** _______________

---

**PHASE 2 OVERALL STATUS:**
- [ ] All Phase 2 tasks completed
- [ ] PIM tested and functional
- [ ] Sentinel ingesting data from all sources
- [ ] First security incident investigated (test or real)
- [ ] Cost tracking confirmed: Expected $21-34/month, Actual: $_____

**Phase 2 Completion Date:** _______________

---

## PHASE 3: MEDIUM PRIORITY (Month 2)

**Goal:** Establish governance and compliance framework
**Estimated Effort:** 27 hours
**Estimated Cost Impact:** Minimal (included in existing licenses)

### Priority 3.1: Policy Governance

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Assign Azure Security Benchmark initiative (enforce mode) | [ ] | | |
| Create policy: Deny public IP creation without approval | [ ] | | |
| Create policy: Require specific Azure regions | [ ] | | |
| Create policy: Require tags on all resources | [ ] | | |
| Deploy policy: Auto-enable diagnostic settings for Key Vaults | [ ] | | |
| Deploy policy: Enforce TLS 1.2 minimum | [ ] | | |
| Review policy compliance state | [ ] | | |
| Remediate non-compliant resources | [ ] | | |
| Document policy exception process | [ ] | | |

**Phase 3.1 Completion Date:** _______________

---

### Priority 3.2: Compliance Posture

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Enable Azure Security Benchmark compliance assessment | [ ] | | |
| Enable additional compliance standards (if required) | [ ] | | Standards: ____________ |
| Review compliance dashboard | [ ] | | Score: _____ |
| Prioritize failed compliance controls | [ ] | | |
| Create cost budget with alerts | [ ] | | Budget: $_____ |
| Configure budget threshold alerts (80%, 100%) | [ ] | | |

**Phase 3.2 Completion Date:** _______________

---

### Priority 3.3: Resource Tagging and Organization

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Define tagging taxonomy | [ ] | | |
| - Environment tag | [ ] | | Values: Production, Staging, Dev, Test |
| - Owner tag | [ ] | | |
| - CostCenter tag | [ ] | | |
| - DataClassification tag | [ ] | | Values: Public, Internal, Confidential |
| - BackupRequired tag | [ ] | | |
| Tag all Static Web Apps | [ ] | | |
| Tag Storage Account | [ ] | | |
| Tag Key Vault | [ ] | | |
| Tag Log Analytics workspace | [ ] | | |
| Tag Lab Plan | [ ] | | |
| Create policy to require tags on new resources | [ ] | | |

**Phase 3.3 Completion Date:** _______________

---

### Priority 3.4: Identity Hardening

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Configure custom banned password list | [ ] | | Terms added: ____________ |
| Enable password protection enforcement | [ ] | | |
| Validate legacy authentication is blocked (CA policy) | [ ] | | |
| Review sign-in logs for legacy auth attempts | [ ] | | Attempts found: _____ |
| Create sign-in risk policy (Entra ID Protection) | [ ] | | |
| Create user risk policy (Entra ID Protection) | [ ] | | |
| Test risk-based policy response | [ ] | | |
| Audit service principals | [ ] | | Count: _____ |
| Document service principal owners | [ ] | | |
| Remove unused service principals | [ ] | | Removed: _____ |
| Set credential expiration < 90 days for all SPs | [ ] | | |
| Replace service principals with managed identities | [ ] | | Converted: _____ |

**Phase 3.4 Completion Date:** _______________

---

**PHASE 3 OVERALL STATUS:**
- [ ] All Phase 3 tasks completed
- [ ] Azure Policy framework enforcing standards
- [ ] Compliance score above 80%
- [ ] All resources tagged consistently
- [ ] Service principals audited and secured

**Phase 3 Completion Date:** _______________

---

## PHASE 4: OPTIMIZATION (Month 3+)

**Goal:** Advanced security and operational excellence
**Estimated Effort:** 50 hours
**Estimated Cost Impact:** $20-355/month (varies by Front Door decision)

### Priority 4.1: Advanced Threat Detection

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Enable UEBA in Sentinel | [ ] | | |
| Configure data sources for UEBA | [ ] | | |
| Create custom threat hunting queries | [ ] | | |
| Develop SOAR playbook: Disable risky user | [ ] | | |
| Develop SOAR playbook: Lock resource on suspicious access | [ ] | | |
| Integrate Microsoft Threat Intelligence | [ ] | | |
| Configure automated incident assignment | [ ] | | |
| Test automated incident response playbooks | [ ] | | |

**Phase 4.1 Completion Date:** _______________

---

### Priority 4.2: Network Defense in Depth

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| **Azure Front Door + WAF (if required)** | | | |
| Evaluate production Static Web Apps criticality | [ ] | | Decision: ____________ |
| Create Azure Front Door Premium profile | [ ] | | |
| Create WAF policy | [ ] | | |
| Enable Microsoft Default Rule Set (DRS 2.1) | [ ] | | |
| Enable Bot Manager Rule Set | [ ] | | |
| Configure custom WAF rules | [ ] | | |
| Migrate Static Web Apps to Front Door | [ ] | | |
| Test WAF protection | [ ] | | |
| **Private Link Implementation** | | | |
| Create Virtual Network (if not exists) | [ ] | | |
| Create subnet for private endpoints | [ ] | | |
| Create private endpoint: Key Vault | [ ] | | |
| Create private endpoint: Storage Account | [ ] | | |
| Update DNS configuration for private endpoints | [ ] | | |
| Test private endpoint connectivity | [ ] | | |
| Disable public access to Key Vault (after PE validated) | [ ] | | |
| Disable public access to Storage (after PE validated) | [ ] | | |

**Phase 4.2 Completion Date:** _______________

---

### Priority 4.3: Advanced Data Protection

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Evaluate customer-managed encryption keys requirement | [ ] | | Decision: ____________ |
| Create encryption key in Key Vault (if CMK required) | [ ] | | |
| Enable Key Vault for disk encryption | [ ] | | |
| Assign Key Vault Crypto Service Encryption User role | [ ] | | |
| Configure Storage Account to use CMK | [ ] | | |
| Test CMK encryption and key rotation | [ ] | | |
| Create data lifecycle management policy | [ ] | | |
| - Tier to Cool after 30 days | [ ] | | |
| - Tier to Archive after 90 days | [ ] | | |
| - Delete after 365 days (adjust as needed) | [ ] | | |
| Evaluate immutable storage requirement | [ ] | | Decision: ____________ |
| Configure immutable storage policy (if required) | [ ] | | |

**Phase 4.3 Completion Date:** _______________

---

### Priority 4.4: Disaster Recovery and Business Continuity

| Task | Status | Completed | Notes |
|------|--------|-----------|-------|
| Document RTO and RPO for each service | [ ] | | |
| Test Key Vault recovery from soft delete | [ ] | | |
| Verify Storage Account geo-redundancy | [ ] | | Redundancy: ____________ |
| Upgrade to GRS/RA-GRS if required | [ ] | | |
| Document Static Web App redeployment procedure | [ ] | | |
| Test complete environment recovery | [ ] | | |
| Create disaster recovery runbooks | [ ] | | |
| Schedule quarterly DR testing | [ ] | | |

**Phase 4.4 Completion Date:** _______________

---

**PHASE 4 OVERALL STATUS:**
- [ ] All Phase 4 tasks completed
- [ ] UEBA detecting behavioral anomalies
- [ ] Front Door/WAF protecting web apps (if implemented)
- [ ] Private Link implemented for PaaS services
- [ ] Disaster recovery tested successfully
- [ ] Cost tracking confirmed: Expected $_____/month, Actual: $_____

**Phase 4 Completion Date:** _______________

---

## ONGOING SECURITY OPERATIONS

### Weekly Tasks

| Task | Frequency | Last Completed |
|------|-----------|----------------|
| Review Defender for Cloud recommendations | Weekly | |
| Review Sentinel incidents | Weekly | |
| Check for new security alerts | Weekly | |
| Review failed CA policy evaluations | Weekly | |

### Monthly Tasks

| Task | Frequency | Last Completed |
|------|-----------|----------------|
| Review Secure Score and trends | Monthly | |
| Review compliance posture | Monthly | |
| Review policy compliance state | Monthly | |
| Review resource costs and anomalies | Monthly | |
| Update banned password list | Monthly | |

### Quarterly Tasks

| Task | Frequency | Last Completed |
|------|-----------|----------------|
| Conduct privileged role access review | Quarterly | |
| Review and update incident response playbooks | Quarterly | |
| Test disaster recovery procedures | Quarterly | |
| Review and update security policies | Quarterly | |
| Conduct security awareness training | Quarterly | |

### Annual Tasks

| Task | Frequency | Last Completed |
|------|-----------|----------------|
| Comprehensive security assessment | Annually | 2026-01-22 |
| Third-party security audit (optional) | Annually | |
| Review and update security strategy | Annually | |
| Review break-glass account access | Annually | |

---

## COST TRACKING

### Phase 1 Costs

| Service | Monthly Cost | Status |
|---------|--------------|--------|
| Defender for Storage | $10 | [ ] Enabled |
| Defender for Key Vault | $0.50 | [ ] Enabled |
| Defender for Resource Manager | $5 | [ ] Enabled |
| Defender for DNS | $2.50 | [ ] Enabled |
| **Phase 1 Total** | **$18** | |

### Phase 2 Costs

| Service | Monthly Cost | Status |
|---------|--------------|--------|
| Entra ID P2 (1 user) | $9 | [ ] Enabled |
| Microsoft Sentinel (5-10GB) | $12-25 | [ ] Enabled |
| **Phase 2 Total** | **$21-34** | |

### Phase 3 Costs

| Service | Monthly Cost | Status |
|---------|--------------|--------|
| Azure Policy | Included | N/A |
| **Phase 3 Total** | **$0** | |

### Phase 4 Costs (Variable)

| Service | Monthly Cost | Status |
|---------|--------------|--------|
| Azure Front Door Premium + WAF | $330 | [ ] Enabled / [ ] Not Required |
| Private Link endpoints (2) | $15 | [ ] Enabled |
| Extended log retention | $5-10 | [ ] Enabled |
| **Phase 4 Total (without Front Door)** | **$20** | |
| **Phase 4 Total (with Front Door)** | **$350** | |

### Overall Cost Summary

| Phase | Monthly Cost | Cumulative Monthly Cost |
|-------|--------------|------------------------|
| Baseline (current) | $50-100 | $50-100 |
| After Phase 1 | +$18 | $68-118 |
| After Phase 2 | +$21-34 | $89-152 |
| After Phase 3 | +$0 | $89-152 |
| After Phase 4 (no Front Door) | +$20 | $109-172 |
| After Phase 4 (with Front Door) | +$350 | $439-502 |

**Current Monthly Cost:** $_____
**Target Monthly Cost:** $_____
**Actual Monthly Cost (updated monthly):** $_____

---

## METRICS AND KPIs

### Security Posture Metrics

| Metric | Baseline (2026-01-22) | Current | Target |
|--------|----------------------|---------|--------|
| Secure Score | TBD | | 80%+ |
| Critical findings | 3 | | 0 |
| High findings | 8 | | <3 |
| Medium findings | 12 | | <5 |
| Resources with locks | 0 | | 100% (critical resources) |
| Resources with diagnostic logging | TBD | | 100% |
| CA policies enabled | 0 | | 3+ |
| Defender plans enabled | 0 | | 4 |

### Operational Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Mean time to detect (MTTD) | <1 hour | |
| Mean time to respond (MTTR) | <4 hours | |
| False positive rate | <10% | |
| Security incidents per month | Monitor | |
| PIM activations per month | Monitor | |
| Failed MFA attempts per month | Monitor | |

---

## NOTES AND DEVIATIONS

### Implementation Notes

| Date | Note |
|------|------|
| | |

### Deviations from Plan

| Date | Deviation | Reason | Risk Accepted By |
|------|-----------|--------|-----------------|
| | | | |

### Issues and Blockers

| Date | Issue | Status | Resolution |
|------|-------|--------|------------|
| | | | |

---

## SIGN-OFF

### Phase 1 Sign-off
- [ ] All critical risks mitigated
- [ ] Testing completed successfully
- [ ] Documentation updated

**Completed By:** _______________
**Date:** _______________

### Phase 2 Sign-off
- [ ] Defense-in-depth implemented
- [ ] Comprehensive monitoring active
- [ ] PIM and Sentinel functional

**Completed By:** _______________
**Date:** _______________

### Phase 3 Sign-off
- [ ] Governance framework established
- [ ] Compliance posture acceptable
- [ ] Identity hardening complete

**Completed By:** _______________
**Date:** _______________

### Phase 4 Sign-off
- [ ] Advanced security controls implemented
- [ ] Disaster recovery tested
- [ ] Security operations ongoing

**Completed By:** _______________
**Date:** _______________

---

**Last Updated:** 2026-01-22
**Next Review:** _______________ (Recommended: Monthly during implementation, Quarterly after completion)
