# Security Hardening & NIST Cybersecurity Framework Mapping

## Executive Summary

This document maps the **cyber-lab-playground** security controls to the NIST Cybersecurity Framework (CSF) and provides hardening guidance aligned with CIS Controls and GDPR requirements. All exercises are conducted in **isolated TEST ENVIRONMENTS ONLY** with no production data.

---

## NIST Cybersecurity Framework Mapping

The lab implements security across all five NIST CSF Functions:

### 1. IDENTIFY (Asset & Risk Management)

**Objective**: Understand the cybersecurity risk to systems, assets, data, and capabilities.

#### Controls Implemented:

| NIST CSF | Control | Lab Implementation | Status |
|----------|---------|-------------------|--------|
| **ID-AM** | Asset Management | Inventory of lab VMs, network devices, data sources | ✅ |
| **ID-RA** | Risk Assessment | Threat modeling using STRIDE for each component | ✅ |
| **ID-RM** | Risk Management Strategy | Risk registers for attack scenarios | ✅ |
| **ID-GV** | Governance | RBAC, compliance tracking | ✅ |

**Lab Practices**:
- Document all lab assets (VMs, networks, services)
- Create threat models for each attack scenario
- Maintain attack-impact matrices
- Regular security posture reviews

---

### 2. PROTECT (Access Control & Data Security)

**Objective**: Implement safeguards to maintain confidentiality, integrity, and availability.

#### Controls Implemented:

| NIST CSF | Control | Lab Implementation | Status |
|----------|---------|-------------------|--------|
| **PR-AC** | Access Control | RBAC, MFA for Azure/Sentinel | ✅ |
| **PR-DS** | Data Security | Encryption at rest/transit, key management | ✅ |
| **PR-IP** | Information Protection Processes | Classification, handling procedures | ✅ |
| **PR-PT** | Protective Technology | Firewalls, network segmentation | ✅ |

**Lab Practices**:
- **Network Segmentation**: Lab network completely isolated from production
- **Identity Management**: Azure AD with MFA for administrative access
- **Encryption**: TLS 1.2+ for Cribl/Sentinel communications
- **Credential Management**: Secrets stored in Azure Key Vault, never in code
- **Data Classification**: Mark all lab data as "TEST" or "SYNTHETIC"

**Hardening Checklist**:
```
☐ Enable MFA on all Azure/GitHub accounts
☐ Implement network ACLs (no external data exfiltration)
☐ Rotate credentials quarterly
☐ Use service principals for automation (never personal accounts)
☐ Enable audit logging on all resources
☐ Encrypt VM disks using AES-256
☐ Configure firewall rules (whitelist only required ports)
```

---

### 3. DETECT (Continuous Monitoring & Analysis)

**Objective**: Develop and implement capabilities to identify security events in real-time.

#### Controls Implemented:

| NIST CSF | Control | Lab Implementation | Status |
|----------|---------|-------------------|--------|
| **DE-AE** | Anomalies & Events | KQL detection rules, Sigma rules | ✅ |
| **DE-CM** | Security Continuous Monitoring | Log ingestion, alert rules | ✅ |
| **DE-DP** | Detection Processes | Alert triage, incident creation | ✅ |

**Lab Practices**:
- **Real-time Monitoring**: Cribl pipelines process logs in <500ms
- **Detection Rules**: 20+ KQL rules covering attack techniques
- **Alert Tuning**: Thresholds calibrated to minimize false positives
- **Event Correlation**: Multi-stage detection (e.g., multiple 4769 events + RC4 encryption)
- **Performance Tracking**: Monitor detection latency and accuracy

**Detection Capabilities**:
```
✓ Authentication attacks (brute force, Kerberoasting)
✓ Lateral movement (Pass-the-Hash, admin shares)
✓ Privilege escalation (LOLBAS, service modification)
✓ Data exfiltration (large transfers, archive creation)
✓ Persistence mechanisms (scheduled tasks, registry)
```

---

### 4. RESPOND (Incident Management)

**Objective**: Develop and implement appropriate activities to take action regarding detected cybersecurity events.

#### Controls Implemented:

| NIST CSF | Control | Lab Implementation | Status |
|----------|---------|-------------------|--------|
| **RS-RP** | Response Planning | Incident playbooks, runbooks | ✅ |
| **RS-CO** | Communications | Alert routing, notification | ✅ |
| **RS-MI** | Mitigation | Automated response actions | ✅ |
| **RS-IM** | Improvements | Post-incident reviews | ✅ |

**Lab Practices**:
- **Automated Playbooks**: Azure Logic Apps execute response actions
- **Incident Tracking**: Create incidents in Sentinel for each alert
- **Response Runbooks**: Step-by-step procedures for common scenarios
- **Forensics Collection**: Automate memory dump, registry capture
- **Communication**: Alert notifications via email/Slack

**Incident Response Workflow**:
```
1. Detection: KQL rule triggers
   ↓
2. Triage: Analyst reviews alert context
   ↓
3. Response: Playbook executes containment (block IP, disable user)
   ↓
4. Investigation: Collect forensics, analyze attack chain
   ↓
5. Recovery: Restore systems, patch vulnerabilities
   ↓
6. Post-Incident: Review, improve detections
```

---

### 5. RECOVER (Business Continuity)

**Objective**: Develop and implement appropriate activities to maintain resilience and restore capabilities to normal operations.

#### Controls Implemented:

| NIST CSF | Control | Lab Implementation | Status |
|----------|---------|-------------------|--------|
| **RC-RP** | Recovery Planning | Snapshot backups, infrastructure-as-code | ✅ |
| **RC-IM** | Improvements | Remediation tracking | ✅ |
| **RC-CO** | Communications | Incident reports, lessons learned | ✅ |

**Lab Practices**:
- **Infrastructure-as-Code**: Terraform for rapid rebuild
- **Snapshots**: Regular VM snapshots for recovery
- **Data Protection**: Critical configs backed up to GitHub
- **Lessons Learned**: Document each exercise with findings

---

## CIS Controls Alignment

The lab aligns with key CIS Controls (v8):

### Foundational Controls

| CIS Control | Lab Mapping | Implementation |
|-------------|-------------|----------------|
| **1.1** Asset Inventory | Lab asset list | GitHub issues + Azure tags |
| **2.1** Software Inventory | Package tracking | requirements.txt, GitHub Actions |
| **3.1** Data Classification | Mark test/synthetic | README labels |
| **4.1** Secure Config Mgt | IaC, templates | Terraform + Ansible |
| **5.1** MFA | Azure AD | Conditional Access policies |

### Security Operations Controls

| CIS Control | Lab Mapping | Implementation |
|-------------|-------------|----------------|
| **8.1** Audit Logging | Enable on all resources | Azure Diagnostic Logs |
| **9.1** Network Segmentation | Lab isolation | VNet ACLs |
| **10.1** Incident Response | Playbooks | Azure Logic Apps |

---

## GDPR Compliance (Where Applicable)

While the lab uses no personal data, these principles apply if extension to production:

### Data Protection
- ✅ Encryption of data in transit and at rest (Article 32)
- ✅ Access control and authentication (Article 32)
- ✅ Audit logging and monitoring (Article 32)
- ✅ Incident response procedures (Article 33)

### Test Environment Practices
- ✅ NO personal data (PII) stored in lab
- ✅ ALL data marked "TEST" or "SYNTHETIC"
- ✅ Regular purging of test data
- ✅ No third-party data sharing without consent

---

## Security Best Practices by Component

### 1. Red Team Lab Hardening

**Network**
```
- Lab network on isolated VLAN (10.0.0.0/24)
- No internet access from VMs
- Internal DNS only
- Firewall rules deny by default, allow by exception
```

**Windows Domain**
```
- DC hardened per Microsoft Secure Admin Workstation (SAW) guidance
- Group Policies enforce strong passwords (14+ chars, complexity)
- Audit all event IDs (4624, 4625, 4720, 4769, 4688)
- Disable LLMNR/NetBIOS for security
```

**Attack Simulation**
```
- Use dedicated attack VM (NOT connected to production)
- Document all tools and techniques
- Maintain activity logs
- Clean up after exercises (remove artifacts)
```

### 2. Cribl Pipeline Hardening

**Authentication**
```
- Require HTTPS for Web UI
- Implement API key rotation (monthly)
- RBAC for pipeline modifications
```

**Data Processing**
```
- Sanitize sensitive data (PII, credentials)
- Encrypt credentials in pipelines
- Log all pipeline changes
- Version control all configurations
```

**Performance & Stability**
```
- Monitor memory/CPU usage
- Set rate limits (prevent DoS)
- Implement circuit breakers
- Error handling and dead-letter queues
```

### 3. Sentinel Detection Hardening

**Analytics Rules**
```
- Test detection rules against sample data
- Tune thresholds to minimize false positives
- Version control all rules
- Document rule logic and mappings
```

**Alert Management**
```
- Implement alert fatigue reduction
- Severity-based alert routing
- Automated triage (severity, entity type)
- Regular alert tuning based on metrics
```

**Access Control**
```
- RBAC for analyst roles (Reader, Responder, Admin)
- Separate workspaces for different teams
- Audit all user actions
```

---

## Compliance Audit Checklist

### Monthly Tasks
- [ ] Review Azure resource access logs
- [ ] Check for failed authentication attempts
- [ ] Validate MFA is enabled on all admin accounts
- [ ] Review firewall rules for unnecessary open ports
- [ ] Check VM patches and updates

### Quarterly Tasks
- [ ] Rotate API keys and service principals
- [ ] Perform security assessment of pipelines
- [ ] Review detection rule effectiveness
- [ ] Update threat models
- [ ] Conduct incident response drill

### Annually
- [ ] Full security audit
- [ ] Penetration testing (with authorization)
- [ ] Policy review and updates
- [ ] Training and awareness refresh
- [ ] Risk assessment update

---

## Incident Response Procedures

### Attack Detected in Lab

**Immediate Actions** (0-5 minutes)
1. Alert researcher/observer
2. Take VM snapshot
3. Preserve log data
4. Do NOT shut down immediately (preserve evidence)

**Investigation** (5-30 minutes)
1. Export Sentinel incidents to CSV
2. Collect Windows Event logs
3. Extract process trees from Sysmon
4. Analyze network flows

**Remediation** (30-60 minutes)
1. Snapshot infected VM
2. Remove attacker artifacts
3. Update detection rules if needed
4. Document findings

**Post-Incident**
1. Write-up attack chain
2. Identify detection gaps
3. Add new rules/signatures
4. Update TTPs documentation

---

## Security Metrics & KPIs

### Detection Effectiveness
- **Detection Rate**: % of injected attacks detected
- **False Positive Rate**: % of legitimate events alerted
- **Mean Time to Detect (MTTD)**: <1 second target
- **Mean Time to Respond (MTTR)**: <5 minutes target

### Lab Environment Health
- **Log Volume**: 100K-500K events/day
- **Ingestion Latency**: <500ms
- **Detection Query Latency**: <2s
- **Alert Accuracy**: >95%

### Compliance Status
- **MFA Coverage**: 100% for privileged accounts
- **Audit Logging**: 100% of actions logged
- **Encryption**: 100% of traffic encrypted
- **Access Reviews**: Quarterly compliance

---

## References

- [NIST Cybersecurity Framework v1.1](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [GDPR - Data Protection Regulation](https://gdpr-info.eu/)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/)
- [Windows Security Hardening](https://learn.microsoft.com/en-us/windows/security/threat-protection/)

---

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Maintained By**: @poulomidwivedi-collab  
**Compliance Status**: Aligned with NIST CSF, CIS Controls v8, GDPR principles
