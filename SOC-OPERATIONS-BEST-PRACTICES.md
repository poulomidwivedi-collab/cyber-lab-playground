# SOC Operations: Best Practices & Advanced Techniques

## Executive Summary

This guide provides comprehensive best practices for operating a mature Security Operations Center (SOC), covering team structure, incident management workflows, alert optimization, metrics, and advanced operational techniques. Tailored for the **cyber-lab-playground** environment and applicable to production SOCs.

---

## 1. SOC Structure & Roles

### Typical Team Hierarchy

```
SOC Manager/Director
├─ SOC Lead (24/7 Coverage)
│   ├─ Security Analyst Tier 1 (Triage & Initial Response)
│   ├─ Security Analyst Tier 2 (Investigation & Escalation)
│   ├─ Security Analyst Tier 3 (Advanced Threat Hunting)
│   └─ Incident Response Specialist
├─ Detection Engineer
│   ├─ KQL/Sigma Rule Developer
│   └─ Integration Specialist
├─ Security Architect
└─ Threat Intelligence Analyst
```

### Role Responsibilities

#### Tier 1 Analyst
- Monitor alerts and dashboards
- Triage low-to-medium severity alerts
- Perform initial investigation
- Escalate to Tier 2 when needed

#### Tier 2 Analyst
- Investigate escalated alerts
- Perform forensic analysis
- Create incidents
- Coordinate with business teams

#### Tier 3 Analyst / Threat Hunter
- Proactive threat hunting
- Advanced investigation techniques
- Create new detection rules
- Mentor junior analysts

#### Detection Engineer
- Develop and optimize detection rules
- Reduce false positives
- Integrate new data sources
- Performance tuning

---

## 2. Alert Management Strategy

### Alert Triage Framework

#### Severity-Based Routing

| Severity | Response Time | Owner | Action |
|----------|---------------|-------|--------|
| **Critical** | <5 min | Tier 2+ | Investigate, block, escalate |
| **High** | <30 min | Tier 1-2 | Triage, determine if incident |
| **Medium** | <2 hours | Tier 1 | Triage, batch review |
| **Low** | <1 day | Automation | Log, archive, weekly review |

#### Alert Enrichment

```kql
// Add context to alerts before presentation
alert
| extend RiskScore = case(
    AlertType == "Kerberoasting", 9,
    AlertType == "BruteForce", 7,
    5
  )
| extend RecentIncidents = case(
    Account in (previous_compromised_accounts), 10,
    Computer in (previous_targeted_systems), 8,
    0
  )
| extend FinalScore = (RiskScore + RecentIncidents) / 2
```

### Alert Fatigue Reduction

**Goals**:
- Reduce false positive rate to <5%
- Reduce alert volume by 30% while maintaining detection

**Techniques**:
1. **Whitelisting**: Suppress known benign activity
2. **Tuning**: Adjust thresholds based on historical data
3. **Correlation**: Combine related alerts
4. **Suppression**: Temporary muting after response

---

## 3. Incident Response Workflow

### IR Runbook Template

#### Step 1: Alert Review (5 min)
```
✓ Verify alert authenticity
✓ Check alert history for same user/system
✓ Look for related alerts in last 24h
✓ Assess baseline activity
```

#### Step 2: Initial Investigation (10 min)
```
✓ Query raw event logs
✓ Check network connections
✓ Review process execution
✓ Collect user/system details
```

#### Step 3: Escalation Decision (5 min)
```
True Positive?
  YES → Create Incident (Tier 2)
  NO  → False Positive (tuning needed)
  UNKNOWN → Escalate to Tier 2 for investigation
```

#### Step 4: Response Actions (varies)
```
Automated Actions:
  - Block IP address
  - Disable user account
  - Collect forensic artifacts
  - Notify stakeholders

Manual Actions:
  - Deep forensic analysis
  - Threat hunting
  - Incident documentation
```

### Incident Severity Levels

| Level | Definition | Response Time | Escalation |
|-------|-----------|----------------|------------|
| **SEV-1** | Confirmed breach, active exfiltration | <5 min | CISO + CEO |
| **SEV-2** | Confirmed compromise, contained | <30 min | CISO + IT Director |
| **SEV-3** | Suspected compromise, investigating | <2 hours | IT Director |
| **SEV-4** | Anomalous activity, likely benign | <1 day | SOC Manager |

---

## 4. Metrics & KPIs

### Detection Metrics

```
Detection Rate = (Confirmed Attacks Detected / Total Attacks) × 100
Target: >95%

False Positive Rate = (False Positives / Total Alerts) × 100
Target: <5%

Mean Time to Detect (MTTD) = Average time from attack start to detection
Target: <1 second (automated)
```

### Response Metrics

```
Mean Time to Respond (MTTR) = Average time from alert to first action
Target: <5 minutes

Incident Classification Time = Time to determine if alert is true positive
Target: <15 minutes

Incident Resolution Time = Time from incident creation to closure
Target: <4 hours
```

### Operational Metrics

```
Alert Volume = Total alerts per day
Target: 50-200 (manageable without fatigue)

Escalation Rate = (Escalated Alerts / Total Alerts) × 100
Target: <10%

Analyst Coverage = Analysts per alert volume
Target: 1 analyst per 50-100 alerts
```

### Dashboard Examples

```
[SOC Dashboard]
├─ Alert Volume (24h): 127 alerts
├─ Active Incidents: 3
├─ MTTD (avg): 45 seconds
├─ MTTR (avg): 8 minutes
├─ FP Rate: 3.2%
├─ Critical: 2 (1 active)
├─ High: 15 (8 active)
└─ Analyst Status: 4/5 online
```

---

## 5. Tool Optimization

### Sentinel Optimization

#### Query Optimization
- Aggregate data early
- Filter before joins
- Limit result sets
- Use materialized views

#### Workspace Configuration
- Separate workspaces by department
- Role-based access control (RBAC)
- Alert retention policies
- Cost optimization

#### Playbook Automation
```yaml
automated_response:
  - on_alert: "Kerberoasting_Detection"
    actions:
      - disable_account: true
      - reset_password: true
      - create_incident: true
      - notify_admin: true
      - block_ip: "24h"
```

### Cribl Optimization

#### Pipeline Performance
- Monitor throughput (EPS)
- Optimize parsing logic
- Use lookups efficiently
- Rate limiting configuration

#### Data Routing
```
Sources → Cribl → Parsers → Enrichment → Sentinel
         <500ms    <100ms      <100ms      <100ms
```

---

## 6. Threat Hunting Program

### Hunting Schedule

**Weekly** (2-4 hours)
- Lateral movement patterns
- Anomalous logins
- Persistence mechanisms

**Monthly** (1-2 days)
- Campaign analysis
- Emerging threat research
- Tool evaluation

**Quarterly**
- Advanced threat simulation
- Security assessment
- Training & skill development

### Hunting Hypothesis Framework

```
1. Hypothesis: "Attackers are using Pass-the-Hash to move laterally"
2. Data: SecurityEvent (EventID 4624, LogonType 3)
3. Query: [multi-stage logon detection]
4. Analysis: Identify anomalies
5. Conclusion: Validate or refute hypothesis
6. Action: Create new detection rule if threat confirmed
```

---

## 7. Training & Certification

### Analyst Career Path

**Level 1** (Entry): 0-1 years
- Alert triage
- Basic investigation
- Learning KQL basics
- Goal: CompTIA Security+

**Level 2** (Intermediate): 1-3 years
- Complex investigations
- KQL proficiency
- Playbook creation
- Goal: Certified SOC Analyst (GIAC)

**Level 3** (Advanced): 3-5 years
- Threat hunting
- Detection development
- Team mentoring
- Goal: GIAC Certified Incident Handler (GCIH)

### Continuous Training

- Monthly threat briefings
- Weekly KQL workshops
- Quarterly CTF competitions
- Annual security conference attendance
- Cross-team rotation (forensics, networking)

---

## 8. Incident Response Templates

### Email Notification Template

```
Subject: [SEV-2] Incident #INC-2024-001: Suspicious Lateral Movement

Incident Summary:
- Type: Lateral Movement
- Severity: SEV-2
- Status: Under Investigation
- Affected Systems: 3 Windows workstations
- Affected Users: 2 accounts

Indicators of Compromise:
- [List IOCs]

Recommended Actions:
- Isolate affected systems
- Reset compromised credentials
- Monitor for data exfiltration

Next Update: 2-hour intervals
Contact: SOC Manager
```

### Forensic Artifacts Collection

```
[Windows System]
✓ Event logs (Security, System, Application)
✓ Registry hives
✓ Browser history & cache
✓ MFT (Master File Table)
✓ Process list & memory
✓ Network connections
✓ Scheduled tasks
✓ Installed software
✓ User activity
```

---

## 9. Communication & Escalation

### Escalation Matrix

```
Alert Type          Tier 1          Tier 2              CISO
===============================================================
Kerberoasting       Triage          Investigate         If SEV-1
Data Exfil          Alert           Investigate         If confirmed
Ransom Note Found   Alert + Block   Incident            YES
Worm Detected       Alert           Incident + IR       YES
SSH Brute Force     Review          Tune rule           -
```

### Stakeholder Updates

- **Executive**: Daily summary, weekly detailed report
- **IT Director**: Hourly during incidents, daily summary
- **Department Head**: Only if affected by incident
- **Incident Responder**: Real-time updates during investigation

---

## 10. Maturity Model

### Level 1: Ad-Hoc
- Manual alert review
- Reactive incident response
- No formal runbooks
- Limited metrics

### Level 2: Repeatable
- Documented processes
- Basic automation
- Alert tuning
- Basic metrics tracking

### Level 3: Defined (Target)
- Standard operating procedures
- Advanced automation
- Proactive threat hunting
- Comprehensive metrics
- Regular training

### Level 4: Managed
- Continuous optimization
- Advanced threat intelligence
- Predictive analytics
- Industry benchmarking

### Level 5: Optimized
- AI/ML-driven detection
- Zero-trust implementation
- Autonomous response
- Strategic threat management

---

## References

- [NIST Incident Response Framework](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.62501.pdf)
- [CIS Controls](https://www.cisecurity.org/controls/v8)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Incident Handler's Handbook](https://www.sans.org/)
- [GIAC Certifications](https://www.giac.org/)

---

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Maintained By**: @poulomidwivedi-collab  
**Target Audience**: SOC managers, incident responders, security analysts
