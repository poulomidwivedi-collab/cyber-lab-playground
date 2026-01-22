# Architecture & System Design

## Overview

The **cyber-lab-playground** implements a comprehensive, production-inspired architecture for learning cybersecurity through hands-on exercises in attack simulation, log ingestion, and detection engineering.

## System Architecture

### High-Level Data Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                    RED TEAM LAB ENVIRONMENT                       │
│  (Attack Simulation - Isolated Test Environment)                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Kerberoasting │ Lateral Movement │ Privilege Escalation         │
│        ↓             ↓                    ↓                       │
│    [Windows VM] → [DC] → [Workstations] → [File Servers]        │
│                                                                   │
└──────────────────────────────────────────┬──────────────────────┘
                                           │ Generate Logs
                                           ↓
┌──────────────────────────────────────────────────────────────────┐
│                    LOG INGESTION LAYER (CRIBL)                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Sources:         Pipelines:              Normalization:         │
│  - Windows Logs   - Route & Filter        - ASIM Schemas         │
│  - Sysmon         - Enrich Data           - Field Mapping        │
│  - AWS CloudTrail - Parse & Transform    - Event Correlation    │
│  - VPC Flows      - Rate Limiting                                │
│                                                                   │
└──────────────────────────────────────────┬──────────────────────┘
                                           │ Normalized Data
                                           ↓
┌──────────────────────────────────────────────────────────────────┐
│              DETECTION & RESPONSE LAYER (SENTINEL)               │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Parsers:          Detections:           Analytics:              │
│  - ASIM Parsers    - KQL Rules            - Threat Hunting       │
│  - Custom Schema   - Sigma Rules          - Incident Response    │
│  - Protocol Parse  - Automation Rules     - Case Management      │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Red Team Lab Environment

**Purpose**: Simulate real-world attacks in an isolated, controlled environment

**Components**:
- **Windows Domain**: Active Directory setup with multiple machines
- **Attack Vectors**: Kerberoasting, Pass-the-Hash, Lateral Movement
- **Compliance**: TEST ENVIRONMENT ONLY - no production data

**Data Generated**:
- Windows Security Event Log (4688, 4769, 4720, 4625)
- Sysmon events (process creation, network connections)
- Application logs

**Key Scenarios**:
1. **Initial Access**: Credential harvesting, phishing simulation
2. **Lateral Movement**: Pass-the-hash, Kerberoasting (TGT extraction)
3. **Privilege Escalation**: LOLBAS exploitation, Kernal exploits
4. **Persistence**: Registry modifications, Service installation

---

### 2. Cribl Log Ingestion Layer

**Purpose**: Normalize, enrich, and route logs from multiple sources

**Architecture**:
```
Cribl Stream (Central)  ←→  Cribl Edge (Distributed)
       ↓                          ↓
   [Azure VM]              [On-Prem Collectors]
       ↓
  [Normalize]
       ↓
  [Enrich]
       ↓
  [Route]
```

**Pipelines Implemented**:

| Pipeline | Input | Output | Transformation |
|----------|-------|--------|----------------|
| Windows Security | Event Viewer | ASIM | Parse SIDs, normalize timestamps |
| Sysmon | WMI Provider | ASIM | Extract process trees, file operations |
| CloudTrail | AWS S3 | ASIM | Extract API calls, resources, principals |
| VPC Flow Logs | AWS VPC | ASIM | Parse 5-tuple, aggregate flows |
| Security Hub | AWS API | ASIM | Map findings to ASIM schema |

**Key Transformations**:
- Timestamp normalization (UTC)
- Field mapping (vendor-specific → ASIM)
- GeoIP enrichment
- Threat intelligence lookup
- Event correlation and aggregation

---

### 3. Detection-as-Code Layer (ASIM + Sentinel)

**Purpose**: Create maintainable, testable detection rules using ASIM normalization

**Architecture**:
```
Raw Events
    ↓
┌─────────────────────────────────┐
│  ASIM Parsers                  │
│  - Source-specific parsing     │
│  - Field standardization       │
│  - Schema validation           │
└──────────┬──────────────────────┘
           ↓
┌─────────────────────────────────┐
│  Normalized Events              │
│  (Consistent fields)            │
└──────────┬──────────────────────┘
           ↓
┌─────────────────────────────────┐
│  Detection Rules (KQL)          │
│  - Threat hunting               │
│  - Behavior detection           │
│  - Anomaly analysis             │
└──────────┬──────────────────────┘
           ↓
┌─────────────────────────────────┐
│  Incidents & Alerts             │
│  - Automated response           │
│  - Incident creation            │
│  - Playbook execution           │
└─────────────────────────────────┘
```

**Detection Categories**:

1. **Authentication Attacks**
   - Kerberoasting detection
   - Brute force detection
   - Pass-the-hash activity

2. **Lateral Movement**
   - Administrative share access
   - Scheduled task abuse
   - WMI reconnaissance

3. **Privilege Escalation**
   - Privilege use anomalies
   - LOLBAS execution
   - Service modification

4. **Data Exfiltration**
   - Large data transfer detection
   - Suspicious protocol usage
   - Archive creation patterns

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|----------|
| **Attack Simulation** | Hyper-V / Proxmox | Lab infrastructure |
| | Mimikatz / Impacket | Attack tools |
| | LOLBAS | Legitimate tools abuse |
| **Log Ingestion** | Cribl Stream | Central log collection |
| | Cribl Edge | Distributed collection |
| | Python/Scripting | Custom transformations |
| **Normalization** | ASIM | Schema standardization |
| | KQL | Event processing |
| **Detection** | Azure Sentinel | SIEM platform |
| | KQL | Detection language |
| | Sigma Rules | Portable detection format |
| **Orchestration** | Azure Logic Apps | Automation |
| | GitHub Actions | CI/CD pipelines |
| **Infrastructure** | Azure VMs | Cloud hosting |
| | AWS Services | Cloud integrations |
| | Terraform | IaC automation |

---

## Data Flow Examples

### Example 1: Kerberoasting Attack Detection

```
1. Attack Phase:
   Attacker requests TGT with hash encryption
   → Event ID 4769 (TGT requested)

2. Log Generation:
   Windows DC logs the request
   → Event includes Service Name, User Name, Client Address

3. Cribl Processing:
   - Parse Windows Security event
   - Extract ServiceName and TicketEncryption fields
   - Add timestamp
   - Normalize to ASIM schema

4. Sentinel Detection:
   - Query for multiple 4769 events from same source
   - Filter for RC4 encryption (common for Kerberoasting)
   - Generate alert if threshold exceeded
   - Correlate with user risk profile

5. Response:
   - Create incident
   - Run playbook: reset password, block user, collect forensics
```

### Example 2: Lateral Movement Detection

```
1. Attack Phase:
   Attacker uses Pass-the-Hash to access file server
   → Network: workstation → file server (445/SMB)

2. Log Generation:
   - Windows: 4624 (logon), 4625 (failed logon)
   - Sysmon: Network connection
   - Firewall: Allowed connection

3. Cribl Processing:
   - Aggregate events by source/destination/user
   - Enrich with GeoIP and threat intel
   - Correlate across sources
   - Tag as "SMB activity"

4. Sentinel Detection:
   - Detect unusual SMB access patterns
   - Check for logon anomalies
   - Search for known attack tools
   - Generate alert

5. Response:
   - Block source IP
   - Isolate destination
   - Collect forensics from compromised machine
```

---

## Scaling Considerations

### Horizontal Scaling

**Log Volume Growth**:
- Single Cribl Stream: ~100K EPS (events per second)
- Multiple Cribl Edges: Scale to millions EPS
- Distributed collector deployment

**Detection Scale**:
- Sentinel: Up to 500GB/day ingestion
- Multiple workspaces for different departments
- Federation for cross-workspace correlation

### Vertical Scaling

- Increase VM compute (CPU, RAM)
- Database tuning for Sentinel
- Cribl pack optimization

---

## Security Best Practices Implemented

### 1. Isolation
- **Lab Environment**: Completely isolated network segment
- **No Internet Access**: Attacks contained within lab
- **No Production Data**: Synthetic/sanitized data only

### 2. Authentication & Authorization
- RBAC for Azure/Sentinel access
- MFA for administrative access
- Service principal for automation

### 3. Encryption
- TLS for Cribl connections
- Encrypted storage for credentials
- Secure secret management (Azure KeyVault)

### 4. Audit & Compliance
- All actions logged to diagnostic log
- Compliance with NIST CSF
- Regular access reviews

---

## Performance Metrics

### Expected Throughput

| Metric | Value | Notes |
|--------|-------|-------|
| Log ingestion latency | <500ms | End-to-end |
| Detection latency | <1s | From log to alert |
| Pipeline throughput | ~10K EPS | Single Cribl Stream |
| Detection query latency | <2s | KQL query execution |

### Resource Utilization

- **Cribl Stream VM**: 4 vCPU, 8GB RAM, ~40% utilized
- **Sentinel**: 100GB/day, ~$50-100/day cost
- **Storage**: ~10GB/month for 100K events/day

---

## Future Enhancements

1. **ML-Based Detections**: Anomaly detection on normalized events
2. **Threat Intelligence**: Automated TI feed integration
3. **Playbook Automation**: End-to-end incident response automation
4. **Forensics**: Memory dumps, file analysis, timeline reconstruction
5. **Red vs Blue Metrics**: Attack success/detection rates

---

## References

- [ASIM Documentation](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- [Cribl Architecture](https://docs.cribl.io/stream/architecture/)
- [Azure Sentinel Design](https://learn.microsoft.com/en-us/azure/sentinel/design-your-siem-repository)
- [NIST Cybersecurity Framework](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Maintained By**: @poulomidwivedi-collab
