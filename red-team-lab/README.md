# Red Team Lab - Offensive Security Exercises

**Practical attack scenarios, lab infrastructure, and OPSEC considerations for learning in isolated test environments.**

---

## Overview

This directory contains hands-on red team exercises designed to teach offensive security techniques in a controlled lab environment.

### Purpose
- Learn attack methodologies (MITRE ATT&CK)
- Practice payload development and delivery
- Test defensive controls and detection capabilities
- Understand attack chains and lateral movement

---

## Folder Structure

```
red-team-lab/
├── README.md                 # This file
├── infra/                    # Infrastructure-as-code
│   ├── terraform/           # Terraform configs for lab VMs
│   ├── ansible/             # Ansible playbooks for setup
│   └── lab-diagrams/        # Network topology images
├── scenarios/               # Attack walkthroughs
│   ├── 01-initial-access/  # Phishing, watering hole, etc.
│   ├── 02-priv-esc/        # Privilege escalation techniques
│   └── 03-lateral-movement/ # Domain admin hunting
└── tools-notes/             # Offensive tooling documentation
    ├── payload-testing.md   # Evasion and obfuscation
    └── opsec-considerations.md
```

---

## Getting Started

### Prerequisites
- Hypervisor: Hyper-V, Proxmox, or cloud-native (Azure VMs)
- Lab Network: Isolated from production
- OS Images: Windows Server 2019+, Windows 10 Enterprise
- Tools: PowerShell 7+, Kali Linux VM (optional)

### Quick Lab Setup

1. **Deploy Infrastructure**
   ```bash
   cd infra/terraform
   terraform init
   terraform plan
   terraform apply  # Creates lab VMs
   ```

2. **Configure Domain Controller**
   ```bash
   cd infra/ansible
   ansible-playbook setup-dc.yml
   ```

3. **Run an Attack Scenario**
   ```bash
   cd scenarios/01-initial-access
   cat scenario.md      # Read objectives
   cat commands.md      # Review attack commands
   ```

---

## Attack Scenarios

Each scenario folder contains:

- **scenario.md** - Objectives, pre-requisites, expected outcomes
- **commands.md** - Detailed attack commands with explanations
- **detections.md** - What SOC/defenders should detect
- **cleanup.md** - How to reset the lab after testing

### Example: Initial Access
- Spear-phishing email with macro-enabled document
- Code execution and reverse shell establishment
- Expected log artifacts: Windows Security Event IDs, process execution

---

## Tools & Frameworks

- **Offensive**: Metasploit, Burp Suite, Hydra, Mimikatz, Cobalt Strike (simulation)
- **Network**: tcpdump, Wireshark, nmap
- **Post-Exploitation**: Empire, PowerUp, BloodHound
- **Detection Simulation**: Sysmon, Windows Defender logs

---

## Best Practices

1. ✅ **Isolation First**: Lab network must be isolated from prod
2. ✅ **Document Everything**: Each attack includes detection notes
3. ✅ **OPSEC**: Obfuscate payloads; avoid IOCs in training
4. ✅ **Cleanup**: Destroy VMs after testing; don't leave backdoors
5. ✅ **Learning Goal**: Focus on understanding, not just exploitation

---

## Common Scenarios

To be documented:
- Phishing → Initial Access → C2 Beacon
- Kerberoasting attacks
- Pass-the-hash lateral movement
- DCSync and golden tickets
- Persistence via scheduled tasks
- Data exfiltration techniques

---

## Related Documentation

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [PentesterLab](https://pentesterlab.com/)
- [HackTheBox](https://www.hackthebox.com/)
- Offense and defense mutual learning

---

## Disclaimer

⚠️ **Lab Environment Only**: All attacks documented here are for isolated test environments only.  
⚠️ **Unauthorized Access Illegal**: Never test against systems without written permission.  
⚠️ **No Real Data**: Never use production credentials or data.  

---

**Last Updated**: January 2026
