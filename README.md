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


