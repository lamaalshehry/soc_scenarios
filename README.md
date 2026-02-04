# Azure Sentinel SOC Labs – Incident Detection & Response

## Overview
This repository demonstrates hands-on SOC L1 experience using Microsoft Sentinel (SIEM) and Microsoft Defender for Endpoint (EDR).
The labs focus on detecting, investigating, and responding to security incidents using real telemetry from Azure, identity, and endpoint sources.

All scenarios follow the NIST 800-61 Incident Response Lifecycle and simulate real SOC workflows.

## Tools & Technologies
- Microsoft Sentinel (SIEM)
- Microsoft Defender for Endpoint (EDR)
- Azure Monitor & Log Analytics
- Kusto Query Language (KQL)
- Azure Virtual Machines
- Azure Entra ID (Azure AD)

## Logging Architecture
Logs were collected from:
- Azure Activity Logs
- Azure AD / Entra ID Sign-in Logs
- Defender for Endpoint (DeviceLogonEvents, DeviceProcessEvents)
- Virtual Machines

Refer to `00-logging-architecture/` for architecture explanation.

## Lab Scenarios
| Scenario | Description |
|--------|-------------|
| VM Brute Force Detection | Detect repeated failed login attempts against Azure VMs |
| PowerShell Web Request | Detect malicious PowerShell download & execution |
| Impossible Travel | Identify anomalous sign-ins from multiple locations |
| Excessive Resource Activity | Detect abnormal Azure resource creation/deletion |

Each scenario includes:
- Detection rule (KQL)
- Incident investigation queries
- Analyst notes and findings
- Closure decision (True / False Positive)

## Incident Response Framework
All incidents were handled using:
- Preparation
- Detection & Analysis
- Containment
- Eradication & Recovery
- Post-Incident Lessons Learned
  <img width="1948" height="992" alt="image" src="https://github.com/user-attachments/assets/9231cf65-cdf6-4a7f-8a4e-14d72a03921b" />
