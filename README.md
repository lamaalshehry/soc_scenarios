# 🛡️ SOC Incident Detection & Response — Microsoft Sentinel

![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoftazure&logoColor=white)
![Defender for Endpoint](https://img.shields.io/badge/EDR-Defender%20for%20Endpoint-0078D4?logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/Query-KQL-5C2D91)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-C8102E)
![NIST 800-61](https://img.shields.io/badge/IR-NIST%20SP%20800--61-1F4E79)

Hands-on **Security Operations Center (SOC)** investigations in a simulated Azure enterprise environment.
Each scenario goes end to end: **write the detection → trigger it → investigate the incident → contain → close**, documented the way an analyst would hand it over to a Tier 2 / IR team.

---

## 📂 Incident Scenarios

| # | Scenario | Data Source | MITRE ATT&CK | Outcome | Write-up |
|---|----------|-------------|--------------|---------|----------|
| 1 | VM Brute Force Attack | `DeviceLogonEvents` | T1110.001 Password Guessing | True Positive — attack unsuccessful, NSG hardened | [View →](scenarios/01-vm-brute-force/) |
| 2 | Suspicious PowerShell Web Request | `DeviceProcessEvents` | T1059.001 PowerShell · T1105 Ingress Tool Transfer | Host isolated, AV scan clean, restored | [View →](scenarios/02-powershell-web-request/) |
| 3 | Potential Impossible Travel | `SigninLogs` | T1078.004 Cloud Accounts | Benign Positive — lab-generated sign-ins | [View →](scenarios/03-impossible-travel/) |
| 4 | Excessive Resource Creation / Deletion | `AzureActivity` | T1578 Modify Cloud Compute Infrastructure | 🚧 In progress | — |

All detection queries are also available as standalone files in [`detections/`](detections/) so they can be copied straight into Log Analytics.

---

## 🧰 Skills Demonstrated

| Area | What's shown |
|------|--------------|
| **Detection engineering** | Scheduled analytics rules, thresholds, lookback/frequency alignment, entity mapping, MITRE tagging |
| **Threat hunting (KQL)** | `summarize`, `parse_json`, `project`, scoping by entity, follow-up pivot queries |
| **Incident handling** | Triage, true/false/benign positive classification, scoping, evidence collection |
| **Response actions** | NSG hardening, MDE device isolation, anti-malware scans, identity response playbook |
| **Documentation** | NIST SP 800-61 structured write-ups, closure notes, recommendations |
| **Critical review** | Detection limitations and tuning ideas noted for each rule |

---

## 🔐 Lab Architecture

End-to-end logging and detection pipeline used across all scenarios:

<img width="2078" height="1162" alt="Lab architecture: Azure VMs, MDE, Entra ID and Azure Activity logs flowing into Log Analytics and Microsoft Sentinel" src="https://github.com/user-attachments/assets/ce26bbf9-b61f-4b1c-88c4-e46c9d6a04a5" />

- **Azure Virtual Machines** generate endpoint and authentication events
- **Microsoft Defender for Endpoint (MDE)** collects endpoint telemetry
- **Entra ID** provides identity and sign-in logs
- **Azure Activity Logs** capture management-plane operations
- Everything is ingested into a **Log Analytics Workspace**
- **Microsoft Sentinel** runs analytics rules, raises incidents and hosts investigations

---

## 📊 Log Sources & Tables

<img width="2013" height="916" alt="Log sources flowing into Log Analytics and consumed by Microsoft Sentinel" src="https://github.com/user-attachments/assets/0495c1df-b6da-4e25-b61e-34178ebcdcaa" />

| Source | Table | Used for |
|--------|-------|----------|
| MDE | `DeviceLogonEvents` | Authentication attempts |
| MDE | `DeviceProcessEvents` | Process execution and command lines |
| MDE | `DeviceNetworkEvents` | Network connections |
| MDE | `DeviceFileEvents` | File creation, deletion, modification |
| MDE | `DeviceInfo` | Endpoint metadata |
| Entra ID | `SigninLogs` | User sign-in activity |
| Entra ID | `AuditLogs` | Identity changes and admin actions |
| Azure | `AzureActivity` | Resource creation, deletion, modification |
| Azure | `AzureNetworkAnalytics_CL` | NSG and network flow logs (where applicable) |

Multi-source visibility is what makes **cross-domain correlation** possible — e.g. tying an endpoint alert to the identity that triggered it.

### Scenario coverage map

<img width="2998" height="1630" alt="Each scenario mapped to its log source and detection layer" src="https://github.com/user-attachments/assets/331945b8-0a1c-4f0d-a5b3-53d5a1642e8c" />

---

## 🚨 Incident Response Methodology — NIST SP 800-61

Every incident is worked through the NIST SP 800-61 lifecycle:

<img width="1948" height="992" alt="NIST SP 800-61 incident response lifecycle" src="https://github.com/user-attachments/assets/9231cf65-cdf6-4a7f-8a4e-14d72a03921b" />

1. **Preparation** — tooling, access, roles and procedures in place
2. **Detection & Analysis** — validate the alert, scope affected entities, decide TP / FP / BP
3. **Containment, Eradication & Recovery** — stop the activity, remove the cause, restore service
4. **Post-Incident Activity** — lessons learned, detection tuning, hardening recommendations

A reusable write-up template is in [`templates/incident-report-template.md`](templates/incident-report-template.md).

---

## 📁 Repository Structure

```
soc_scenarios/
├── README.md                          ← you are here
├── scenarios/
│   ├── 01-vm-brute-force/README.md
│   ├── 02-powershell-web-request/README.md
│   └── 03-impossible-travel/README.md
├── detections/                        ← KQL rules & hunting queries
└── templates/
    └── incident-report-template.md
```

---

## 👩‍💻 About Me

**Lama Alshehry** — Cybersecurity professional with hands-on experience across SOC analysis and GRC, based in Riyadh, Saudi Arabia.

**Certifications:** CompTIA Security+ · CompTIA CySA+ · Cisco CCNA · PMI CAPM

<!-- Add your LinkedIn / email here, e.g.
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin)](https://www.linkedin.com/in/your-profile)
-->

---

### Acknowledgements
Lab environment provided by the **Log(N) Pacific Cyber Range**. All activity was performed in an isolated training tenant; IP addresses and accounts shown are from that lab.
