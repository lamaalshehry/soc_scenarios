# Scenario 1: Virtual Machine Brute Force Detection

[← Back to portfolio](../../README.md)

## 📋 Incident Summary

| Field | Value |
|-------|-------|
| **Alert** | VM Brute Force Attempt |
| **Severity** | Medium |
| **Affected asset** | `lamavmonboardin` (Windows VM) |
| **Source IPs** | `178.57.110.29`, `194.180.49.142` (external) |
| **Data source** | Microsoft Defender for Endpoint — `DeviceLogonEvents` |
| **MITRE ATT&CK** | Credential Access → T1110 Brute Force / T1110.001 Password Guessing |
| **Verdict** | ✅ True Positive — attack observed, **no successful logon** |
| **Response** | Public RDP restricted via NSG hardening |

---

## Part 1: Detection Rule Creation

**Goal:** detect brute-force attempts against Azure VMs by flagging many failed logons from the same remote IP within a short window.

### Rule configuration

| Setting | Value |
|---------|-------|
| Rule type | Scheduled query rule |
| Severity | Medium |
| Table | `DeviceLogonEvents` |
| Threshold | ≥ 10 failed logons per remote IP / device |
| Query frequency | Every 5 hours |
| Lookback | 5 hours (aligned with frequency so no gaps or overlaps) |
| Entity mapping | IP → `RemoteIP`, Host → `DeviceName` |

**Why Medium?** The activity shows an active attack attempt, but nothing yet confirms a compromise. A successful logon from the same IP would justify raising it to High.

<img width="1344" height="1207" alt="Analytics rule general settings" src="https://github.com/user-attachments/assets/460fa6ba-e697-426e-ab98-d139a76a9aff" />

### Detection query (KQL)
[`detections/01-vm-brute-force.kql`](../../detections/01-vm-brute-force.kql)

```kql
DeviceLogonEvents
| where TimeGenerated > ago(5h)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

**Logic**
- Limits to the last 5 hours to match the rule schedule.
- Keeps only failed logons.
- Groups by remote IP **and** target device so each attacker/target pair is its own result.
- A threshold of 10 filters out ordinary mistyped passwords.

<img width="1588" height="1374" alt="Query results" src="https://github.com/user-attachments/assets/0e6e1115-8128-48fd-b0ed-7e962389fcdc" />

### Validation
Multiple failed logons were generated against the VM. Once the threshold was crossed, the rule fired and Sentinel created an incident.

---

## Part 2: Alert Triggered → Incident Created

- Incident created by the scheduled analytics rule
- Severity: Medium
- Entities: remote IP addresses and the affected VM

<img width="2341" height="846" alt="Sentinel incident created" src="https://github.com/user-attachments/assets/687d6813-b2f9-4b6e-be92-78e171523711" />

---

## Part 3: Working the Incident (NIST SP 800-61)

### 1. Preparation
- Roles, responsibilities and procedures documented.
- Sentinel, MDE and Log Analytics access confirmed.

### 2. Detection & Analysis

**Step 1 — Scope the attacking IPs.** Which IPs generated ≥ 10 failures against this host?

```kql
DeviceLogonEvents
| where DeviceName == "lamavmonboardin"
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount desc
```

<img width="1078" height="287" alt="Attacking IPs" src="https://github.com/user-attachments/assets/0ddc0c84-9fd3-4f51-813b-ac01fdf32917" />

Two external IPs were identified: `178.57.110.29` and `194.180.49.142`.

**Step 2 — Did any of them get in?** This is the question that decides severity.

```kql
DeviceLogonEvents
| where DeviceName == "lamavmonboardin"
| where ActionType == "LogonSuccess"
| where RemoteIP in ("178.57.110.29", "194.180.49.142")
```

<img width="654" height="248" alt="No successful logons" src="https://github.com/user-attachments/assets/eb407cf6-7013-475d-b51d-a6e96d0e2bba" />

**Result:** no rows returned. Neither IP authenticated successfully, so the attack failed and the host was not compromised.

### 3. Containment, Eradication & Recovery
- **Containment:** NSG hardened to restrict public RDP to trusted sources only.
- **Eradication:** no successful authentication or malware execution was found, so there was nothing to remove. An MDE antivirus scan was considered as a precaution.
- **Recovery:** not needed; the VM kept running normally.

### 4. Post-Incident Activity
- Findings documented in the incident.
- **Recommendation:** enforce restrictive NSG rules on all VMs and stop exposing RDP to the internet. Use **Azure Bastion** or **Just-in-Time (JIT) VM access** instead.

### Closure
Closed as **True Positive — Suspicious Activity**: brute-force attempts were real, but no successful logon or compromise occurred.

<img width="903" height="957" alt="Incident closure" src="https://github.com/user-attachments/assets/ea3fdc70-0991-4d43-a74c-b3431e1bf2d2" />

---

## 🔧 Detection Tuning Notes

Ideas for running this rule in production:

- **Correlate failure → success.** Add a companion rule that alerts at **High** when an IP that crossed the failure threshold later logs on successfully. That is the event that actually matters.
- **Catch password spraying.** This rule groups by IP and device, so one IP trying a few passwords on *many* accounts or hosts can slip under the threshold. A `dcount(AccountName)` per `RemoteIP` covers that pattern.
- **Enrich with threat intel.** Join `RemoteIP` against `ThreatIntelligenceIndicator` to prioritise known-bad sources.
- **Reduce noise.** Exclude known scanners or internal jump hosts with a watchlist rather than raising the threshold.
