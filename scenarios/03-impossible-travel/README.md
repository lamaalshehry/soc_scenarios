# Scenario 3: Potential Impossible Travel Detection

[← Back to portfolio](../../README.md)

## 📋 Incident Summary

| Field | Value |
|-------|-------|
| **Alert** | Potential Impossible Travel |
| **Data source** | Entra ID — `SigninLogs` |
| **Entity** | One Entra ID user account (masked) |
| **Locations** | Boydton, United States (Azure VM, East US 2) → Ar Riyadh, Saudi Arabia (local ISP) |
| **Time between sign-ins** | ~40 minutes |
| **MITRE ATT&CK** | T1078 Valid Accounts / T1078.004 Cloud Accounts |
| **Verdict** | 🟡 Benign Positive — sign-ins were deliberately generated for the lab |

---

## Part 1: Detection Rule

**Goal:** detect a user signing in from geographically distant locations in a short time, which can indicate stolen credentials or unauthorised access.

### Analytics rule settings

| Setting | Value |
|---------|-------|
| Rule type | Scheduled analytics rule |
| Data source | Entra ID (`SigninLogs`) |
| Run frequency | Every 4 hours |
| Lookup period | Last 5 hours |
| Entity mapping | Account → `UserPrincipalName` |

<img width="2727" height="1007" alt="Analytics rule settings" src="https://github.com/user-attachments/assets/f152c140-b824-49b8-96a3-db3cf051671f" />

### Detection query (KQL)
[`detections/03-impossible-travel.kql`](../../detections/03-impossible-travel.kql)

```kql
let TimePeriodThreshold = timespan(7d); // How far back to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName,
    City    = tostring(parse_json(LocationDetails).city),
    State   = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

**Logic**
1. Extract city, state and country from the `LocationDetails` JSON.
2. Get the distinct locations per user.
3. Count those locations per user.
4. Alert when a user has signed in from more than the allowed number of locations.

> **Note:** when a scheduled rule runs, Sentinel only gives the query the data inside the rule's lookup period (5 hours here), even though the query asks for `ago(7d)`. Setting the `let` value to match the lookup period keeps the two consistent and makes the logic clearer for whoever reads the rule next.

### MITRE ATT&CK mapping

| Tactics | Technique | ID |
|---------|-----------|----|
| Initial Access · Persistence · Privilege Escalation · Defense Evasion | Valid Accounts | T1078 |
| (same) | Valid Accounts: Cloud Accounts | T1078.004 |

Valid Accounts is mapped because a successful sign-in from an unexpected location usually means an attacker is **using legitimate credentials**, not breaking in.

---

## Part 2: Generating the Alert

### Multi-location sign-in simulation
Goal: produce real Entra ID telemetry in `SigninLogs` by signing in with the same account from two different network locations.

**Step A — Local device:** signed in to `https://portal.azure.com` from my local browser, then waited 1–2 minutes for ingestion.

**Step B — Azure VM in another region:** connected to a Windows VM in **East US 2** via Bastion/RDP, signed in to the portal with the same account, then waited 1–2 minutes.

### Log validation

```kql
SigninLogs
| where TimeGenerated > ago(30m)
| where UserPrincipalName == "<masked_user>@lognpacific.com"
| project TimeGenerated,
          UserPrincipalName,
          IPAddress,
          City    = tostring(parse_json(LocationDetails).city),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

<img width="2238" height="1189" alt="Sign-ins from different locations in Sentinel" src="https://github.com/user-attachments/assets/71f853de-c24a-480d-8256-ba7eea1fb436" />

✅ The same account signed in from different IP addresses and locations.

---

## Part 3: Working the Incident (NIST SP 800-61)

### 1. Preparation
Incident assigned to myself as SOC analyst and handled following the NIST SP 800-61 lifecycle.

### 2. Detection & Analysis
- Opened the **"Potential Impossible Travel"** incident
- Assigned it to myself
- Set status to **Active**

<img width="816" height="556" alt="Incident assigned and set to Active" src="https://github.com/user-attachments/assets/73625710-f010-41ad-9fce-5b6ce021f727" />

**Pull the user's sign-in history:**

```kql
let TargetUserPrincipalName = "<masked_user>";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated,
          IPAddress,
          City    = tostring(parse_json(LocationDetails).city),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

<img width="1692" height="991" alt="Sign-in history results" src="https://github.com/user-attachments/assets/cdca8625-0e65-49d4-912e-f4decffd0723" />

### Findings

| Time (UTC) | Country | City | Source |
|------------|---------|------|--------|
| 18:05–18:07 | United States | Boydton | Azure VM (East US 2) |
| 18:47 | Saudi Arabia | Ar Riyadh | Local ISP |

- Distance between the two locations is roughly **11,000 km**.
- The gap between sign-ins is **~40 minutes**, which works out at well over 15,000 km/h. No one can physically travel that fast.
- The pattern therefore matches impossible travel **technically**.

### Conclusion
The sign-ins were generated on purpose as part of the lab simulation, and the US sign-in came from my own Azure VM.

**Final classification: Benign Positive**: the detection worked correctly, but the activity was expected and authorised.

> In a real SOC, the analyst would confirm this with the user and check whether the "remote" IP belongs to a known corporate VPN, cloud host or proxy before closing. Those are the most common causes of benign impossible-travel alerts.

### 3. Containment, Eradication & Recovery

**Lab:** no containment needed.

**If this had been a True Positive**, the response would be:
1. Disable the Entra ID account
2. Revoke all active sessions and refresh tokens
3. Force a password reset
4. Review MFA methods and remove any the user did not register
5. Review `AuditLogs` for changes made by the account (new MFA methods, app consents, inbox rules, role assignments)
6. Contact the user and their manager

### 4. Post-Incident Activity
- Investigation notes documented in Sentinel.
- **Tuning recommendations:**
  - Exclude known corporate egress IPs and VPN ranges with a **watchlist**.
  - Consider only **successful** sign-ins (`ResultType == 0`) for the high-severity version.
  - Pair with **Entra ID Protection** risk signals (`AADUserRiskEvents`) for extra confidence.

### Closure
- Confirmed no active threat
- Closed as **Benign Positive**

<img width="1225" height="1398" alt="Incident closure" src="https://github.com/user-attachments/assets/d44fab41-7424-4674-bf23-72c1fd4db4ba" />

---

## 🔧 Detection Limitations & Improved Version

The lab rule counts **how many distinct locations** a user signed in from. That is a useful starting point, but it has two blind spots:

- **It ignores time.** A user who flew Riyadh → Dubai → London over a week triggers it; real impossible travel is about *speed*.
- **It can miss real attacks.** An attacker in one location plus the real user in one location is only **2** locations, which does not exceed the threshold of 2.

A more precise approach compares **consecutive** sign-ins for each user and calculates the travel speed between them:

```kql
// Improved: flag consecutive successful sign-ins whose implied travel speed is impossible
let MaxSpeedKmh = 900;      // roughly commercial airliner speed
let MinDistanceKm = 500;    // ignore small geo-IP inaccuracies
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude),
         City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Lat) and isnotnull(Lon)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, Lat, Lon
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName), PrevTime = prev(TimeGenerated),
         PrevLat = prev(Lat), PrevLon = prev(Lon),
         PrevCity = prev(City), PrevCountry = prev(Country), PrevIP = prev(IPAddress)
| where UserPrincipalName == PrevUser
| extend DistanceKm = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000.0,
         Hours = datetime_diff('second', TimeGenerated, PrevTime) / 3600.0
| extend SpeedKmh = iff(Hours > 0, DistanceKm / Hours, real(null))
| where DistanceKm > MinDistanceKm and (isnull(SpeedKmh) or SpeedKmh > MaxSpeedKmh)
| project TimeGenerated, UserPrincipalName,
          From = strcat(PrevCity, ", ", PrevCountry), FromIP = PrevIP,
          To = strcat(City, ", ", Country), ToIP = IPAddress,
          DistanceKm = round(DistanceKm, 0), Hours = round(Hours, 2), SpeedKmh = round(SpeedKmh, 0)
```

Against this lab's data (Boydton → Riyadh, ~11,000 km in ~40 minutes) this query would return one clear row showing the implied speed, which is far easier to triage than a location count. Also saved as [`detections/03-impossible-travel-improved.kql`](../../detections/03-impossible-travel-improved.kql).
