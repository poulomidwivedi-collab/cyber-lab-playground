# Authentication Detection Rules - ASIM Normalized KQL Queries

## Overview
This document contains production-ready KQL detection rules using ASIM normalization for Azure Sentinel. All queries are designed to detect authentication anomalies and attack patterns while minimizing false positives.

## 1. Brute Force Detection: Multiple Failed Authentications

```kql
let threshold = 10; // Failed attempts within 5 minutes
let timeWindow = 5m;
imAlert | where isnotempty(ActorUsername)
| summarize FailureCount = dcount(EventType) by ActorUsername, ActorUserId, IpAddr, bin(TimeGenerated, timeWindow)
| where FailureCount >= threshold
| extend Severity = "High", DetectionMethod = "ASIM"
| project TimeGenerated, ActorUsername, ActorUserId, IpAddr, FailureCount, Severity
```

## 2. Impossible Travel Detection

```kql
let time_window = 10m;
let distance_threshold = 900; // km threshold for impossible travel
imAlert
| where EventType has "Logon" or EventType has "Authentication"
| extend LocationLat = 0.0, LocationLon = 0.0 // Normalize with geo data
| summarize arg_max(TimeGenerated, *) by ActorUserId, bin(TimeGenerated, time_window)
| partition by ActorUserId (
    order by TimeGenerated asc
    | extend PrevLocation = prev(LocationLat), PrevTime = prev(TimeGenerated)
    | extend TravelSpeed = 1000 / ((TimeGenerated - PrevTime) / 1h) // km/h
    | where TravelSpeed > distance_threshold
)
```

## 3. Detection: Authentication from Unusual Location

```kql
let baseline_locations = dynamic(["GB", "US", "CA"]); // Customize for your org
imAlert
| where EventType has "Logon" or EventType has "Authentication"
| where tostring(SrcGeoRegion) !in (baseline_locations)
| summarize EventCount = count() by ActorUsername, SrcGeoRegion, SrcGeoCountry
| where EventCount > 3
| extend RiskLevel = "Medium"
```

## 4. Privileged Account Authentication Anomaly

```kql
let priv_users = dynamic(["admin", "root", "domain admins"]);
let threshold = 2;
imAlert
| where tolower(ActorUsername) has_any (priv_users)
| where EventType has "Logon" or EventType has "Authentication"
| extend IsFailure = EventResult == "Failure"
| summarize FailureCount = countif(IsFailure), SuccessCount = countif(not(IsFailure)) by ActorUsername, bin(TimeGenerated, 1h)
| where FailureCount >= threshold
| extend Alert = "Privileged Account Failure Spike", Severity = "High"
```

## 5. Detection: Password Spray Attack Pattern

```kql
let minutes = 10;
let hit_threshold = 30; // Different accounts targeted
imAlert
| where EventType has "Logon" or EventType has "Authentication"
| where EventResult == "Failure"
| summarize UniqueTargets = dcount(ActorUsername) by SrcIpAddr, bin(TimeGenerated, minutes)
| where UniqueTargets >= hit_threshold
| extend ThreatLevel = "Critical", AttackType = "PasswordSpray"
```

## 6. Lateral Movement: Unusual Account Login Chain

```kql
imAlert
| where EventType has "Logon" or EventType has "Authentication"
| where EventResult == "Success"
| extend SourceSystem = SrcGeoCountry
| summarize LoginCount = count(), Hosts = dcount(TargetHostname) by ActorUsername, bin(TimeGenerated, 30m)
| where LoginCount > 5 and Hosts > 3
| extend DetectionType = "LateralMovement", AlertSeverity = "High"
```

## 7. Multi-Stage Authentication Bypass

```kql
let mfa_bypass_threshold = 3;
imAlert
| where EventType has "MultiFactor" or EventType has "MFA"
| summarize 
    InitialFailures = countif(EventResult == "Failure" and step_s == 1),
    StepTwoSuccesses = countif(EventResult == "Success" and step_s == 2)
    by ActorUsername, bin(TimeGenerated, 1h)
| where InitialFailures > 0 and StepTwoSuccesses > 0
| extend RiskScore = 85, DetectionCategory = "AuthBypass"
```

## 8. Service Account Suspicious Activity

```kql
let service_accounts = dynamic(["svc_", "srv_"]);
imAlert
| where ActorUsername has_any (service_accounts)
| where EventType has "Logon" or EventType has "Authentication"
| summarize EventCount = count() by ActorUsername, SrcIpAddr, bin(TimeGenerated, 1h)
| where EventCount > 50 // Unusual volume for service account
| extend AlertType = "ServiceAccountAnomaly", Priority = "Medium"
```

## 9. Detection: Source IP Based Attacks

```kql
let attack_ips = dynamic(["10.0.1.0/24"]); // Customize for your environment
imAlert
| where SrcIpAddr in (attack_ips) or ipv4_is_in_range(SrcIpAddr, "192.168.0.0/16")
| summarize FailureCount = countif(EventResult == "Failure"), TotalEvents = count() 
    by SrcIpAddr, ActorUsername, bin(TimeGenerated, 10m)
| extend FailureRate = (FailureCount * 100.0 / TotalEvents)
| where FailureRate > 50
```

## 10. Credential Usage Outside Business Hours

```kql
imAlert
| where EventType has "Logon" or EventType has "Authentication"
| extend HourOfDay = hourofday(TimeGenerated), DayOfWeek = dayofweek(TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 20 // Outside business hours
| where DayOfWeek in (0, 6) // Weekend
| summarize EventCount = count() by ActorUsername, SrcIpAddr
| where EventCount > 2
| extend AnomalyType = "OutOfHoursActivity", RiskScore = 70
```

## Best Practices

1. **Tuning Thresholds**: Adjust threshold values based on your organization's baseline
2. **Time Windows**: Modify time windows based on your use cases and false positive rates
3. **Whitelisting**: Maintain allowlists for known service accounts and expected patterns
4. **Integration**: Integrate with Cribl for log enrichment before normalization
5. **Testing**: Use diagnostic queries before deploying to production
6. **Documentation**: Document all custom thresholds and assumptions

## Running Detections

```bash
# Example CLI execution in Azure Sentinel
az sentinel alert create --resource-group <rg> --name "Auth-BruteForce" --query <kql-query>
```
