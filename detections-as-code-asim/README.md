# Detection-as-Code with ASIM

**ASIM-normalized KQL detection rules, parser functions, and unit tests for Azure Sentinel.**

---

## Overview

Azure Sentinel Information Model (ASIM) enables detection engineers to write rules that work across multiple data sources by normalizing logs to standard schemas.

### Goals
- Write parsers that map source-specific fields to ASIM schemas
- Create detection rules that work on normalized data
- Test rules against multiple data formats
- Enable code-driven detection engineering in Sentinel

---

## Folder Structure

```
detections-as-code-asim/
├── README.md                      # This file
├── schemas/                       # ASIM schema documentation
│   ├── asim-authentication/
│   └── asim-network-session/
├── parsers/                      # KQL parser functions
│   ├── cribl-auth-parser.kql
│   └── cribl-network-parser.kql
├── detections/                    # Detection rules
│   ├── kql/
│   │   ├── auth/
│   │   └── lateral-movement/
│   └── sigma/
├── tests/                        # Test data and unit tests
│   ├── sample-events/
│   └── kql-unit-tests.md
└── ci/                           # CI/CD validation
    ├── validate-kql.ps1
    └── validate-sigma.sh
```

---

## Parsers

ASIM parsers normalize raw events into standard schemas.

### Example: Authentication Parser

```kql
let CriblAuth = view () {
    CriblRawLogs
    | where EventType == "authentication"
    | project
        TimeGenerated,
        SrcIpAddress = SourceIP,
        TargetUsername = User,
        TargetDvcHostname = Host,
        EventResult = case(
            Status == "success", "Success",
            "Failure"
        )
};
CriblAuth
```

### Parsers included:
- Cribl Windows Security events→ Authentication ASIM
- Cribl VPC Flow Logs → NetworkSession ASIM

---

## Detections

Rules organized by MITRE ATT&CK tactic/technique.

### Authentication
- Brute force detection (many failed logins)
- Anomalous login times/locations
- Failed logon storms

### Lateral Movement
- SMB lateral movement (Event ID 5140)
- Scheduled task execution
- Pass-the-hash patterns

---

## Testing

### Running Unit Tests

```bash
# In Sentinel - create test data
let TestEvents = externaldata(TimeGenerated:datetime, User:string) [
    "@'sample-events/test-auth.csv"
];

// Run parser against test data
TestEvents | invoke CriblAuthParser()

// Validate output matches ASIM schema
| where isnotempty(TimeGenerated) and isnotempty(SrcIpAddress)
```

---

## Best Practices

1. ✓ Follow ASIM schema specifications strictly
2. ✓ Use parsers in all detection rules (don't hardcode field names)
3. ✓ Test against multiple source formats
4. ✓ Document assumptions about field mappings
5. ✓ Version all rules in Git; enable code review

---

## ASIM Resources

- [ASIM Architecture](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- [Writing ASIM Parsers](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-overview)
- [Detection Rules in Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

## Integration with Cribl

Cribl pipelines in `../cribl-ingestion/` output events compatible with these parsers.

**Data Flow**:
```
Raw Logs → Cribl (normalize) → Sentinel → Parser → ASIM Schema → Detection Rules
```

---

**Last Updated**: January 2026
