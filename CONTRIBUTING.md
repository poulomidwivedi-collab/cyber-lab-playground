# Contributing to cyber-lab-playground

Thank you for your interest in contributing! This guide will help you get started.

## How to Contribute

### 1. Adding Red Team Scenarios

Create a new folder under `red-team-lab/scenarios/` following this structure:

```
scenarios/
├── XX-scenario-name/
│   ├── scenario.md          # Objective, pre-reqs, expected outcomes
│   ├── commands.md          # Step-by-step attack commands
│   ├── detections.md       # What defenders should see in logs
│   └── cleanup.md          # Lab reset instructions
```

**Guidelines:**
- Document all assumptions and dependencies
- Include MITRE ATT&CK IDs for attack techniques
- Link detection artifacts to Windows Event IDs or log sources
- Keep scenarios self-contained and reproducible

### 2. Adding Detection Rules

Create new KQL rules under `detections-as-code-asim/detections/kql/`:

```
detections/kql/
├── auth/
│   ├── rule-id_Brute_Force_Detection.kql
│   └── rule-id_Failed_Logon_Storm.kql
```

**Rule template:**
```kql
// Name: Brief rule name
// ID: DETC-001
// MITRE: T1110 (Brute Force)
// Date: 2026-01-22

Authentication
| where EventResult == "Failure"
| summarize FailCount = count() by SrcIpAddress, TargetUsername
| where FailCount > 10
| project-reorder TimeGenerated, SrcIpAddress, TargetUsername, FailCount
```

### 3. Adding Cribl Pipelines

Export pipelines from Cribl Stream and save as JSON:

```
cribl-ingestion/pipelines/
├── normalize-windows-auth.json
├── drop-noisy-logs.json
```

**Include documentation:**
- Input sources
- Transformation logic
- Output format
- Performance considerations

## Commit Message Format

Follow conventional commits:

```
<type>: <subject>

<body>
```

Types:
- `feat:` New scenario, detection, or pipeline
- `docs:` Documentation updates
- `fix:` Bug fixes
- `refactor:` Restructure without changing functionality
- `ci:` CI/CD updates

Example:
```
feat: Add lateral movement scenario with SMB exploitation

- Documents pass-the-hash technique
- Includes Windows Event 5140 detection
- Adds Cribl pipeline for SMB log normalization
```

## Code of Conduct

- **Lab-only content**: All attack techniques documented here are for isolated test environments only
- **No production data**: Never commit real credentials, API keys, or organization data
- **Attribution**: Link to original research, tools, and frameworks used
- **Responsible disclosure**: If you discover security issues with the tools, report privately first

## Testing

Before submitting:

1. **Red Team Scenarios**: Test in your lab; document all steps
2. **Detection Rules**: Validate against test data in ASIM schema
3. **Cribl Pipelines**: Test with sample data; verify output format
4. **Documentation**: Run spell-check; ensure links work

## Review Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/scenario-name`
3. Commit with clear messages
4. Push to your fork
5. Open a Pull Request with a description
6. Address review feedback

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ASIM Parser Guide](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-overview)
- [Cribl Documentation](https://docs.cribl.io/stream/)
- [KQL Query Language](https://learn.microsoft.com/en-us/kusto/query/)

---

**Thank you for contributing!** Questions? Open an issue or discuss in the repo.
