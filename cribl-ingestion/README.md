# Cribl Ingestion - Log Pipeline Design

**Cribl Stream/Edge configurations, sample data, and pipeline documentation for security log normalization.**

---

## Overview

Log collection, processing, and normalization from various sources using Cribl Stream/Edge.

### Key Capabilities
- Multi-source log collection (Windows, Linux, cloud, network)
- Data enrichment and field extraction  
- Sensitive data masking (PII, credentials)
- Routing to SIEM backends (Sentinel, Splunk, Chronicle)
- Format normalization (JSON, syslog, CEF)

---

## Folder Structure

```
cribl-ingestion/
├── README.md                  # This file
├── packs/                     # Custom Cribl packs
│   ├── vpc-flows/
│   └── windows-security/
├── pipelines/                 # Pipeline definitions (JSON)
│   ├── normalize-winevent.json
│   └── drop-noisy-auth.json
├── routes/                    # Routing configurations
│   └── lab-routes.yaml
└── samples/                   # Sample log data
    ├── aws-vpc-flow.log
    └── windows-security.evtx.json
```

---

## Quick Start

### Prerequisites
- Cribl Stream or Edge instance (trial available)
- Source: Windows Security logs, CloudTrail, VPC Flows, etc.
- Destination: Azure Sentinel or other SIEM

### Sample Pipeline

```yaml
Source → Extract Fields → Drop Noisy Logs → Normalize → Destination
```

---

## Pipelines

### Windows Security Event Normalization
- Input: Raw Windows Event Logs (4624, 4625, 4728)
- Processing: Extract source IP, user, host, result
- Output: JSON to Sentinel CustomSecurityLog_CL table

### AWS VPC Flow Logs
- Input: S3 or CloudWatch
- Processing: Parse protocol, ports, bytes
- Output: Network session normalized format

---

## Best Practices

1. Filter early - drop noisy/useless logs at ingestion
2. Mask secrets - use regex to mask credentials
3. Normalize format - consistent field naming
4. Monitor volume - track ingestion costs
5. Version control - track pipeline JSON in Git

---

## ASIM Integration

Output compatible with Azure Sentinel ASIM schemas:
- Authentication → `Authentication` table
- Network traffic → `NetworkSession` table
- DNS queries → `DnsEvents` table

See `../detections-as-code-asim/` for KQL parser functions.

---

## Resources

- [Cribl Stream Docs](https://docs.cribl.io/stream/)
- [ASIM Documentation](https://learn.microsoft.com/en-us/azure/sentinel/normalization)

---

**Last Updated**: January 2026
