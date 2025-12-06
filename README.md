# Network Security Policy-as-Code v2

A vendor-agnostic, GitOps-driven framework for managing network security policies across multi-cloud and on-premises infrastructure.

## Overview

This repository provides a unified approach to network security policy management:

- **Single Entry Point**: Define policies in vendor-agnostic YAML
- **Centralized Object Registry**: Define hosts, groups, and services once, reference everywhere
- **Multi-Platform Support**: AWS, GCP, Azure, Palo Alto, Fortinet, Illumio
- **Automated Workflows**: GitHub Actions for validation, planning, and deployment
- **Guardrails**: Automated policy evaluation with auto-approve/review gates
- **Terraform Enterprise**: All deployments flow through TFE for consistency

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Registry     │     │    Policies     │     │   Guardrails    │
│  (What exists)  │────▶│ (Who talks to   │────▶│  (Auto-approve  │
│                 │     │      whom)      │     │   or review)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                        ┌───────────────────────────────┘
                        ▼
              ┌─────────────────┐
              │    Adapters     │
              │ (Translate to   │
              │  vendor TF)     │
              └─────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │   AWS   │    │  Palo   │    │ Illumio │
   │   TFE   │    │  Alto   │    │   TFE   │
   └─────────┘    │   TFE   │    └─────────┘
                  └─────────┘
```

## Repository Structure

```
network-security/
├── registry/                 # Object definitions (hosts, groups, services)
│   ├── hosts/               # Individual host definitions
│   ├── groups/              # Logical groupings (static and dynamic)
│   ├── services/            # Service/port definitions
│   └── zones/               # Security zone definitions
├── policies/                 # Network policy definitions
│   ├── production/
│   ├── staging/
│   └── development/
├── adapters/                 # Translation engine
│   ├── core/                # Shared logic
│   └── plugins/             # Platform-specific adapters
├── guardrails/              # Policy evaluation rules
├── schemas/                 # JSON schemas for validation
├── scripts/                 # CI/CD helper scripts
└── generated/               # Generated Terraform (gitignored or separate branch)
```

## Quick Start

### 1. Define Objects in Registry

```yaml
# registry/groups/application-groups/web-tier.yaml
apiVersion: netsec/v1
kind: Group
metadata:
  name: web-tier
  owner: web-team@company.com
spec:
  membership:
    dynamic:
      match-labels:
        tier: web
        environment: production
    networks:
      - 10.100.1.0/24
  platform-mapping:
    paloalto:
      strategy: hybrid
      dag:
        name: dag-web-tier
        match-criteria:
          - "'tier.web' and 'env.production'"
      static:
        name: grp-web-tier-static
      combined:
        name: grp-web-tier
    illumio:
      strategy: label-based
      labels:
        - key: app
          value: web-tier
```

### 2. Create a Policy

```yaml
# policies/production/allow-web-to-api.yaml
apiVersion: netsec/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-api
  requestor: john.smith@company.com
  ticket: SNOW-12345
spec:
  description: "Allow web tier to communicate with API tier"
  source:
    group: web-tier
  destination:
    group: api-tier
  services:
    - https
  action: allow
  logging: true
  targets:
    - platform: paloalto
      scope: ["datacenter-east", "datacenter-west"]
    - platform: aws
      scope: ["prod-web", "prod-api"]
    - platform: illumio
      scope: ["pce-prod"]
```

### 3. Open a Pull Request

The workflow will automatically:
- Validate schema and references
- Evaluate guardrails
- Generate Terraform for all platforms
- Run speculative plans in TFE
- Comment results on the PR

### 4. Merge to Deploy

On merge, the workflow:
- Regenerates all affected Terraform
- Triggers TFE applies for each workspace
- Notifies on completion

## CLI Usage

```bash
# Validate policies
python -m adapters.cli validate --registry registry/ --policies policies/

# Generate Terraform
python -m adapters.cli generate --registry registry/ --policies policies/ --output generated/terraform/

# Generate for specific platform
python -m adapters.cli generate --platform paloalto --policies policies/production/

# Dry run
python -m adapters.cli generate --dry-run --policies policies/
```

## Adding a New Platform

1. Create adapter plugin in `adapters/plugins/newvendor.py`
2. Implement the `AdapterPlugin` interface
3. Register in `adapters/core/engine.py`
4. Add platform mappings to registry objects

See `adapters/plugins/base.py` for the interface definition.

## Guardrails

Guardrails automatically evaluate policies:

- **Auto-approve**: Standard ports, same-environment, existing patterns
- **Require review**: Cross-environment, internet-facing, non-standard ports
- **Deny**: Any-to-any rules, policy violations

Configure in `guardrails/rules.yaml`.

## Requirements

- Python 3.11+
- Terraform Enterprise account
- GitHub Actions
- Platform credentials (AWS, GCP, Palo Alto, etc.)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TFE_TOKEN` | Terraform Enterprise API token |
| `TFE_ORG` | TFE organization name |
| `GITHUB_TOKEN` | GitHub token for PR comments |

## Contributing

1. Create a feature branch
2. Make changes
3. Run tests: `pytest adapters/tests/`
4. Open PR

## License

Internal use only.
