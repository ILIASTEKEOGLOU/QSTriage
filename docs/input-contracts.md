# QSTriage Input Contracts

QSTriage accepts two decision-input formats: a native YAML inventory and CycloneDX CBOM JSON. An optional YAML configuration file controls default output paths and export format.

This document describes the public input contract implemented by `qstriage/models.py`, `qstriage/config.py`, `qstriage/cbom.py`, and `qstriage/limits.py`. Code and tests remain authoritative for executable behavior.

## General input safety

All file-backed text input must be valid UTF-8 and remain within the documented size limits. QSTriage rejects malformed structures rather than attempting to repair them.

YAML input is parsed with a safe loader and additionally rejects:

- YAML aliases (anchor-based value reuse),
- duplicate mapping keys,
- nesting deeper than 64 levels,
- more than 200,000 parser events,
- non-scalar or unhashable mapping keys.

Unknown fields are rejected in the native inventory and configuration models.

## Supported limits

| Input or collection | Supported limit |
|---|---:|
| Inventory YAML file | 10 MiB |
| CycloneDX CBOM JSON file | 32 MiB |
| Configuration YAML file | 1 MiB |
| Assets per inventory | 1–1,000 |
| Dependencies per inventory | 0–10,000 |
| Migration scenarios per inventory | 0–100 |
| Asset/scenario simulation results | 20,000 |
| CycloneDX components | 10,000 |
| Identifier length | 256 characters |
| General text field length | 512 characters |
| Notes length | 4,096 characters |

The simulation-result budget is calculated as `asset_count × max(1, scenario_count)`.

These are supported-workload boundaries for deterministic local operation, not claims about enterprise-wide discovery capacity.

## Native inventory YAML

The document root is a mapping with three top-level collections:

- `assets`: required and must contain 1–1,000 items,
- `dependencies`: optional and defaults to an empty list,
- `scenarios`: optional and defaults to an empty list.

### Asset fields

| Field | Type | Contract |
|---|---|---|
| `id` | string | Required, non-empty, unique, maximum 256 characters |
| `name` | string | Required, non-empty, maximum 512 characters |
| `environment` | string | Required, non-empty |
| `asset_type` | string | Required, non-empty |
| `protocol` | string | Required, non-empty |
| `algorithm` | string | Required, non-empty; classified by the current standards registry |
| `key_size_bits` | integer or null | Optional; when present, must be zero or greater |
| `data_class` | string | Required, non-empty |
| `retention_years` | integer | Required; must be zero or greater |
| `exposure` | string | Required, non-empty |
| `criticality` | enum | `low`, `medium`, `high`, or `critical` |
| `local_blast_radius` | enum | `low`, `medium`, `high`, or `critical` |
| `migration_effort` | enum | `low`, `medium`, `high`, or `critical` |
| `notes` | string | Optional; defaults to an empty string |

Values such as `unknown`, `0`, or imported defaults are accepted as data but can create evidence findings, lower confidence, or gate the canonical decision. They are not interpreted as proof of low risk.

### Dependency fields

| Field | Type | Contract |
|---|---|---|
| `id` | string | Required, non-empty, unique |
| `source` | asset ID | Must reference an existing asset |
| `target` | asset ID | Must reference an existing asset and differ from `source` |
| `direction` | enum | `inbound`, `outbound`, or `bidirectional` |
| `dependency_type` | enum | `auth`, `dataflow`, `tls_termination`, `database`, `logging`, `firmware_update`, `api_call`, or `telemetry_upload` |
| `protocol` | string | Required, non-empty |
| `weight` | number | Inclusive range 0.0–1.0 |
| `criticality` | enum | `low`, `medium`, `high`, or `critical` |
| `carries_crypto_context` | boolean | Optional; defaults to `false` |
| `notes` | string | Optional; defaults to an empty string |

Dependencies are QSTriage business/security relationships used for graph and blast-radius analysis. Their meaning is narrower than a general package dependency graph.

### Migration scenario fields

| Field | Type | Contract |
|---|---|---|
| `id` | string | Required, non-empty, unique |
| `name` | string | Required, non-empty |
| `pqc_profile` | string | Required, non-empty |
| `mtu_bytes` | integer | Optional; defaults to 1500 and must be at least 576 |
| `notes` | string | Optional; defaults to an empty string |

## CycloneDX CBOM JSON

QSTriage implements a bounded CBOM import path for explicit cryptographic assets. It does not treat every SBOM component as a cryptographic asset.

A component is selected when either:

- `type` equals `cryptographic-asset`, or
- the component contains `cryptoProperties`.

The document root must be a JSON object and `components`, when present, must be an array. Duplicate JSON keys are rejected. Component and supported crypto metadata fields must have the expected object/array shape, and supported scalar fields cannot contain objects or arrays.

### Imported metadata

QSTriage reads supported values from:

- component `bom-ref`, `name`, and `type`,
- `cryptoProperties.assetType`,
- `cryptoProperties.executionEnvironment`,
- `cryptoProperties.algorithmProperties`,
- `cryptoProperties.protocolProperties`.

Supported algorithm-property fields include:

- `parameterSetIdentifier`,
- `algorithm`,
- `algorithmFamily`,
- `primitive`,
- `executionEnvironment`,
- `keySize`, `keySizeBits`, `keyLength`, or `publicKeySize`,
- `classicalSecurityLevel`,
- `nistQuantumSecurityLevel`.

### Import mapping and conservative defaults

Each selected component becomes one QSTriage asset with these defaults when business context is unavailable:

| QSTriage field | Imported value or default |
|---|---|
| `id` | Normalized from `bom-ref`, then component name, then a fixed fallback |
| `name` | Component name, otherwise the derived algorithm identifier |
| `environment` | CBOM execution environment, otherwise `unknown` |
| `asset_type` | `cbom_cryptographic_asset` |
| `protocol` | Protocol metadata, primitive, asset type, or `unknown` |
| `algorithm` | Derived from explicit algorithm metadata, family/parameter data, or component name |
| `key_size_bits` | Explicit supported key-size field or a bounded numeric identifier extracted from the algorithm string |
| `data_class` | `unknown` |
| `retention_years` | `0` |
| `exposure` | `unknown` |
| `criticality` | `medium` |
| `local_blast_radius` | `medium` |
| `migration_effort` | `medium` |

These defaults represent missing context. They do not assert medium risk or decision-grade evidence.

CBOM dependency relationships are intentionally not imported as QSTriage blast-radius dependencies. Imported inventories therefore contain empty `dependencies` and `scenarios` lists until a reviewer enriches them.

If no supported explicit cryptographic-asset component is present, import fails with no inventory output. PDR generation from that CBOM also fails rather than creating an unjustified decision record.

Algorithm identifier derivation and registry classification are documented in [Standards and Classification](standards-and-classification.md).

## Configuration YAML

The optional configuration file accepts only these sections and fields:

```yaml
outputs:
  report_path: reports/qstriage_report.md
  scores_path: reports/scores.json
  simulations_path: reports/simulations.json

exports:
  default_format: json
```

`exports.default_format` must be `json` or `csv`. Missing sections use the shown defaults. Unknown fields are rejected.

## Contract boundaries

Successful parsing means only that the input satisfies the supported structural contract. It does not establish:

- completeness of cryptographic discovery,
- correctness of declared business context,
- security acceptability of an algorithm,
- decision-grade evidence,
- approval to modify a production system.
