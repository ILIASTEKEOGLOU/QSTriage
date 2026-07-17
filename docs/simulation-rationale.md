# QSTriage Simulation Rationale

QSTriage provides a deterministic planning heuristic for basic hybrid post-quantum migration impact. It estimates relative handshake-size pressure and emits review warnings before any production change.

This document describes the public behavior implemented by `qstriage/simulator.py`. Code and tests remain authoritative for executable behavior.

## Scope

The simulator is intended to help identify assets and scenarios that deserve compatibility testing. It is not:

- a packet-level network simulator,
- a TLS, SSH, or IPsec protocol implementation,
- a benchmark of a real cryptographic library,
- a latency or throughput predictor,
- proof that a migration will succeed or fail,
- authorization to change production systems.

Results depend only on the validated QSTriage inventory, migration scenarios, and declared QSTriage dependency graph.

## Scenario selection

For every migration scenario, QSTriage produces one result per asset.

When the inventory contains no scenarios, QSTriage uses this default:

| Field | Value |
|---|---|
| `id` | `default-hybrid-kem` |
| `name` | `Default hybrid KEM migration path` |
| `pqc_profile` | `ML-KEM-768 + X25519` |
| `mtu_bytes` | `1500` |
| `notes` | `Default local-first simulation scenario.` |

A scenario requires an ID, name, non-empty PQC profile, and an MTU of at least 576 bytes. Inventory validation limits the total number of asset/scenario results to 20,000.

## Estimated handshake size

For an asset and scenario:

```text
estimated_handshake_bytes =
    protocol_baseline_bytes
    + pqc_profile_overhead_bytes
    + (outgoing_crypto_dependency_count × 80)
```

This is a planning estimate, not a measured wire size.

### Protocol baseline

The first matching protocol marker determines the baseline:

| Protocol marker | Baseline bytes |
|---|---:|
| `MTLS` or `M/TLS` | 1300 |
| `TLS` or `HTTPS` | 900 |
| `SSH` | 800 |
| `IPSEC` | 1000 |
| no recognized marker | 600 |

Matching is case-insensitive and substring-based.

### PQC profile overhead

The profile is uppercased, hyphens are converted to underscores, and spaces are removed before matching.

The first matching KEM profile contributes:

| Profile marker | Bytes |
|---|---:|
| `ML_KEM_512` or `KYBER512` | 900 |
| `ML_KEM_768` or `KYBER768` | 1184 |
| `ML_KEM_1024` or `KYBER1024` | 1624 |
| no recognized marker | 1000 |

QSTriage then adds:

- 64 bytes when the normalized profile contains `X25519`, `ECDHE`, or `P256`,
- 96 bytes of fixed framing allowance.

For example, the default `ML-KEM-768 + X25519` profile contributes `1184 + 64 + 96 = 1344` estimated bytes.

These constants are explicit heuristic parameters. They are not normative sizes for every protocol encoding or implementation.

### Dependency contribution

Only outgoing graph edges from the asset with `carries_crypto_context: true` are counted. Each contributes 80 estimated bytes.

The count does not infer dependencies from a CBOM. It uses only QSTriage dependencies declared in the inventory. The edge direction is the declared `source` to `target` graph direction.

The current graph is a directed simple graph. Multiple dependency records with the same source and target do not create parallel simulation edges.

## MTU ratio and fragmentation risk

The raw MTU ratio is:

```text
estimated_handshake_bytes / scenario.mtu_bytes
```

The returned ratio is rounded to two decimal places, but risk thresholds are evaluated using the unrounded value.

| MTU ratio | Fragmentation risk |
|---:|---|
| `>= 1.50` | `critical` |
| `>= 1.00` and `< 1.50` | `high` |
| `>= 0.85` and `< 1.00` | `medium` |
| `< 0.85` | `low` |

This label indicates estimated size pressure. It does not prove IP fragmentation or protocol failure.

## Middlebox risk

Middlebox risk uses normalized exposure, protocol markers, asset-type markers, and MTU ratio.

An external path is an exposure normalized to `public` or `partner`.

A constrained path is an asset type containing `ot`, `industrial`, or `gateway`.

A TLS-like path is a protocol containing `TLS` or `HTTPS`.

The current rules are:

| Condition | Middlebox risk |
|---|---|
| ratio `>= 1.50` and external or constrained path | `critical` |
| ratio `>= 1.00` and external, constrained, or TLS-like path | `high` |
| ratio `>= 0.85` | `medium` |
| otherwise | `low` |

Unknown or unmapped exposure is not guessed to be external. See [Evidence and Context](evidence-and-context.md).

## Compatibility risk

Compatibility risk is assigned in this order:

1. `critical` when migration effort is `critical`,
2. `high` when asset type contains `industrial`, `legacy`, or `mainframe`,
3. `high` when migration effort is `high` or fragmentation risk is `high` or `critical`,
4. `medium` when migration effort is `medium`,
5. otherwise `low`.

This is a deterministic prioritization rule, not a compatibility test.

## Warning generation

Warnings are emitted when:

- estimated handshake size exceeds scenario MTU,
- fragmentation risk is `high` or `critical`,
- middlebox risk is `high` or `critical`,
- compatibility risk is `high` or `critical`,
- outgoing crypto-bearing dependencies are present,
- the asset is industrial-like or migration effort is `critical`,
- MTU ratio is at least 1.0 and the raw exposure text contains `public` or `partner`.

The final external-path warning uses the supplied exposure text, while the middlebox-risk calculation uses normalized exposure categories.

Warnings recommend path-MTU testing, middlebox review, staged simulation, dependency review, constrained-environment caution, or client and gateway compatibility validation. They do not initiate remediation.

## Result contract

Each result contains:

- asset and scenario identifiers and names,
- PQC profile and asset protocol,
- estimated handshake bytes,
- scenario MTU and rounded MTU ratio,
- fragmentation, middlebox, and compatibility risk labels,
- outgoing crypto-bearing dependency count,
- ordered warning text.

Results are deterministic for the same validated inventory and code version.

## Report behavior

Markdown reports include the simulation result for each asset/scenario pair and render its warnings under the asset finding.

When no QSTriage dependencies are declared, report output separately warns that graph-amplified blast-radius analysis is limited. CBOM dependency relationships are not treated as QSTriage blast-radius dependencies.

## Interpretation boundaries

A high label means the current heuristic found conditions that justify testing and review. A low label means only that no higher current rule matched.

The simulator does not model:

- certificate chains,
- full handshake transcripts,
- transport retransmission,
- implementation-specific framing,
- CPU or memory cost,
- latency, throughput, or packet loss,
- path discovery or real middlebox behavior,
- application retry and timeout behavior,
- protocol negotiation failure,
- scanner completeness.

Production decisions require measurements in the actual protocol, client, network, and operational environment.
