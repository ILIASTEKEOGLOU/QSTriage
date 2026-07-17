# QSTriage CBOM Compatibility

QSTriage provides a bounded import path for CycloneDX-style CBOM JSON cryptographic evidence. It converts supported cryptographic asset components into validated QSTriage inventory assets and can generate reports and PDR 0.2 documents from that inventory.

This document describes the public compatibility boundary implemented by `qstriage/cbom.py` and validated by the Track 5.1 external compatibility lab. Code and tests remain authoritative for executable behavior.

## Supported input boundary

QSTriage accepts UTF-8 JSON with:

- a JSON object at the document root,
- an optional `components` field that, when present, is a JSON array,
- at most 10,000 components,
- at most 32 MiB of captured input.

The parser rejects:

- duplicate JSON object keys,
- non-object document roots,
- non-array `components`,
- non-object component entries,
- non-object `cryptoProperties`,
- non-object `algorithmProperties` or `protocolProperties`,
- objects or arrays where supported metadata fields require scalar values,
- JSON that triggers a recursion-depth failure during parsing,
- documents that produce no supported cryptographic assets.

QSTriage performs bounded structural validation for the fields it consumes. It does not claim full CycloneDX schema validation and does not require every field defined by the wider CycloneDX specification.

Input limits and capture behavior are documented in [Input Contracts](input-contracts.md).

## Cryptographic asset selection

A component is treated as a cryptographic asset when either:

- `type` is exactly `cryptographic-asset`, or
- the component contains `cryptoProperties`.

Other components are ignored by the importer.

When no supported cryptographic asset component remains, import and PDR generation fail with:

```text
CBOM contains no cryptographic asset components.
```

This is fail-closed behavior for the supported importer boundary. It is not evidence that the source repository or system contains no cryptography.

## Imported asset mapping

Each supported component becomes one QSTriage asset.

| QSTriage field | CBOM source or default |
|---|---|
| `id` | normalized `bom-ref`, then component name, then a fixed fallback |
| `name` | component name, then derived algorithm identifier |
| `environment` | crypto execution environment, algorithm execution environment, then `unknown` |
| `asset_type` | `cbom_cryptographic_asset` |
| `protocol` | protocol metadata for protocol assets; otherwise primitive, asset type, then `unknown` |
| `algorithm` | bounded algorithm derivation described below |
| `key_size_bits` | supported key-size fields or a 3–5 digit sequence in the algorithm identifier |
| `data_class` | `unknown` |
| `retention_years` | `0` |
| `exposure` | `unknown` |
| `criticality` | `medium` |
| `local_blast_radius` | `medium` |
| `migration_effort` | `medium` |
| `notes` | review-required marker plus selected crypto metadata |

Imported business and operational values are conservative placeholders. Evidence review marks them as missing or defaulted and requires human review. See [Evidence and Context](evidence-and-context.md).

## Algorithm identifier derivation

QSTriage selects the first available supported signal in this order:

1. `parameterSetIdentifier`,
2. explicit `algorithm`,
3. `algorithmFamily`,
4. component name, except for assets explicitly typed as protocols,
5. `unknown`.

Supported structural combinations include:

- parameter identifiers joined to a supplied family,
- `ML-KEM` parameter sets 512, 768, and 1024,
- `ML-DSA` parameter sets 44, 65, and 87,
- RSA family plus key size,
- AES family plus key size,
- cdxgen forms `aes256-CBC` and `aes256-GCM`.

The cdxgen AES forms normalize to `AES-256-CBC` and `AES-256-GCM`.

After import, algorithm classification uses the bounded registry described in [Standards and Classification](standards-and-classification.md). Unknown identifiers remain unknown and require manual cryptographic verification.

## Key-size extraction

QSTriage checks these algorithm-property fields in order:

1. `keySize`,
2. `keySizeBits`,
3. `keyLength`,
4. `publicKeySize`.

An integer value or digit-only string is accepted. If none is present, QSTriage searches the derived algorithm text for the first 3–5 digit sequence.

This is a limited extraction rule and does not infer cryptographic strength.

## Protocol handling

For an asset with `assetType: protocol`, QSTriage derives the protocol from:

1. `protocolProperties.protocol`,
2. `protocolProperties.name`,
3. component name,
4. asset type,
5. `protocol`.

Protocol assets do not use the component name as an algorithm fallback. Their algorithm remains `unknown` when no supported algorithm metadata exists.

For other assets, protocol is derived from:

1. algorithm primitive,
2. asset type,
3. `unknown`.

## Dependency boundary

CycloneDX or scanner dependency relationships are not imported as QSTriage business or security dependencies.

Generated inventories therefore contain:

```yaml
dependencies: []
scenarios: []
```

until a reviewer supplies QSTriage-specific context.

Consequences include:

- no scanner-derived graph-amplified blast radius,
- unknown relationship completeness in CBOM evidence review,
- explicit report warnings when QSTriage dependencies are absent.

This separation prevents a software dependency graph from being silently treated as a verified business-impact graph.

## Raw evidence and PDR binding

File-backed PDR generation reads the bounded CBOM once. The same captured bytes are decoded, parsed, and hashed for `input_snapshot.source_hash`.

QSTriage preserves the source evidence hash but does not copy every scanner field into the normalized inventory. The PDR contract is documented in [PDR Contract](pdr-contract.md).

## Track 5.1 validation baseline

The external compatibility lab was completed on 2026-07-12 with:

- QSTriage 1.1.0 at main commit `645a10b`,
- PDR contract 0.2,
- cdxgen 12.7.1,
- Node.js 24.17.0,
- CycloneDX 1.7 output,
- cdxgen options `--include-crypto`, `--evidence`, `--deep`, `--no-install-deps`, `--fail-on-error`, and `--json-pretty`.

External repository dependencies were not installed and external project code was not executed.

### Controlled calibration

The upstream cdxgen `cbom-js-repotest` fixture emitted eight algorithm assets covering AES, SHA-2, and RSA signatures.

Import and PDR generation succeeded.

The run exposed unsupported cdxgen identifiers `aes256-CBC` and `aes256-GCM`. QSTriage added tests-first normalization and now maps them to canonical AES identifiers without changing the PDR contract, scoring, policy, confidence semantics, or raw evidence.

### Real-world cases

| Case | Scanner output | QSTriage result | Boundary demonstrated |
|---|---|---|---|
| `panva/jose` | 0 supported crypto assets | import and PDR refused | No emitted asset is not proof of no cryptography |
| `FilenCloudDienste/filen-cli` | 1 MD5 asset | imported; unknown registry classification; verification-first decision | Successful import plus missed production AES-GCM scanner coverage |
| `node-saml/node-saml` | 8 certificate or key assets under `test/static` | artifact contained supported explicit assets | Certificate discovery plus missed production RSA signing calls |
| `byteball/ocore` | RIPEMD160, SHA-1, SHA-256 | 3 assets imported; one PDR with 3 records | End-to-end real-world positive |

For the `byteball/ocore` captured input:

- QSTriage inventory output was byte-identical across two runs,
- PDR output was byte-identical across two runs,
- the exact raw CBOM source hash was preserved.

A repeated cdxgen scan produced a different raw CBOM hash because scanner metadata may vary, while the normalized crypto-asset projection remained semantically identical.

## Compatibility statement

The demonstrated compatibility claim is limited to:

- QSTriage 1.1.0 importer behavior,
- tested CycloneDX 1.7 artifact structures,
- cdxgen 12.7.1 output used by the lab,
- the documented input and workload limits,
- explicit cryptographic assets emitted by the scanner,
- the current normalization and classification registry.

It is not a claim of universal CycloneDX, CBOM, scanner, language, repository, or cryptographic API compatibility.

## Explicit non-claims

QSTriage does not claim:

- complete source-code cryptography discovery,
- correct detection of every cryptographic API call,
- absence of cryptography when a scanner emits no supported asset,
- equivalence between a scanner dependency graph and a business-impact graph,
- security approval because a component parsed successfully,
- automatic policy approval from scanner output,
- full CycloneDX schema validation,
- support for every CBOM producer or version,
- semantic equivalence of raw scanner files across separate scans.

Scanner coverage, importer compatibility, evidence quality, algorithm classification, and canonical decisions are separate boundaries and must be reviewed separately.
