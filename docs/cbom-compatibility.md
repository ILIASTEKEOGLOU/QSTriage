# QSTriage CBOM Compatibility

QSTriage provides a bounded import path for CycloneDX-style CBOM JSON cryptographic evidence. It converts supported cryptographic asset components into validated QSTriage inventory assets and can generate reports and PDR 0.3 documents from that inventory.

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
- nesting deeper than 64 levels, detected before parsing,
- unpaired surrogate code points in keys or string values,
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
| `key_size_bits` | an explicit key-size field only (see below); otherwise null |
| `cbom_key_sizes` | only for RSA when the size fields disagree (see below); otherwise absent |
| `data_class` | `unknown` |
| `retention_years` | `0` |
| `exposure` | `unknown` |
| `criticality` | `medium` |
| `local_blast_radius` | `medium` |
| `migration_effort` | `medium` |
| `notes` | review-required marker plus selected crypto metadata |

Imported business and operational values are conservative placeholders. Evidence review marks them as missing or defaulted and requires human review. See [Evidence and Context](evidence-and-context.md).

## Algorithm identifier derivation

QSTriage keeps the identifier the source states. It selects the first
available signal in this order:

1. a full `parameterSetIdentifier` (not a bare number), such as `RSA-2048`,
2. a full `algorithm`,
3. a bare `parameterSetIdentifier` through an explicit mapping (below),
4. `algorithmFamily`,
5. component name, except for assets explicitly typed as protocols,
6. `unknown`.

Explicit mappings for a bare `parameterSetIdentifier`:

- `ML-KEM` with 512, 768, or 1024,
- `ML-DSA` with 44, 65, or 87,
- `AES` with 128, 192, or 256 (the form the CycloneDX CBOM guide uses).

An `algorithm` that only repeats the family (`algorithm: ML-KEM` with
`algorithmFamily: ML-KEM`, or `algorithm: ML-KEM` without a family) is not a
full identifier, so the mapping still applies and yields `ML-KEM-768`.
Family names are compared with the algorithm registry's normalization, so
`ML KEM`, `ml_kem`, and `ML-KEM` are the same family.
Any other bare number is ignored. It never produces an identifier and never
replaces a full identifier stated elsewhere. With an RSA family it is not
mapped, because a bare number in RSA metadata does not reliably name the
modulus: the CycloneDX CBOM guide's RSA signature example carries `512`, the
SHA-512 digest. An identifier is never built from a key-size field or from
digits in a name: `algorithmFamily: RSA` with `keySize: 4096` imports as
`algorithm: RSA` and `key_size_bits: 4096`.

The cdxgen forms `aes256-CBC` and `aes256-GCM` are full identifiers and
normalize to `AES-256-CBC` and `AES-256-GCM`.

After import, algorithm classification uses the bounded registry described in [Standards and Classification](standards-and-classification.md). Unknown identifiers remain unknown and require manual cryptographic verification.

## Key-size extraction

QSTriage checks these algorithm-property fields in order:

1. `keySize`,
2. `keySizeBits`,
3. `keyLength`,
4. `publicKeySize`.

Each field is read as follows:

| Value in the CBOM | Result |
|---|---|
| JSON integer from 0 to 2^53, or a string of ASCII digits with that value (leading zeros allowed, so `"0002048"` is 2048) | a size |
| `null` | treated as absent, without a notice |
| boolean, negative or larger integer, number with a fraction or exponent (`2048.0`), any other string (`"2048 bits"`, `""`, non-ASCII digits) | ignored; the import prints a notice naming the component, its asset ID, the field, and its value (shortened when long) |
| array or object | the import stops with an error, because every listed field must be a JSON scalar value |

2^53 is the integer range QSTriage writes to a PDR. If no field holds a size,
`key_size_bits` stays null.

When the size fields agree, their value becomes `key_size_bits`. When they
disagree:

- RSA: all disagreeing fields are kept in `cbom_key_sizes`, as written in the
  CBOM, and `key_size_bits` stays null. The evaluation reports
  `conflicting_key_size` (see
  [Evidence and Context](evidence-and-context.md#key-size-used-for-scoring));
  correct the CBOM and import it again.
- Other algorithms: the first field in the order above is kept, as before, and
  the import prints a notice that the fields disagree. Only RSA sizes are
  compared, because only the RSA score depends on a key size.

`import cbom`, `review evidence --input-format cbom`, and
`pdr generate --input-format cbom` print these notices. QSTriage does not take a size from digits in the
algorithm text or the component name, so `ML-KEM-768`, `SHA-256`, and
`X25519MLKEM768` import without a key size. For an RSA identifier that states
a modulus length, such as `RSA-2048`, scoring uses that length and records
that it comes from the identifier (see
[Evidence and Context](evidence-and-context.md#key-size-used-for-scoring)).

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
