# QSTriage v0.2.0 Roadmap

## Theme

QSTriage v0.2.0 focuses on CBOM/CycloneDX import lite.

The goal is to let QSTriage consume scanner-generated cryptographic inventory data without pretending that scanner output contains complete business blast-radius context.

Working theme:

QSTriage v0.2.0 — CBOM import and partial inventory generation

## Current baseline

QSTriage v0.1.0 supports:

- YAML inventory validation
- directed dependency graph construction
- graph-amplified blast radius analysis
- explainable PQC migration scoring
- hybrid PQC impact simulation
- narrative Markdown report generation
- JSON and CSV exports
- basic configuration defaults
- CLI commands for validate, score, graph, report, and export

## v0.2.0 priorities

### Priority 1 — CycloneDX CBOM JSON import lite

Goal:

Add a conservative importer that reads CycloneDX-style CBOM JSON and generates a QSTriage YAML inventory.

Expected CLI shape:

```bash
qstriage import cbom input.cbom.json --output imported_inventory.yaml
```

Initial importer behavior:

- Read CycloneDX JSON.
- Detect cryptographic assets from CBOM components.
- Map available crypto metadata into QSTriage `CryptographicAsset` records.
- Preserve algorithm, primitive, parameter set, key size, environment, and security-level hints when available.
- Generate conservative review defaults for business context fields that scanners cannot know.
- Write a valid QSTriage YAML inventory.

### Priority 2 — Explicit partial-import semantics

Goal:

Avoid giving users a false sense that imported CBOM data is a complete QSTriage risk model.

Importer rules:

- Imported CBOM assets become QSTriage assets.
- Imported CBOM dependency relationships are not automatically converted into QSTriage business/security dependencies.
- Generated inventories should use `dependencies: []` unless QSTriage-specific dependency data is provided.
- Imported assets should include notes indicating that business context requires human review.

Reason:

CycloneDX dependency relationships describe software composition and related component structure. QSTriage dependencies describe business/security blast-radius semantics such as auth, dataflow, TLS termination, criticality, weight, and crypto-context propagation. These are related but not equivalent.

### Priority 3 — Report transparency for missing dependencies

Goal:

Make reports honest when an inventory has no declared QSTriage dependencies.

Expected behavior:

- Reports should explicitly state when graph-amplified blast radius is limited because no QSTriage business dependencies were declared.
- Reports should not imply that an imported CBOM dependency graph is equivalent to a QSTriage blast-radius graph.

Candidate message:

```text
Graph-amplified blast radius is limited because no QSTriage business dependencies were declared. CBOM dependency relationships, if present, are not treated as QSTriage blast-radius dependencies.
```

## Deferred candidates

### Standards mapping layer

Useful after CBOM import, because CBOM crypto metadata can provide primitive, algorithm family, parameter set, and security-level fields. QSTriage should consume those fields first and use fallback heuristics only for hand-written YAML inventories.

### Scoring profiles

Useful later, but should be treated as a real scoring refactor rather than a simple config addition. Any scoring profile must be traceable in reports to preserve explainability.

### Regulatory presets

Useful later for NIS2, DORA, CNSA 2.0, and similar frameworks, but should not be mixed into the CBOM importer.

## v0.2.0 acceptance criteria

QSTriage v0.2.0 should be considered ready when:

- Existing v0.1.0 commands still work.
- All tests pass.
- A sample CBOM JSON fixture can be imported.
- Imported output validates as a QSTriage YAML inventory.
- Imported inventories clearly mark business-context defaults as review-required.
- Reports are transparent when no QSTriage dependencies are declared.
- README and usage docs document the import workflow.
- CHANGELOG has a v0.2.0 section.
- A new tag v0.2.0 can be created cleanly.

## Safety boundary

QSTriage remains a local-first decision-support tool.

It must not touch production systems, rotate certificates, change cryptographic settings, deploy PQC algorithms, or perform automated rollout or rollback.
