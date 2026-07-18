# Build Week demo script

Target runtime: **2:45**. Pre-stage the repository, terminal, CBOM, patch, and comparison files before recording. Use copy/paste or command history; no live typing is required.

## 0:00-0:12 - Opening

**Screen action:** Show the QSTriage README title and the Evidence Closure workflow diagram. Keep a terminal open beside it.

**Voiceover:** “QSTriage Evidence Closure turns incomplete cryptographic inventories into a human-approved, provenance-aware workflow. The assistant helps collect evidence, while QSTriage remains the deterministic decision authority.”

## 0:12-0:29 - Raw CBOM

**Screen action:** Open `examples/build-week/sample_cbom.json`. Highlight the single `customer-api-rsa` component, RSA-2048 parameter set, and empty dependencies list.

**Terminal command:**

```bash
python -m qstriage.cli import cbom examples/build-week/sample_cbom.json --output demo/imported.yaml
```

**Voiceover:** “We start with a synthetic CycloneDX 1.6 CBOM. It identifies one Customer API RSA signing key, but it contains no QSTriage business context or imported blast-radius dependencies.”

## 0:29-0:49 - Gated evidence result

**Screen action:** Run the evidence review, then hold on the table showing evidence `0.00`, confidence cap `0.50`, not decision-grade, and human review required.

**Terminal command:**

```bash
python -m qstriage.cli review evidence demo/imported.yaml
```

**Voiceover:** “The raw import is correctly constrained. Its evidence score is zero, confidence is capped at zero point five, and evidence review is not decision-grade. The canonical migration action is gated because verification is still required.”

## 0:49-1:10 - Exact gaps

**Screen action:** Run gap inspection. Slowly highlight the seven returned fields: data class, retention, exposure, criticality, local blast radius, migration effort, and relationship completeness.

**Terminal command:**

```bash
python -m qstriage.cli closure inspect demo/imported.yaml
```

**Voiceover:** “QSTriage produces seven structured questions. These are the only facts the workflow asks for. It does not infer business meaning from the asset name, and unknown remains an acceptable answer.”

## 1:10-1:31 - Codex/GPT-5.6 evidence interview

**Screen action:** Show a prepared Codex conversation using the `qstriage-evidence-closure` skill. Display `inspect_evidence_gaps`, two concise operator answers, and the distinction between declared and verified. Show the model selector with `gpt-5.6-sol` briefly.

**Voiceover:** “Using GPT-5.6 through the repository Codex skill, the operator is asked only about unresolved fields. Declared claims remain distinct from verified claims, and verified evidence requires a source reference. The model cannot establish that a supplied fact is true.”

## 1:31-1:49 - Draft patch

**Screen action:** Open `examples/build-week/approved_enrichment.patch.yaml`. Highlight the source inventory hash, assertion state, provenance, and source references. Do not imply that the model approved it.

**Voiceover:** “The result is a complete draft patch bound to the exact source inventory hash. Every claimed value carries state, provenance, and a reference. This demo uses clearly synthetic facts.”

## 1:49-2:08 - Human validation and apply

**Screen action:** Show the operator reviewing the prepared patch, then run validation and apply. Emphasize that apply writes a new file.

**Terminal commands:**

```bash
python -m qstriage.cli closure validate demo/imported.yaml examples/build-week/approved_enrichment.patch.yaml
python -m qstriage.cli closure apply demo/imported.yaml examples/build-week/approved_enrichment.patch.yaml --output demo/enriched.yaml
```

**Voiceover:** “The human reviews every assertion, then explicitly validates and applies the patch. QSTriage rejects stale hashes or unsafe values and writes a new enriched inventory; the original is never overwritten.”

## 2:08-2:34 - Deterministic comparison

**Screen action:** Run comparison and hold on all metrics and finding lists.

**Terminal command:**

```bash
python -m qstriage.cli closure compare demo/imported.yaml demo/enriched.yaml
```

**Voiceover:** “The deterministic comparison closes all seven findings. Evidence score moves from zero to one, and confidence cap from zero point five to one. The action remains migration planning, execution remains gated, and verification priority remains high. Better evidence does not manufacture a more dramatic migration decision.”

## 2:34-2:45 - Trust-boundary close

**Screen action:** Show the final disclaimer from the comparison, then the project title. Keep “decision-grade evidence is not production authorization” visible.

**Voiceover:** “Decision-grade evidence is not production authorization. GPT-5.6 does not invent or approve the risk decision. It helps the operator close the exact evidence gaps identified by QSTriage, while the deterministic engine remains the final authority.”
