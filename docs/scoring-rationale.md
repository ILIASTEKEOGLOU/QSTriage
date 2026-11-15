# QSTriage Scoring Rationale

QSTriage priority scores are deterministic planning heuristics.

They help answer one practical question:

> Which cryptographic assets should be reviewed and planned first?

They do not answer:

> What is the measured probability of compromise, failure, or loss?

Scores are useful because they are explainable, repeatable, and auditable. They are limited because they depend on the supplied inventory, current registry rules, and declared business context.

## What the score represents

The priority score is a 0-100 planning signal.

It combines seven factors:

- cryptographic risk
- data shelf-life
- exposure
- business criticality
- graph-amplified blast radius
- deadline pressure
- migration effort

The score is mainly useful for ranking assets inside the same inventory. An asset whose algorithm classification has standard status `unknown` (an unrecognized identifier, or a recognized family without a supported parameter set) has execution state `verification_first` and gets no backlog rank: `score`, `report`, and `export scores` list it separately under "Verify First", ordered by risk attention and then asset ID, because its score rests on a guessed algorithm. The score exports still carry its planning score. It should be read together with the asset explanation, evidence review, dependency completeness, decision context review, simulation warnings, and PDR confidence.

## What the score is not

A QSTriage score is not:

- a probability of attack
- a measured incident rate
- a financial loss estimate
- a compliance certification
- a guarantee that migration is safe
- a substitute for cryptographic architecture review
- a substitute for business-owner validation

A high score means "review and plan earlier." It does not mean "change production immediately."

A low score means "lower priority under the current evidence." It does not mean "safe forever."

## Score components

### Cryptographic risk

Cryptographic risk comes from the QSTriage algorithm registry.

Classical public-key algorithms such as RSA, finite-field Diffie-Hellman, and elliptic-curve cryptography are treated as quantum-vulnerable for PQC migration planning.

Standardized PQC algorithms such as ML-KEM, ML-DSA, and SLH-DSA are treated as quantum-resistant categories.

Symmetric encryption and hash algorithms are classified separately from public-key migration targets.

Unknown algorithms are treated conservatively and require manual review.

### Shelf-life risk

Shelf-life risk reflects how long protected data may need to remain confidential or trustworthy.

Longer retention increases planning pressure, especially for sensitive data. This supports "harvest now, decrypt later" planning, but it does not claim that decryption is currently possible.

### Exposure risk

Exposure risk reflects how reachable the asset appears from the inventory.

Public or internet-facing exposure receives higher planning pressure than isolated or internal exposure. Unknown exposure should be treated as incomplete context.

### Criticality score

Criticality reflects the business importance declared in the inventory.

QSTriage uses this as a planning input. It does not independently verify the business value of the asset.

### Graph-amplified blast radius

Graph-amplified blast radius reflects local and downstream dependency impact when QSTriage dependencies are supplied.

If no QSTriage dependencies are declared, this part of the score is limited. CBOM dependency relationships are not currently imported as QSTriage blast-radius dependencies.

### Deadline pressure

Deadline pressure is 5 points when `retention_years` is at least 10 and the
cryptographic risk component is at least 8.0; quantum-vulnerable RSA with a
modulus above 3072 bits scores 7.0 and does not reach this step. Otherwise it
is 3 points when `retention_years` is at least 5 and the exposure is public or
partner, and 1 point in every other case. It reads the cryptographic risk
already computed for the asset, so both components use the same key size.

It is a planning heuristic, not a prediction of when a cryptographic break will happen.

### Migration effort

Migration effort reduces immediate priority when a direct production change would be operationally difficult.

This does not mean the asset is less important. It means the safer next step may be simulation, staged remediation planning, or architecture review before production changes.

## Combining components into one score

The components are summed and scaled into a 0-100 range.

The scaling step exists for readability. It carries no independent risk meaning. The sum is multiplied by 2, capped to 0-100, and rounded to two decimals. Changing only the scaling factor keeps the order of the raw sums, but the cap and the rounding can then make assets with different raw sums show the same score.

## Where the weights come from

The exact numeric weights are not derived from an empirical dataset of breach probabilities, incident rates, or measured quantum attacks. QSTriage does not claim that such a dataset exists.

The weights encode a conservative ordering judgment:

- classical public-key cryptography ranks above symmetric encryption and hash algorithms for PQC migration planning
- standardized PQC algorithms rank below quantum-vulnerable classical public-key algorithms
- smaller RSA key sizes rank above larger RSA key sizes
- unknown algorithms require manual review instead of being treated as safe

This ordering follows the same categories used by the QSTriage standards registry: NIST IR 8547 Initial Public Draft for quantum-vulnerable RSA, finite-field Diffie-Hellman, and elliptic-curve public-key cryptography; FIPS 203, FIPS 204, and FIPS 205 for ML-KEM, ML-DSA, and SLH-DSA; and NIST SP 800-57 Part 1 Revision 5 for classical security-strength context.

These standards do not publish QSTriage numeric scores. They inform the category ordering, not the exact numbers.

Future work may replace or refine the current weights through structured expert elicitation, sensitivity analysis, or field calibration.

## Priority bands

QSTriage maps the numeric score into four backlog labels:

- critical
- high
- medium
- low

These are triage labels for planning and communication. They do not replace human decision-making.

## Unresolved context is scored at its worst case

A context field that cannot be used (missing, withheld, not an accepted label,
defaulted on a CBOM import, or a zero retention that nobody confirmed) is
scored at its most severe value. Missing evidence can therefore raise an asset
in the backlog; it never lowers one.

| Field | Scored as when unresolved |
|---|---|
| `data_class` | sensitive |
| `exposure` | public |
| `retention_years` | 10 years |
| `criticality` | critical |
| `local_blast_radius` | critical |
| `migration_effort` | low (the smallest effort penalty) |

The dependency graph uses the same values, so an unresolved downstream
criticality also counts at its worst case for the assets that depend on it.

An RSA key size conflict is also scored at its worst case: when the stated
sizes differ (the RSA identifier, `key_size_bits`, and the CBOM size fields in
`cbom_key_sizes`), the smallest is scored, and the assumption names every
stated value (see
[Evidence and Context](evidence-and-context.md#key-size-used-for-scoring)).

Every substitution is visible. The score has a basis: `confirmed` when every
context field the score uses is present and usable and all stated key sizes
agree, `worst case` otherwise.
`score` shows the basis and the substituted fields for ranked assets; the
report shows them for every asset, Verify First included, and lists each
field with its value in the inventory, the problem, and the value scored; the
score export carries `score_basis` and `scoring_assumptions`; the PDR writes
one line per field in `assumptions_made`. Supplying the real values replaces
the assumption. The bundled Evidence Closure demo asset scores 100.0 at worst
case with six fields unresolved and 93.0 confirmed after enrichment.

The substitution changes the score and its band, and every output that reads
the band: verification priority, the high-priority human review condition,
the `risk:<band>_attention` reason code, and the PDR field
`mission_impact_if_delayed`. Execution state, action type, and evidence
findings keep reading their own inputs (evidence, policy, confidence, and the
declared migration effort).

## Relationship to evidence review

Scoring and evidence review are separate.

An asset can have a numeric score while still not being decision-grade. This can happen when business context, exposure, retention, dependency completeness, or algorithm evidence is missing or defaulted.

For governance use, do not read the score alone. Read it with:

- evidence review findings
- decision context review status
- algorithm classification
- dependency scope warnings
- simulation warnings
- PDR decision confidence

## Confidence label

Each score carries a confidence label. PDR decision confidence starts from the
base value of the label and is then limited by evidence quality and evidence
review.

| Label | Condition | Base value |
|---|---|---|
| `medium-high` | the key length is known and every business context field (`data_class`, `exposure`, `retention_years`, `criticality`, `local_blast_radius`, `migration_effort`) is usable | 0.80 |
| `medium` | the key length is known and a business context field is unknown, unrecognized or `redacted`, `retention_years` is 0 without an evidence assertion, or a value is a CBOM import default | 0.65 |
| `low` | the key length is unknown | 0.45 |

The key length is known when `key_size_bits` is stated, when the algorithm
identifier fixes it (such as `RSA-2048`), or when the primitive has no key
(such as a hash). `cbom_key_sizes` does not make it known: a bare `RSA` whose
CBOM size fields disagree has the label `low`. When the identifier fixes the
key length, as with `RSA-2048`, the score label is `medium-high` if all
business context fields are usable and `medium` otherwise. The label is
separate from the decision confidence cap: a size conflict caps decision
confidence at 0.50 and the decision is `gated`. For example, with complete
business context and no other evidence gap, the final decision confidence is
0.45 for the bare `RSA` and 0.50 for `RSA-2048`. Other gaps can lower it
further: for the same assets imported directly from a CBOM, with business
context still at its import defaults, it is 0.00 in both cases.

The default decision-grade threshold is 0.75. Free text in `notes` is not
evidence and does not affect the label; the one exception is the CBOM import
marker that `import cbom` writes into `notes`, which identifies an imported
asset whose `medium` risk levels are import defaults. Whether a field is usable is decided by the context resolver
described in the Evidence and Context guide; an evidence assertion resolves a
CBOM import default.

## CBOM-derived scores

CBOM-derived assets often contain cryptographic metadata but little business context.

Their scores can help decide what to inspect first. They should not be treated as decision-grade until missing business and dependency context is supplied.

## Safe interpretation

The safest interpretation is:

> QSTriage scores are deterministic, explainable planning heuristics for cryptographic migration prioritization.

When input evidence or algorithm-classification rules used by scoring change, scores may change. Policy rules do not directly change the numeric score; they can change findings, gating, and the canonical decision. Those changes should be tracked through review and PDR generation.
