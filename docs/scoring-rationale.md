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

The score is mainly useful for ranking assets inside the same inventory. It should be read together with the asset explanation, evidence review, dependency completeness, decision context review, simulation warnings, and PDR confidence.

## What the score is not

A QSTriage score is not:

- a probability of attack
- a measured incident rate
- a financial loss estimate
- a compliance certification
- a guarantee that migration is safe
- a substitute for cryptographic architecture review
- a substitute for business-owner validation

A high score means “review and plan earlier.” It does not mean “change production immediately.”

A low score means “lower priority under the current evidence.” It does not mean “safe forever.”

## Score components

### Cryptographic risk

Cryptographic risk comes from the QSTriage algorithm registry.

Classical public-key algorithms such as RSA, finite-field Diffie-Hellman, and elliptic-curve cryptography are treated as quantum-vulnerable for PQC migration planning.

Standardized PQC algorithms such as ML-KEM, ML-DSA, and SLH-DSA are treated as quantum-resistant categories.

Symmetric encryption and hash algorithms are classified separately from public-key migration targets.

Unknown algorithms are treated conservatively and require manual review.

### Shelf-life risk

Shelf-life risk reflects how long protected data may need to remain confidential or trustworthy.

Longer retention increases planning pressure, especially for sensitive data. This supports “harvest now, decrypt later” planning, but it does not claim that decryption is currently possible.

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

Deadline pressure increases when long-retention data and quantum-vulnerable public-key cryptography appear together.

It is a planning heuristic, not a prediction of when a cryptographic break will happen.

### Migration effort

Migration effort reduces immediate priority when a direct production change would be operationally difficult.

This does not mean the asset is less important. It means the safer next step may be simulation, staged remediation planning, or architecture review before production changes.

## Combining components into one score

The components are summed and scaled into a 0-100 range.

The scaling step exists for readability. It carries no independent risk meaning. Changing only the scaling factor would not change the relative ranking between assets.

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

## CBOM-derived scores

CBOM-derived assets often contain cryptographic metadata but little business context.

Their scores can help decide what to inspect first. They should not be treated as decision-grade until missing business and dependency context is supplied.

## Safe interpretation

The safest interpretation is:

> QSTriage scores are deterministic, explainable planning heuristics for cryptographic migration prioritization.

When input evidence or algorithm-classification rules used by scoring change, scores may change. Policy rules do not directly change the numeric score; they can change findings, gating, and the canonical decision. Those changes should be tracked through review and PDR generation.
