"""RFC 10024 PQ/T hybrid key agreement groups (registry version 2).

Excerpts below are verbatim text from the cited sources. They are pinned here
so that any edit to the registry text fails a test and is reviewed.
"""

from __future__ import annotations

import itertools

import pytest

from qstriage.algorithm_registry import Lifecycle, load_registry, normalize_identifier
from qstriage.models import load_inventory
from qstriage.pdr import generate_pdr_document
from qstriage.policy import get_policy_pack
from qstriage.standards import classify_algorithm


RFC_S3 = "[RFC9954] also defines a \"hybrid\" key exchange as the simultaneous use of multiple key exchange algorithms, with their outputs combined to provide security as long as at least one of the component algorithms remains secure, even if the others are compromised."
RFC_S5_INTRO = "This section provides informal notes on how the hybrid key agreement mechanisms defined in this document relate to existing NIST guidance on key derivation and hybrid key establishment."
RFC_S5_X25519 = "In contrast, for X25519MLKEM768, the ML-KEM implementation must be certified."
RFC_S5_ECDHE = "This means that for SecP256r1MLKEM768 and SecP384r1MLKEM1024, the ECDHE implementation must be certified, whereas the ML-KEM implementation does not require certification."
RFC_S7 = "These identifiers are to be used with the final version of ML-KEM ratified by NIST, which is specified in [NIST-FIPS-203]."
SP_800_227_S462 = "This publication approves the use of the key combiner (14) for any t > 1 if at least one shared secret (i.e., S_j for some j) is generated from the key-establishment methods in SP 800-56A [1] or SP 800-56B [2] or an approved KEM."

GROUPS = {
    "X25519MLKEM768": {
        "entry_id": "tls-group-x25519mlkem768",
        "components": ("ML-KEM-768", "X25519"),
        "certification_component": "ML-KEM-768",
        "order_excerpt": "For X25519MLKEM768, the shared secret is the concatenation of the ML-KEM shared secret and the X25519 shared secret.",
        "certification_excerpt": RFC_S5_X25519,
    },
    "SecP256r1MLKEM768": {
        "entry_id": "tls-group-secp256r1mlkem768",
        "components": ("secp256r1", "ML-KEM-768"),
        "certification_component": "secp256r1",
        "order_excerpt": "For SecP256r1MLKEM768, the shared secret is the concatenation of the ECDHE and ML-KEM shared secrets.",
        "certification_excerpt": RFC_S5_ECDHE,
    },
    "SecP384r1MLKEM1024": {
        "entry_id": "tls-group-secp384r1mlkem1024",
        "components": ("secp384r1", "ML-KEM-1024"),
        "certification_component": "secp384r1",
        "order_excerpt": "For SecP384r1MLKEM1024, the shared secret is the concatenation of the ECDHE and ML-KEM shared secrets.",
        "certification_excerpt": RFC_S5_ECDHE,
    },
}

# RFC 10024, Section 2: "secp256r1 (NIST P-256)" and "secp384r1 (NIST P-384)".
RFC_CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384"}


def _excerpts(entry_id: str) -> dict[tuple[str, str | None], str | None]:
    entry = load_registry().entry(entry_id)
    return {(source.source_id, source.section): source.excerpt for source in entry.sources}


@pytest.mark.parametrize("group", sorted(GROUPS))
def test_group_name_classifies_as_standardized_pq_t_hybrid(group: str) -> None:
    expected = GROUPS[group]
    classification = classify_algorithm(group)

    assert classification.registry_entry_id == expected["entry_id"]
    assert classification.algorithm_family == "pq_t_hybrid_kem"
    assert classification.primitive == "key_establishment"
    assert classification.quantum_status == "quantum_resistant"
    assert classification.standard_status == "standardized_pq_t_hybrid"
    assert classification.identifier_resolution == "exact_identifier"
    assert classification.scheme_type == "pq_t_hybrid"
    assert classification.components == expected["components"]
    assert classification.certification_component == expected["certification_component"]
    assert classification.source_ids == ("RFC-10024", "NIST-SP-800-227", "NIST-FIPS-203")


@pytest.mark.parametrize("group", sorted(GROUPS))
def test_registry_holds_verbatim_source_text(group: str) -> None:
    expected = GROUPS[group]
    excerpts = _excerpts(expected["entry_id"])

    assert excerpts[("RFC-10024", "Section 3")] == RFC_S3
    assert excerpts[("RFC-10024", "Section 4.3")] == expected["order_excerpt"]
    assert excerpts[("RFC-10024", "Section 5, introduction")] == RFC_S5_INTRO
    assert excerpts[("RFC-10024", "Section 5, FIPS-compliance")] == (
        expected["certification_excerpt"]
    )
    assert excerpts[("RFC-10024", "Section 7")] == RFC_S7
    assert excerpts[("NIST-SP-800-227", "Section 4.6.2")] == SP_800_227_S462
    assert excerpts[("NIST-FIPS-203", None)] is None


@pytest.mark.parametrize("group", sorted(GROUPS))
def test_components_resolve_to_registry_classifications(group: str) -> None:
    for component in GROUPS[group]["components"]:
        if component.startswith("ML-KEM-"):
            classification = classify_algorithm(component)
            assert classification.algorithm_family == "ML-KEM"
            assert classification.identifier_resolution == "exact_identifier"
        else:
            name = RFC_CURVE_NAMES.get(component, component)
            assert classify_algorithm(name).algorithm_family == "ECC"


@pytest.mark.parametrize(
    "spelling",
    (
        "X25519-ML-KEM-768",
        "x25519_mlkem768",
        "ML-KEM-768+X25519",
        "MLKEM768X25519",
        "X25519MLKEM768-ECDHE",
        "SecP256r1-MLKEM768",
        "P256MLKEM768",
        "SecP384r1MLKEM768",
        "SecP256r1MLKEM1024",
        "X25519Kyber768Draft00",
        "SecP256r1Kyber768Draft00",
    ),
)
def test_other_spellings_and_pre_standard_names_get_no_positive_classification(
    spelling: str,
) -> None:
    classification = classify_algorithm(spelling)

    assert classification.quantum_status != "quantum_resistant"
    assert classification.standard_status not in {
        "standardized_pqc",
        "standardized_pq_t_hybrid",
    }


@pytest.mark.parametrize("group", sorted(GROUPS))
def test_target_state_suggestion_states_certification_requirement(group: str, tmp_path) -> None:
    expected = GROUPS[group]
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text(
        "assets:\n"
        "  - id: edge\n"
        "    name: Edge\n"
        "    environment: production\n"
        "    asset_type: web_gateway\n"
        "    protocol: TLS1.3\n"
        f"    algorithm: {group}\n"
        "    data_class: customer_pii\n"
        "    retention_years: 10\n"
        "    exposure: public_internet\n"
        "    criticality: high\n"
        "    local_blast_radius: high\n"
        "    migration_effort: medium\n",
        encoding="utf-8",
    )
    record = generate_pdr_document(load_inventory(inventory_path)).records[0]
    components = ", ".join(expected["components"])

    assert record.observed_state.scheme_type == "pq_t_hybrid"
    assert record.observed_state.components == list(expected["components"])
    assert record.observed_state.certification_component == (
        expected["certification_component"]
    )
    assert record.decision.action_type.value == "retain_monitor"
    assert record.decision.human_review_required is True
    assert "classification:standardized_pq_t_hybrid" in record.decision.reason_codes
    assert (
        "standardized_pq_t_hybrid_requires_certification_evidence_review"
        in record.policy_evaluation.applied_rule_ids
    )
    [suggestion] = record.target_state_suggestion
    assert suggestion.option == "retain_pq_t_hybrid_kem"
    assert suggestion.standards == ["RFC-10024", "NIST-SP-800-227", "NIST-FIPS-203"]
    assert suggestion.operational_risk == "medium"
    assert suggestion.requires_human_review is True
    assert suggestion.rationale == (
        f"{group} is a PQ/T hybrid key agreement group defined in RFC 10024. "
        f"Components, in shared-secret order (RFC 10024, Section 4.3): {components}. "
        "RFC 10024, Section 5 (informal notes on NIST guidance): "
        f'"{expected["certification_excerpt"]}" '
        "The identifier does not show whether the "
        f"{expected['certification_component']} implementation is certified. "
        "Human review of certification evidence is required."
    )


def test_policy_pack_rule_text_for_pq_t_hybrids() -> None:
    pack = get_policy_pack()
    [rule] = [
        rule
        for rule in pack.rules
        if rule.rule_id == "standardized_pq_t_hybrid_requires_certification_evidence_review"
    ]

    assert pack.version == "0.3"
    assert rule.title == "Standardized PQ/T hybrid requires certification evidence review"
    assert rule.description == (
        "Records a PQ/T hybrid key agreement group defined in RFC 10024 and "
        "requires human review of implementation certification evidence."
    )
    assert rule.rationale == (
        "RFC 10024, Section 5 names the component whose implementation must be "
        "certified. An algorithm identifier does not show whether that "
        "implementation is certified."
    )
    assert rule.recommendation == (
        "Obtain evidence that the implementation of the component named in "
        "certification_component is certified, and record the review outcome."
    )
    assert rule.references == ["RFC-10024", "NIST-SP-800-227", "NIST-FIPS-203"]
    assert rule.applicability.conditions == {"standard_status": "standardized_pq_t_hybrid"}


def test_no_text_states_that_a_hybrid_is_approved() -> None:
    texts = []
    for entry in load_registry().entries:
        if entry.scheme_type.value != "single":
            texts.append(entry.rationale)
            texts.append(entry.recommended_action)
    pack = get_policy_pack()
    for rule in pack.rules:
        if "pq_t_hybrid" in rule.rule_id:
            texts.extend([rule.title, rule.description, rule.rationale, rule.recommendation])

    for text in texts:
        assert "approved" not in text.lower()


# Property tests over deterministic corpora (no random input).

_SEPARATORS = ("", "-", "_", " ", "/", "+", ".")
_CLASSICAL = ("X25519", "X448", "P256", "P-256", "SECP256R1", "ECDHE", "RSA", "ED25519")
_PQ = ("MLKEM768", "ML-KEM-768", "MLKEM1024", "KYBER768", "MLDSA65", "SLHDSA", "FALCON512")


def _generated_hybrid_spellings() -> list[str]:
    values = set()
    for classical, pq, sep in itertools.product(_CLASSICAL, _PQ, _SEPARATORS):
        values.add(f"{classical}{sep}{pq}")
        values.add(f"{pq}{sep}{classical}")
        values.add(f"{classical}{sep}{pq}".lower())
    return sorted(values)


def test_normalization_is_idempotent() -> None:
    corpus = _generated_hybrid_spellings() + sorted(GROUPS) + ["  ml__kem / 768  ", "a//b--c"]
    for value in corpus:
        once = normalize_identifier(value)
        assert normalize_identifier(once) == once


def test_every_registry_identifier_resolves_to_its_own_entry() -> None:
    for entry in load_registry().entries:
        for identifier in entry.identifiers:
            assert classify_algorithm(identifier).registry_entry_id == entry.entry_id


def test_pq_marker_identifiers_outside_the_registry_get_no_positive_classification() -> None:
    listed = {
        normalize_identifier(identifier)
        for entry in load_registry().entries
        for identifier in entry.identifiers
    }
    checked = 0
    for value in _generated_hybrid_spellings():
        if normalize_identifier(value) in listed:
            continue
        classification = classify_algorithm(value)
        assert classification.quantum_status != "quantum_resistant", value
        assert classification.standard_status not in {
            "standardized_pqc",
            "standardized_pq_t_hybrid",
        }, value
        checked += 1
    assert checked > 500


def test_unpublished_entries_give_no_positive_classification() -> None:
    for entry in load_registry().entries:
        if entry.lifecycle != Lifecycle.published:
            assert not entry.is_positive
