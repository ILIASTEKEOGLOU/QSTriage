import pytest

from qstriage.models import CryptographicAsset, Inventory
from qstriage.pdr import generate_pdr_document


def _pdr_record_for_algorithm(algorithm: str):
    asset = CryptographicAsset(
        id="crypto-test",
        name="Cryptographic Test Asset",
        environment="production",
        asset_type="service",
        protocol="tls",
        algorithm=algorithm,
        key_size_bits=None,
        data_class="telemetry",
        retention_years=1,
        exposure="internal",
        criticality="medium",
        local_blast_radius="medium",
        migration_effort="medium",
    )
    inventory = Inventory(
        assets=[asset],
        dependencies=[],
        scenarios=[],
    )

    return generate_pdr_document(inventory).records[0]


@pytest.mark.parametrize(
    "algorithm",
    [
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
    ],
)
def test_parameterized_pqc_algorithms_do_not_require_key_size(
    algorithm: str,
) -> None:
    record = _pdr_record_for_algorithm(algorithm)

    assert "key_size_bits" not in record.evidence_quality.missing_evidence
    assert record.evidence_quality.score == 1.0


@pytest.mark.parametrize(
    "algorithm",
    [
        "RSA",
        "MysteryCrypto",
    ],
)
def test_non_exempt_algorithms_without_key_size_remain_missing(
    algorithm: str,
) -> None:
    record = _pdr_record_for_algorithm(algorithm)

    assert "key_size_bits" in record.evidence_quality.missing_evidence
    assert record.evidence_quality.score == 0.88


# The parameter set fixes the key length and the asset has complete business
# context, so the score confidence label is "medium-high" (0.80) without
# key_size_bits. Human review stays required: policy pack 0.4 requires it for
# every standardized PQC and ML-KEM asset.
def test_parameter_set_counts_as_known_key_length_for_confidence() -> None:
    record = _pdr_record_for_algorithm("ML-KEM-768")

    assert record.evidence_quality.missing_evidence == []
    assert record.evidence_quality.score == 1.0
    assert record.decision_confidence.score == 0.8
    assert record.decision.confidence_score == 0.8
    assert record.decision.human_review_required is True
    assert record.decision_confidence.reason == (
        "Decision confidence is based on available inventory, scoring, and standards context."
    )
    assert "Missing key_size_bits lowers evidence quality and decision confidence." not in (
        record.assumptions_made
    )
