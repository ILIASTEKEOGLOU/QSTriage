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


# Boundary lock: this track corrects PDR evidence quality only.
# Scoring-derived confidence remains a separate design concern.
def test_pqc_evidence_quality_fix_preserves_legacy_confidence_boundary() -> None:
    record = _pdr_record_for_algorithm("ML-KEM-768")

    assert record.evidence_quality.missing_evidence == []
    assert record.evidence_quality.score == 1.0
    assert record.decision_confidence.score == 0.45
    assert record.decision.confidence_score == 0.45
    assert record.decision.human_review_required is True
    assert record.decision_confidence.reason == (
        "Decision confidence is based on available inventory, scoring, and standards context."
    )
    assert "Missing key_size_bits lowers evidence quality and decision confidence." not in (
        record.assumptions_made
    )
