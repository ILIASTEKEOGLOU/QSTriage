"""One rule decides whether an asset must state key_size_bits.

Evidence review, PDR evidence quality, and the score confidence label all use
qstriage.standards.key_size_requirement.
"""

from __future__ import annotations

import pytest

from qstriage.assessment import evaluate_evidence_quality
from qstriage.evidence import review_asset_evidence
from qstriage.models import CryptographicAsset
from qstriage.scoring import score_inventory
from qstriage.models import Inventory
from qstriage.standards import KeySizeRequirement, classify_algorithm, key_size_requirement


CASES = {
    # Fixed by the identifier.
    "ML-KEM-768": KeySizeRequirement.fixed_by_identifier,
    "SLH-DSA-SHA2-128s": KeySizeRequirement.fixed_by_identifier,
    "X25519MLKEM768": KeySizeRequirement.fixed_by_identifier,
    "SecP384r1MLKEM1024": KeySizeRequirement.fixed_by_identifier,
    "AES-256-GCM": KeySizeRequirement.fixed_by_identifier,
    "AES128": KeySizeRequirement.fixed_by_identifier,
    "RSA-2048": KeySizeRequirement.fixed_by_identifier,
    "RSA4096": KeySizeRequirement.fixed_by_identifier,
    "FFDHE2048": KeySizeRequirement.fixed_by_identifier,
    "P-256": KeySizeRequirement.fixed_by_identifier,
    "ECDSA_P256": KeySizeRequirement.fixed_by_identifier,
    "X25519": KeySizeRequirement.fixed_by_identifier,
    "Ed25519": KeySizeRequirement.fixed_by_identifier,
    # No key.
    "SHA-256": KeySizeRequirement.not_applicable,
    "SHA3-256": KeySizeRequirement.not_applicable,
    "SHAKE128": KeySizeRequirement.not_applicable,
    # Parameter set verified separately.
    "ML-KEM-9999": KeySizeRequirement.parameter_set_unverified,
    "ML-KEM": KeySizeRequirement.parameter_set_unverified,
    # Key length not stated by the identifier.
    "AES": KeySizeRequirement.required,
    "RSA": KeySizeRequirement.required,
    "RSA-PSS": KeySizeRequirement.required,
    "sha256WithRSAEncryption": KeySizeRequirement.required,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": KeySizeRequirement.required,
    "ECDHE": KeySizeRequirement.required,
    "ECDSA": KeySizeRequirement.required,
    "SHA256withECDSA": KeySizeRequirement.required,
    "ECDHE_RSA": KeySizeRequirement.required,
    "DH": KeySizeRequirement.required,
    # Unrecognized identifiers stay conservative.
    "MysteryCrypto": KeySizeRequirement.required,
    "X25519-ML-KEM-768": KeySizeRequirement.required,
}


def _asset(algorithm: str, key_size_bits: int | None = None) -> CryptographicAsset:
    return CryptographicAsset(
        id="asset-1",
        name="Asset 1",
        environment="production",
        asset_type="service",
        protocol="tls",
        algorithm=algorithm,
        key_size_bits=key_size_bits,
        data_class="telemetry",
        retention_years=1,
        exposure="internal",
        criticality="medium",
        local_blast_radius="medium",
        migration_effort="medium",
    )


@pytest.mark.parametrize("algorithm", sorted(CASES))
def test_key_size_requirement(algorithm: str) -> None:
    assert key_size_requirement(classify_algorithm(algorithm)) == CASES[algorithm]


@pytest.mark.parametrize("algorithm", sorted(CASES))
def test_evidence_review_and_evidence_quality_agree(algorithm: str) -> None:
    asset = _asset(algorithm)
    required = CASES[algorithm] == KeySizeRequirement.required

    finding_codes = {finding.code for finding in review_asset_evidence(asset).findings}
    missing = evaluate_evidence_quality(asset, classify_algorithm(algorithm)).missing_evidence

    assert ("missing_key_size_bits" in finding_codes) is required
    assert ("key_size_bits" in missing) is required


@pytest.mark.parametrize("algorithm", sorted(CASES))
def test_score_confidence_treats_known_key_length_alike(algorithm: str) -> None:
    without_size = score_inventory(Inventory(assets=[_asset(algorithm)])).pop()
    with_size = score_inventory(Inventory(assets=[_asset(algorithm, 2048)])).pop()
    known = CASES[algorithm] in {
        KeySizeRequirement.fixed_by_identifier,
        KeySizeRequirement.not_applicable,
    }

    assert with_size.confidence == "medium"
    assert without_size.confidence == ("medium" if known else "low")


def test_stated_key_size_is_still_recorded_for_fixed_identifiers() -> None:
    asset = _asset("RSA-2048", 2048)

    assert asset.key_size_bits == 2048
    assert "missing_key_size_bits" not in {
        finding.code for finding in review_asset_evidence(asset).findings
    }
