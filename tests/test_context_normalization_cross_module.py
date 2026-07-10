import networkx as nx
import pytest

from qstriage.context import DataSensitivity, ExposureCategory, normalize_asset_context
from qstriage.decision import (
    DecisionContext,
    ExecutionState,
    VerificationPriority,
    VerificationRequirement,
    reconcile_decision,
)
from qstriage.evidence import build_evidence_review
from qstriage.models import CryptographicAsset, RiskLevel
from qstriage.policy import _derive_data_class_sensitivity, _derive_exposure_category
from qstriage.scoring import _deadline_pressure, _exposure_risk, _shelf_life_risk, score_asset
from qstriage.simulator import _middlebox_risk
from qstriage.standards import classify_algorithm
from tests.test_decision import _policy_result, _score


def _asset(*, data_class: str = "internal", exposure: str = "internal") -> CryptographicAsset:
    return CryptographicAsset(
        id="asset-1",
        name="Asset 1",
        environment="prod",
        asset_type="service",
        protocol="TLS",
        algorithm="RSA-2048",
        key_size_bits=2048,
        data_class=data_class,
        retention_years=5,
        exposure=exposure,
        criticality=RiskLevel.medium,
        local_blast_radius=RiskLevel.low,
        migration_effort=RiskLevel.low,
    )


@pytest.mark.parametrize("data_class", ["GDPR_scope", "cardholder_data", "patient_records"])
def test_sensitive_alias_is_shared_by_policy_and_scoring(data_class: str) -> None:
    asset = _asset(data_class=data_class)
    context = normalize_asset_context(asset)

    assert context.data_sensitivity.canonical_value is DataSensitivity.sensitive
    assert _derive_data_class_sensitivity(asset.data_class) == "sensitive"
    assert _shelf_life_risk(asset.retention_years, asset.data_class) == 8.0


@pytest.mark.parametrize(
    ("exposure", "category", "risk"),
    [
        ("public-facing", ExposureCategory.public, 9.0),
        ("internet_facing", ExposureCategory.public, 9.0),
        ("dmz", ExposureCategory.public, 9.0),
        ("perimeter", ExposureCategory.public, 9.0),
        ("edge", ExposureCategory.public, 9.0),
        ("partner-facing", ExposureCategory.partner, 7.0),
        ("third-party", ExposureCategory.partner, 7.0),
        ("vendor", ExposureCategory.partner, 7.0),
        ("supplier", ExposureCategory.partner, 7.0),
    ],
)
def test_external_alias_is_shared_by_policy_scoring_and_simulator(
    exposure: str,
    category: ExposureCategory,
    risk: float,
) -> None:
    asset = _asset(exposure=exposure)
    context = normalize_asset_context(asset)

    assert context.exposure.canonical_value is category
    assert _derive_exposure_category(asset.exposure) == category.value
    assert _exposure_risk(asset.exposure) == risk
    assert _deadline_pressure(asset) == 3.0
    assert _middlebox_risk(asset, 1.0) == "high"


@pytest.mark.parametrize("exposure", ["private-network", "corp", "corporate", "lan"])
def test_internal_alias_is_shared_by_policy_and_scoring(exposure: str) -> None:
    asset = _asset(exposure=exposure)

    assert _derive_exposure_category(asset.exposure) == "internal"
    assert _exposure_risk(asset.exposure) == 4.0


def test_unmapped_decision_bearing_context_does_not_lower_score_but_requires_verification() -> None:
    asset = _asset(data_class="Personal_Info_Scope", exposure="internal")
    graph = nx.DiGraph()
    graph.add_node(
        asset.id,
        local_blast_radius=asset.local_blast_radius,
        criticality=asset.criticality,
    )

    score = score_asset(asset, graph)
    decision = reconcile_decision(
        classification=classify_algorithm(asset.algorithm),
        score=_score(
            value=score.priority_score,
            band=score.priority_band,
            legacy_action=score.recommended_action,
        ),
        evidence_review=build_evidence_review([], asset_id=asset.id),
        policy_evaluation=_policy_result(),
        decision_confidence=0.9,
        migration_effort=asset.migration_effort,
        context=DecisionContext(normalized_context=normalize_asset_context(asset)),
    )

    assert score.breakdown.shelf_life_risk == 7.0
    assert decision.execution_state is ExecutionState.justified
    assert decision.verification_priority is VerificationPriority.medium
    assert VerificationRequirement.business_context in decision.verification_requirements
    assert "verification:business_context" in decision.reason_codes
