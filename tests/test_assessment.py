from pathlib import Path

import pytest

from qstriage.assessment import assess_asset
from qstriage.cbom import import_cbom_inventory
from qstriage.decision import (
    ActionType,
    ExecutionState,
    VerificationPriority,
    VerificationRequirement,
)
from qstriage.models import load_inventory
from qstriage.policy import get_policy_pack
from qstriage.scoring import score_inventory


SAMPLE_INVENTORY = Path("examples/sample_inventory.yaml")
SAMPLE_CBOM = Path("tests/fixtures/sample_cbom.json")


def test_asset_assessment_reconciles_legacy_action_divergence() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)
    asset = next(asset for asset in inventory.assets if asset.id == "payments-api")
    score = next(
        result for result in score_inventory(inventory) if result.asset_id == asset.id
    )

    assessment = assess_asset(
        asset,
        score=score,
        policy_pack=get_policy_pack(),
    )

    assert score.recommended_action == (
        "review soon and include in near-term migration backlog"
    )
    assert assessment.decision.action_type is ActionType.simulate_before_migration
    assert assessment.decision.execution_state is ExecutionState.justified
    assert assessment.decision.risk_attention_score == score.priority_score
    assert (
        assessment.decision.decision_confidence
        == assessment.decision_confidence.score
    )
    assert assessment.normalized_context.business_context_present is True


def test_cbom_asset_assessment_preserves_verification_first_inputs() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    asset = next(asset for asset in inventory.assets if asset.id == "crypto-rsa-2048")
    score = next(
        result for result in score_inventory(inventory) if result.asset_id == asset.id
    )

    assessment = assess_asset(
        asset,
        score=score,
        policy_pack=get_policy_pack(),
        source_type="cyclonedx_cbom",
    )

    assert assessment.decision.execution_state is ExecutionState.gated
    assert assessment.decision.verification_priority is VerificationPriority.high
    assert assessment.decision.human_review_required is True
    assert VerificationRequirement.business_context in (
        assessment.decision.verification_requirements
    )
    assert VerificationRequirement.policy_resolution in (
        assessment.decision.verification_requirements
    )


def test_asset_assessment_rejects_cross_asset_score() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)
    asset = next(asset for asset in inventory.assets if asset.id == "payments-api")
    wrong_score = next(
        result
        for result in score_inventory(inventory)
        if result.asset_id == "ot-gateway"
    )

    with pytest.raises(ValueError, match="does not match asset"):
        assess_asset(
            asset,
            score=wrong_score,
            policy_pack=get_policy_pack(),
        )
