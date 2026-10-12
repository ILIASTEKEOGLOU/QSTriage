"""A policy rule whose identifier promises a review must enforce one.

Policy pack 0.4 closes a gap in which two rules recommended a review of the
implementation without requiring human review in the decision.
"""

import pytest

from qstriage.models import CryptographicAsset, Inventory
from qstriage.pdr import generate_pdr_document
from qstriage.policy import PolicyRuleEffect, get_policy_pack


def test_rules_named_as_requirements_or_reviews_enforce_review() -> None:
    pack = get_policy_pack()
    enforcing = {
        PolicyRuleEffect.requires_human_review,
        PolicyRuleEffect.blocks_decision_grade,
    }

    promising = [
        rule
        for rule in pack.rules
        if "requires" in rule.rule_id or "review" in rule.rule_id
    ]

    assert promising
    for rule in promising:
        assert enforcing & set(rule.effects), rule.rule_id


@pytest.mark.parametrize(
    "algorithm",
    ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s", "X25519MLKEM768"],
)
def test_pqc_assets_with_complete_context_still_require_human_review(
    algorithm: str,
) -> None:
    asset = CryptographicAsset(
        id="pqc-asset",
        name="PQC Asset",
        environment="production",
        asset_type="tls_endpoint",
        protocol="tls",
        algorithm=algorithm,
        data_class="telemetry",
        retention_years=1,
        exposure="internal",
        criticality="medium",
        local_blast_radius="medium",
        migration_effort="medium",
    )

    record = generate_pdr_document(Inventory(assets=[asset])).records[0]

    assert record.decision.action_type.value == "retain_monitor"
    assert record.decision.human_review_required is True
