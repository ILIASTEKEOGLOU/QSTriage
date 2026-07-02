from pathlib import Path

from qstriage.cbom import import_cbom_inventory
from qstriage.models import CryptographicAsset, Inventory, RiskLevel, load_inventory
from qstriage.review import review_decision_context


def test_review_marks_cbom_imported_assets_as_incomplete_without_business_context() -> None:
    inventory = import_cbom_inventory(Path("tests/fixtures/sample_cbom.json"))

    review = review_decision_context(inventory)

    assert review.status == "incomplete"
    assert review.incomplete_asset_count == 2
    assert review.inventory_issues == (
        "No QSTriage business/security dependencies declared; graph-amplified blast radius may be limited.",
    )

    rsa_review = next(
        asset_review
        for asset_review in review.asset_reviews
        if asset_review.asset_id == "crypto-rsa-2048"
    )
    issue_fields = {issue.field for issue in rsa_review.issues}

    assert rsa_review.status == "incomplete"
    assert "data_class" in issue_fields
    assert "retention_years" in issue_fields
    assert "exposure" in issue_fields
    assert "criticality" in issue_fields
    assert "local_blast_radius" in issue_fields
    assert "migration_effort" in issue_fields
    assert rsa_review.recommended_action == (
        "Add business context before treating this asset score as decision-grade."
    )


def test_review_marks_sample_inventory_as_complete_for_current_rules() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    review = review_decision_context(inventory)

    assert review.status == "complete"
    assert review.incomplete_asset_count == 0
    assert review.issue_count == 0
    assert review.inventory_issues == ()

    assert all(asset_review.status == "complete" for asset_review in review.asset_reviews)
    assert all(
        asset_review.recommended_action
        == "Decision context appears complete for current review rules."
        for asset_review in review.asset_reviews
    )


def test_review_flags_unknown_context_even_for_hand_written_inventory() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unknown-context",
                name="Unknown Context Asset",
                environment="test",
                asset_type="service",
                protocol="custom",
                algorithm="RSA-2048",
                key_size_bits=2048,
                data_class="unknown",
                retention_years=0,
                exposure="unknown",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.medium,
                migration_effort=RiskLevel.medium,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    review = review_decision_context(inventory)
    asset_review = review.asset_reviews[0]
    issue_fields = {issue.field for issue in asset_review.issues}

    assert review.status == "incomplete"
    assert asset_review.status == "incomplete"
    assert issue_fields == {"data_class", "retention_years", "exposure"}
    assert review.inventory_issues == (
        "No QSTriage business/security dependencies declared; graph-amplified blast radius may be limited.",
    )
