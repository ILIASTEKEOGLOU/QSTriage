from pathlib import Path

import pytest
from qstriage.models import CryptographicAsset, Inventory, RiskLevel, load_inventory
from qstriage.scoring import score_inventory


def test_score_inventory_returns_ranked_results() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = score_inventory(inventory)

    assert len(results) == 5
    assert results[0].priority_score >= results[-1].priority_score


def test_public_api_gateway_is_high_priority() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = score_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    public_api = by_id["public-api-gateway"]

    assert public_api.priority_band in {"high", "critical"}
    assert public_api.breakdown.graph_blast_radius == 10.0
    assert "simulation" in public_api.recommended_action or "migration" in public_api.recommended_action


def test_ot_gateway_penalized_by_critical_effort_but_still_explained() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = score_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    ot_gateway = by_id["ot-gateway"]

    assert ot_gateway.breakdown.effort_penalty == 6.0
    assert ot_gateway.explanation
    assert any("production change should be avoided" in line for line in ot_gateway.explanation)


def test_explanation_contains_human_readable_reasons() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = score_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    customer_db = by_id["customer-db"]

    joined = "\n".join(customer_db.explanation)

    assert "Customer Database" in joined
    assert "Cryptographic risk" in joined
    assert "Shelf-life risk" in joined
    assert "Recommended action" in joined


def test_scoring_explanation_uses_algorithm_registry_classification() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = score_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    customer_db = by_id["customer-db"]
    joined = "\n".join(customer_db.explanation)

    assert "Algorithm registry classifies RSA as quantum_vulnerable" in joined
    assert "registry action is migrate_to_hybrid_or_pqc_path" in joined


def test_scoring_treats_standardized_pqc_as_low_cryptographic_risk() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="pqc-kem",
                name="PQC KEM",
                environment="test",
                asset_type="service",
                protocol="TLS1.3",
                algorithm="ML-KEM-768",
                key_size_bits=768,
                data_class="internal",
                retention_years=1,
                exposure="internal",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.low,
                migration_effort=RiskLevel.low,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    result = score_inventory(inventory)[0]

    assert result.breakdown.cryptographic_risk == 1.5
    assert any("ML-KEM" in line and "quantum_resistant" in line for line in result.explanation)


def test_scoring_keeps_unknown_algorithm_as_conservative_medium_risk() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unknown-crypto",
                name="Unknown Crypto",
                environment="test",
                asset_type="service",
                protocol="custom",
                algorithm="MysteryCrypto-1",
                key_size_bits=None,
                data_class="internal",
                retention_years=1,
                exposure="internal",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.low,
                migration_effort=RiskLevel.low,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    result = score_inventory(inventory)[0]
    joined = "\n".join(result.explanation)

    assert result.breakdown.cryptographic_risk == 5.0
    assert "Algorithm registry classifies unknown as unknown" in joined
    assert "registry action is manual_review_required" in joined


def test_scoring_does_not_award_low_risk_to_unverified_pqc_parameters() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unverified-pqc-kem",
                name="Unverified PQC KEM",
                environment="test",
                asset_type="service",
                protocol="TLS1.3",
                algorithm="ML-KEM-9999",
                key_size_bits=None,
                data_class="internal",
                retention_years=1,
                exposure="internal",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.low,
                migration_effort=RiskLevel.low,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    result = score_inventory(inventory)[0]
    joined = "\n".join(result.explanation)

    assert result.breakdown.cryptographic_risk == 5.0
    assert "Algorithm registry classifies ML-KEM as unknown" in joined
    assert (
        "registry action is verify_exact_parameter_set_before_classification"
        in joined
    )


def test_score_inventory_enforces_shared_graph_traversal_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import qstriage.scoring as scoring_module
    from qstriage.limits import ResourceLimitError, TraversalBudget

    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    monkeypatch.setattr(
        scoring_module,
        "TraversalBudget",
        lambda: TraversalBudget(limit=1),
    )

    with pytest.raises(ResourceLimitError, match="graph traversal budget"):
        scoring_module.score_inventory(inventory)
