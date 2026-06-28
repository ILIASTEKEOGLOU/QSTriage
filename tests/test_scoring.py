from pathlib import Path

from qstriage.models import load_inventory
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
