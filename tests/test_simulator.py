from pathlib import Path

from qstriage.models import load_inventory
from qstriage.simulator import estimate_pqc_overhead_bytes, simulate_inventory


def test_simulate_inventory_returns_one_result_per_asset_for_sample_scenario() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = simulate_inventory(inventory)

    assert len(results) == 5
    assert {result.scenario_id for result in results} == {"hybrid-kem"}


def test_ml_kem_768_profile_has_expected_overhead() -> None:
    overhead = estimate_pqc_overhead_bytes("ML-KEM-768 + X25519")

    assert overhead >= 1200


def test_public_api_gateway_has_fragmentation_and_middlebox_warnings() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = simulate_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    public_api = by_id["public-api-gateway"]

    assert public_api.estimated_handshake_bytes > public_api.mtu_bytes
    assert public_api.fragmentation_risk in {"high", "critical"}
    assert public_api.middlebox_risk in {"high", "critical"}
    assert any("MTU" in warning for warning in public_api.warnings)
    assert any("Externally exposed path" in warning for warning in public_api.warnings)


def test_ot_gateway_is_flagged_as_constrained_or_ot_like() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = simulate_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    ot_gateway = by_id["ot-gateway"]

    assert ot_gateway.compatibility_risk == "critical"
    assert any("OT-like" in warning for warning in ot_gateway.warnings)


def test_crypto_dependency_count_is_included_in_simulation() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    results = simulate_inventory(inventory)
    by_id = {result.asset_id: result for result in results}

    public_api = by_id["public-api-gateway"]
    customer_db = by_id["customer-db"]

    assert public_api.crypto_dependency_count == 2
    assert customer_db.crypto_dependency_count == 0
