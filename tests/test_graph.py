from pathlib import Path

import pytest

from qstriage.graph import (
    _encoding_supports_unicode_tree,
    build_dependency_graph,
    calculate_graph_amplified_blast_radius,
    critical_paths,
    direct_downstream_assets,
    downstream_assets,
    render_text_graph,
    upstream_assets,
)
from qstriage.models import load_inventory


def test_build_dependency_graph_from_sample_inventory() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    assert graph.number_of_nodes() == 5
    assert graph.number_of_edges() == 5

    assert graph.nodes["public-api-gateway"]["algorithm"] == "ECDHE_RSA"
    assert graph.edges["public-api-gateway", "auth-service"]["weight"] == 0.90


def test_downstream_and_upstream_assets() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    assert direct_downstream_assets(graph, "public-api-gateway") == [
        "auth-service",
        "payments-api",
    ]

    assert downstream_assets(graph, "public-api-gateway") == [
        "auth-service",
        "customer-db",
        "payments-api",
    ]

    assert upstream_assets(graph, "customer-db") == [
        "auth-service",
        "ot-gateway",
        "payments-api",
        "public-api-gateway",
    ]


def test_graph_amplified_blast_radius_is_capped_at_ten() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    result = calculate_graph_amplified_blast_radius(graph, "public-api-gateway")

    assert result.asset_id == "public-api-gateway"
    assert result.local_score == 8.0
    assert result.direct_graph_exposure > 0
    assert result.total_score == 10.0


def test_render_text_graph_contains_dependency_context() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    rendered = render_text_graph(graph, "public-api-gateway", output_encoding="utf-8")

    assert "[public-api-gateway]" in rendered
    assert "auth" in rendered
    assert "HTTPS/TLS1.3" in rendered
    assert "w=0.90" in rendered
    assert "│   └──(database, mTLS, w=0.80)──> [customer-db]" in rendered


def test_render_text_graph_keeps_unicode_tree_for_utf8_output() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    rendered = render_text_graph(graph, "public-api-gateway", output_encoding="utf-8")

    assert "├──(auth, HTTPS/TLS1.3, w=0.90)──> [auth-service]" in rendered
    assert "└──(api_call, HTTPS/TLS1.3, w=0.75)──> [payments-api]" in rendered


def test_render_text_graph_uses_ascii_tree_for_charmap_output() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    rendered = render_text_graph(graph, "public-api-gateway", output_encoding="cp1252")

    assert "|--(auth, HTTPS/TLS1.3, w=0.90)--> [auth-service]" in rendered
    assert "`--(api_call, HTTPS/TLS1.3, w=0.75)--> [payments-api]" in rendered
    assert "├" not in rendered
    assert "└" not in rendered
    assert "│" not in rendered
    assert "─" not in rendered


def test_ascii_tree_fallback_encodes_on_non_utf8_output() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    rendered = render_text_graph(graph, "public-api-gateway", output_encoding="ascii")

    rendered.encode("ascii")


def test_unicode_tree_encoding_detection() -> None:
    assert _encoding_supports_unicode_tree("utf-8")
    assert not _encoding_supports_unicode_tree("cp1252")
    assert not _encoding_supports_unicode_tree("ascii")


def test_critical_paths_include_api_to_customer_db() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    paths = critical_paths(graph)

    assert ["public-api-gateway", "auth-service"] in paths
    assert ["public-api-gateway", "auth-service", "customer-db"] in paths


def test_unknown_asset_raises_key_error() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    graph = build_dependency_graph(inventory)

    with pytest.raises(KeyError):
        downstream_assets(graph, "missing-asset")
