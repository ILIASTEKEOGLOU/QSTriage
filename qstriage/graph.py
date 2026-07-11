from __future__ import annotations

import sys
from dataclasses import dataclass

import networkx as nx

from qstriage.models import Inventory, RiskLevel
from qstriage.presentation import sanitize_terminal_text


RISK_LEVEL_SCORES: dict[RiskLevel, float] = {
    RiskLevel.low: 2.0,
    RiskLevel.medium: 5.0,
    RiskLevel.high: 8.0,
    RiskLevel.critical: 10.0,
}


@dataclass(frozen=True)
class BlastRadiusResult:
    asset_id: str
    local_score: float
    direct_graph_exposure: float
    recursive_graph_exposure: float
    total_score: float


@dataclass(frozen=True)
class _TextGraphStyle:
    branch: str
    last_branch: str
    continuation: str
    edge_arrow: str


_UNICODE_GRAPH_STYLE = _TextGraphStyle(
    branch="├──",
    last_branch="└──",
    continuation="│   ",
    edge_arrow="──>",
)
_ASCII_GRAPH_STYLE = _TextGraphStyle(
    branch="|--",
    last_branch="`--",
    continuation="|   ",
    edge_arrow="-->",
)
_UNICODE_TREE_CHARACTERS = "├└│─"


def build_dependency_graph(inventory: Inventory) -> nx.DiGraph:
    graph = nx.DiGraph()

    for asset in inventory.assets:
        graph.add_node(
            asset.id,
            name=asset.name,
            environment=asset.environment,
            asset_type=asset.asset_type,
            protocol=asset.protocol,
            algorithm=asset.algorithm,
            key_size_bits=asset.key_size_bits,
            data_class=asset.data_class,
            retention_years=asset.retention_years,
            exposure=asset.exposure,
            criticality=asset.criticality,
            local_blast_radius=asset.local_blast_radius,
            migration_effort=asset.migration_effort,
            notes=asset.notes,
        )

    for dependency in inventory.dependencies:
        graph.add_edge(
            dependency.source,
            dependency.target,
            id=dependency.id,
            direction=dependency.direction,
            dependency_type=dependency.dependency_type,
            protocol=dependency.protocol,
            weight=dependency.weight,
            criticality=dependency.criticality,
            carries_crypto_context=dependency.carries_crypto_context,
            notes=dependency.notes,
        )

    return graph


def downstream_assets(graph: nx.DiGraph, asset_id: str) -> list[str]:
    _ensure_node_exists(graph, asset_id)
    return sorted(nx.descendants(graph, asset_id))


def upstream_assets(graph: nx.DiGraph, asset_id: str) -> list[str]:
    _ensure_node_exists(graph, asset_id)
    return sorted(nx.ancestors(graph, asset_id))


def direct_downstream_assets(graph: nx.DiGraph, asset_id: str) -> list[str]:
    _ensure_node_exists(graph, asset_id)
    return sorted(graph.successors(asset_id))


def calculate_graph_amplified_blast_radius(
    graph: nx.DiGraph,
    asset_id: str,
    *,
    depth_decay: float = 0.50,
    max_depth: int = 3,
) -> BlastRadiusResult:
    _ensure_node_exists(graph, asset_id)

    local_level = graph.nodes[asset_id]["local_blast_radius"]
    local_score = _risk_score(local_level)

    direct_graph_exposure = 0.0
    recursive_graph_exposure = 0.0

    for target in graph.successors(asset_id):
        edge = graph.edges[asset_id, target]
        direct_graph_exposure += edge["weight"] * _risk_score(graph.nodes[target]["criticality"])

    visited_paths: set[tuple[str, ...]] = set()

    def walk(current: str, depth: int, path_weight: float, path: tuple[str, ...]) -> None:
        nonlocal recursive_graph_exposure

        if depth > max_depth:
            return

        for target in graph.successors(current):
            if target in path:
                continue

            edge = graph.edges[current, target]
            new_path_weight = path_weight * edge["weight"]
            new_path = (*path, target)

            if new_path in visited_paths:
                continue

            visited_paths.add(new_path)

            if depth >= 2:
                recursive_graph_exposure += (
                    (depth_decay ** depth)
                    * new_path_weight
                    * _risk_score(graph.nodes[target]["criticality"])
                )

            walk(target, depth + 1, new_path_weight, new_path)

    walk(asset_id, depth=1, path_weight=1.0, path=(asset_id,))

    total_score = min(10.0, local_score + direct_graph_exposure + recursive_graph_exposure)

    return BlastRadiusResult(
        asset_id=asset_id,
        local_score=round(local_score, 2),
        direct_graph_exposure=round(direct_graph_exposure, 2),
        recursive_graph_exposure=round(recursive_graph_exposure, 2),
        total_score=round(total_score, 2),
    )


def render_text_graph(
    graph: nx.DiGraph,
    root_asset_id: str,
    *,
    max_depth: int = 3,
    output_encoding: str | None = None,
) -> str:
    _ensure_node_exists(graph, root_asset_id)
    style = _text_graph_style(output_encoding)

    lines: list[str] = [_node_label(root_asset_id, graph.nodes[root_asset_id])]

    def render_child(
        parent_id: str,
        child_id: str,
        prefix: str,
        is_last: bool,
        depth: int,
        visited: set[str],
    ) -> None:
        edge = graph.edges[parent_id, child_id]
        connector = style.last_branch if is_last else style.branch
        continuation_prefix = "    " if is_last else style.continuation

        edge_label = (
            f"{connector}({edge['dependency_type'].value}, "
            f"{sanitize_terminal_text(edge['protocol'])}, "
            f"w={edge['weight']:.2f}){style.edge_arrow} "
        )

        if child_id in visited:
            lines.append(
                f"{prefix}{edge_label}[{sanitize_terminal_text(child_id)}] "
                "(cycle/reference)"
            )
            return

        lines.append(f"{prefix}{edge_label}{_node_label(child_id, graph.nodes[child_id])}")

        if depth >= max_depth:
            return

        next_visited = set(visited)
        next_visited.add(child_id)

        children = sorted(graph.successors(child_id))

        for index, grandchild_id in enumerate(children):
            render_child(
                child_id,
                grandchild_id,
                prefix + continuation_prefix,
                index == len(children) - 1,
                depth + 1,
                next_visited,
            )

    children = sorted(graph.successors(root_asset_id))

    for index, child_id in enumerate(children):
        render_child(
            root_asset_id,
            child_id,
            prefix="",
            is_last=index == len(children) - 1,
            depth=1,
            visited={root_asset_id},
        )

    return "\n".join(lines)


def _text_graph_style(output_encoding: str | None = None) -> _TextGraphStyle:
    encoding = output_encoding or sys.stdout.encoding
    if _encoding_supports_unicode_tree(encoding):
        return _UNICODE_GRAPH_STYLE
    return _ASCII_GRAPH_STYLE


def _encoding_supports_unicode_tree(encoding: str | None) -> bool:
    if not encoding:
        return False

    try:
        _UNICODE_TREE_CHARACTERS.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False

    return True


def critical_paths(graph: nx.DiGraph, *, min_target_criticality: RiskLevel = RiskLevel.high) -> list[list[str]]:
    min_score = _risk_score(min_target_criticality)
    paths: list[list[str]] = []

    for source in sorted(graph.nodes):
        for target in sorted(nx.descendants(graph, source)):
            target_score = _risk_score(graph.nodes[target]["criticality"])
            if target_score < min_score:
                continue

            for path in nx.all_simple_paths(graph, source=source, target=target, cutoff=4):
                if len(path) >= 2:
                    paths.append(path)

    paths.sort(key=lambda item: (len(item), item))
    return paths


def _risk_score(level: RiskLevel) -> float:
    return RISK_LEVEL_SCORES[level]


def _ensure_node_exists(graph: nx.DiGraph, asset_id: str) -> None:
    if asset_id not in graph:
        raise KeyError(f"Unknown asset id: {asset_id}")


def _node_label(asset_id: str, node: dict) -> str:
    return (
        f"[{sanitize_terminal_text(asset_id)}] "
        f"{sanitize_terminal_text(node['algorithm'])} "
        f"criticality={node['criticality'].value} "
        f"blast={node['local_blast_radius'].value}"
    )
