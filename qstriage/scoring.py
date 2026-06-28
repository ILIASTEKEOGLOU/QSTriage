from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from qstriage.graph import build_dependency_graph, calculate_graph_amplified_blast_radius
from qstriage.models import CryptographicAsset, Inventory, RiskLevel


@dataclass(frozen=True)
class ScoreBreakdown:
    cryptographic_risk: float
    shelf_life_risk: float
    exposure_risk: float
    criticality_score: float
    graph_blast_radius: float
    deadline_pressure: float
    effort_penalty: float
    total: float


@dataclass(frozen=True)
class ScoreResult:
    asset_id: str
    asset_name: str
    priority_score: float
    priority_band: str
    recommended_action: str
    confidence: str
    breakdown: ScoreBreakdown
    explanation: list[str]


def score_inventory(inventory: Inventory) -> list[ScoreResult]:
    graph = build_dependency_graph(inventory)
    results = [score_asset(asset, graph) for asset in inventory.assets]
    return sorted(results, key=lambda result: result.priority_score, reverse=True)


def score_asset(asset: CryptographicAsset, graph: nx.DiGraph) -> ScoreResult:
    cryptographic_risk = _cryptographic_risk(asset.algorithm, asset.key_size_bits)
    shelf_life_risk = _shelf_life_risk(asset.retention_years, asset.data_class)
    exposure_risk = _exposure_risk(asset.exposure)
    criticality_score = _risk_level_score(asset.criticality)
    blast_radius = calculate_graph_amplified_blast_radius(graph, asset.id).total_score
    deadline_pressure = _deadline_pressure(asset)
    effort_penalty = _effort_penalty(asset.migration_effort)

    raw_total = (
        cryptographic_risk
        + shelf_life_risk
        + exposure_risk
        + criticality_score
        + blast_radius
        + deadline_pressure
        - effort_penalty
    )

    priority_score = round(max(0.0, min(100.0, raw_total * 2.0)), 2)
    priority_band = _priority_band(priority_score)
    recommended_action = _recommended_action(priority_score, asset.migration_effort)
    confidence = _confidence(asset)

    breakdown = ScoreBreakdown(
        cryptographic_risk=round(cryptographic_risk, 2),
        shelf_life_risk=round(shelf_life_risk, 2),
        exposure_risk=round(exposure_risk, 2),
        criticality_score=round(criticality_score, 2),
        graph_blast_radius=round(blast_radius, 2),
        deadline_pressure=round(deadline_pressure, 2),
        effort_penalty=round(effort_penalty, 2),
        total=priority_score,
    )

    explanation = _explain(asset, breakdown, priority_band, recommended_action)

    return ScoreResult(
        asset_id=asset.id,
        asset_name=asset.name,
        priority_score=priority_score,
        priority_band=priority_band,
        recommended_action=recommended_action,
        confidence=confidence,
        breakdown=breakdown,
        explanation=explanation,
    )


def _cryptographic_risk(algorithm: str, key_size_bits: int | None) -> float:
    normalized = algorithm.upper().replace("-", "_")

    if "RSA" in normalized:
        if key_size_bits is None:
            return 8.0
        if key_size_bits <= 2048:
            return 9.0
        if key_size_bits <= 3072:
            return 8.0
        return 7.0

    if "ECDSA" in normalized or "ECDHE" in normalized or "ECDH" in normalized:
        return 8.5

    if "DH" in normalized:
        return 8.0

    if "ML_KEM" in normalized or "ML_DSA" in normalized or "SLH_DSA" in normalized:
        return 1.5

    if "AES" in normalized or "CHACHA" in normalized:
        return 2.0

    return 5.0


def _shelf_life_risk(retention_years: int, data_class: str) -> float:
    data_class_normalized = data_class.lower()

    if retention_years >= 10:
        base = 9.0
    elif retention_years >= 5:
        base = 7.0
    elif retention_years >= 3:
        base = 5.0
    elif retention_years >= 1:
        base = 3.0
    else:
        base = 1.0

    if any(token in data_class_normalized for token in ["pii", "identity", "medical", "payment"]):
        base += 1.0

    return min(10.0, base)


def _exposure_risk(exposure: str) -> float:
    normalized = exposure.lower()

    if "public" in normalized or "internet" in normalized:
        return 9.0
    if "partner" in normalized:
        return 7.0
    if "restricted" in normalized:
        return 5.0
    if "internal" in normalized:
        return 4.0
    if "isolated" in normalized:
        return 2.0

    return 5.0


def _deadline_pressure(asset: CryptographicAsset) -> float:
    if asset.retention_years >= 10 and _cryptographic_risk(asset.algorithm, asset.key_size_bits) >= 8.0:
        return 5.0

    if asset.retention_years >= 5 and asset.exposure in {"public_internet", "partner_network"}:
        return 3.0

    return 1.0


def _effort_penalty(migration_effort: RiskLevel) -> float:
    values = {
        RiskLevel.low: 1.0,
        RiskLevel.medium: 2.5,
        RiskLevel.high: 4.0,
        RiskLevel.critical: 6.0,
    }
    return values[migration_effort]


def _risk_level_score(level: RiskLevel) -> float:
    values = {
        RiskLevel.low: 2.0,
        RiskLevel.medium: 5.0,
        RiskLevel.high: 8.0,
        RiskLevel.critical: 10.0,
    }
    return values[level]


def _priority_band(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _recommended_action(score: float, effort: RiskLevel) -> str:
    if score >= 85 and effort in {RiskLevel.high, RiskLevel.critical}:
        return "simulate before migration; prepare staged remediation plan"

    if score >= 85:
        return "prioritize for early PQC migration planning"

    if score >= 70:
        return "review soon and include in near-term migration backlog"

    if score >= 45:
        return "monitor and reassess after higher-risk assets"

    return "defer; keep inventory evidence current"


def _confidence(asset: CryptographicAsset) -> str:
    if asset.notes and asset.key_size_bits is not None:
        return "medium-high"

    if asset.key_size_bits is not None:
        return "medium"

    return "low"


def _explain(
    asset: CryptographicAsset,
    breakdown: ScoreBreakdown,
    priority_band: str,
    recommended_action: str,
) -> list[str]:
    lines = [
        f"{asset.name} is rated {priority_band} with score {breakdown.total}.",
        f"Cryptographic risk is {breakdown.cryptographic_risk} because the asset uses {asset.algorithm}.",
        f"Shelf-life risk is {breakdown.shelf_life_risk} because data retention is {asset.retention_years} years for {asset.data_class}.",
        f"Graph-amplified blast radius is {breakdown.graph_blast_radius}, reflecting local and downstream dependency impact.",
        f"Recommended action: {recommended_action}.",
    ]

    if breakdown.effort_penalty >= 4.0:
        lines.append("Migration effort is high, so direct production change should be avoided before simulation.")

    return lines
