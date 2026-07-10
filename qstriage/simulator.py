from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from qstriage.graph import build_dependency_graph
from qstriage.context import ExposureCategory, normalize_asset_context
from qstriage.models import CryptographicAsset, Inventory, MigrationScenario, RiskLevel


DEFAULT_SCENARIO = MigrationScenario(
    id="default-hybrid-kem",
    name="Default hybrid KEM migration path",
    pqc_profile="ML-KEM-768 + X25519",
    mtu_bytes=1500,
    notes="Default local-first simulation scenario.",
)


@dataclass(frozen=True)
class ImpactSimulationResult:
    asset_id: str
    asset_name: str
    scenario_id: str
    scenario_name: str
    pqc_profile: str
    protocol: str
    estimated_handshake_bytes: int
    mtu_bytes: int
    mtu_ratio: float
    fragmentation_risk: str
    middlebox_risk: str
    compatibility_risk: str
    crypto_dependency_count: int
    warnings: list[str]


def simulate_inventory(inventory: Inventory) -> list[ImpactSimulationResult]:
    graph = build_dependency_graph(inventory)
    scenarios = inventory.scenarios or [DEFAULT_SCENARIO]

    results: list[ImpactSimulationResult] = []

    for scenario in scenarios:
        for asset in inventory.assets:
            results.append(simulate_asset(asset, scenario, graph))

    return results


def simulate_asset(
    asset: CryptographicAsset,
    scenario: MigrationScenario,
    graph: nx.DiGraph,
) -> ImpactSimulationResult:
    crypto_dependency_count = _crypto_dependency_count(graph, asset.id)

    baseline_bytes = _baseline_handshake_bytes(asset)
    pqc_overhead_bytes = estimate_pqc_overhead_bytes(scenario.pqc_profile)
    dependency_overhead_bytes = crypto_dependency_count * 80

    estimated_handshake_bytes = (
        baseline_bytes
        + pqc_overhead_bytes
        + dependency_overhead_bytes
    )

    mtu_ratio = estimated_handshake_bytes / scenario.mtu_bytes

    fragmentation_risk = _fragmentation_risk(mtu_ratio)
    middlebox_risk = _middlebox_risk(asset, mtu_ratio)
    compatibility_risk = _compatibility_risk(asset, fragmentation_risk)

    warnings = _warnings(
        asset=asset,
        scenario=scenario,
        estimated_handshake_bytes=estimated_handshake_bytes,
        mtu_ratio=mtu_ratio,
        fragmentation_risk=fragmentation_risk,
        middlebox_risk=middlebox_risk,
        compatibility_risk=compatibility_risk,
        crypto_dependency_count=crypto_dependency_count,
    )

    return ImpactSimulationResult(
        asset_id=asset.id,
        asset_name=asset.name,
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        pqc_profile=scenario.pqc_profile,
        protocol=asset.protocol,
        estimated_handshake_bytes=estimated_handshake_bytes,
        mtu_bytes=scenario.mtu_bytes,
        mtu_ratio=round(mtu_ratio, 2),
        fragmentation_risk=fragmentation_risk,
        middlebox_risk=middlebox_risk,
        compatibility_risk=compatibility_risk,
        crypto_dependency_count=crypto_dependency_count,
        warnings=warnings,
    )


def estimate_pqc_overhead_bytes(pqc_profile: str) -> int:
    normalized = pqc_profile.upper().replace("-", "_").replace(" ", "")

    overhead = 0

    if "ML_KEM_512" in normalized:
        overhead += 900
    elif "ML_KEM_768" in normalized:
        overhead += 1184
    elif "ML_KEM_1024" in normalized:
        overhead += 1624
    elif "KYBER512" in normalized:
        overhead += 900
    elif "KYBER768" in normalized:
        overhead += 1184
    elif "KYBER1024" in normalized:
        overhead += 1624
    else:
        overhead += 1000

    if "X25519" in normalized or "ECDHE" in normalized or "P256" in normalized:
        overhead += 64

    overhead += 96

    return overhead


def _baseline_handshake_bytes(asset: CryptographicAsset) -> int:
    protocol = asset.protocol.upper()

    if "MTLS" in protocol or "M/TLS" in protocol:
        return 1300

    if "TLS" in protocol or "HTTPS" in protocol:
        return 900

    if "SSH" in protocol:
        return 800

    if "IPSEC" in protocol:
        return 1000

    return 600


def _crypto_dependency_count(graph: nx.DiGraph, asset_id: str) -> int:
    return sum(
        1
        for _, _, data in graph.out_edges(asset_id, data=True)
        if data.get("carries_crypto_context") is True
    )


def _fragmentation_risk(mtu_ratio: float) -> str:
    if mtu_ratio >= 1.50:
        return "critical"

    if mtu_ratio >= 1.00:
        return "high"

    if mtu_ratio >= 0.85:
        return "medium"

    return "low"


def _middlebox_risk(asset: CryptographicAsset, mtu_ratio: float) -> str:
    exposure_category = normalize_asset_context(asset).exposure.canonical_value
    protocol = asset.protocol.upper()
    asset_type = asset.asset_type.lower()

    external_path = exposure_category in {ExposureCategory.public, ExposureCategory.partner}
    tls_like = "TLS" in protocol or "HTTPS" in protocol
    constrained_path = "ot" in asset_type or "industrial" in asset_type or "gateway" in asset_type

    if mtu_ratio >= 1.50 and (external_path or constrained_path):
        return "critical"

    if mtu_ratio >= 1.00 and (external_path or constrained_path or tls_like):
        return "high"

    if mtu_ratio >= 0.85:
        return "medium"

    return "low"


def _compatibility_risk(asset: CryptographicAsset, fragmentation_risk: str) -> str:
    asset_type = asset.asset_type.lower()

    if asset.migration_effort == RiskLevel.critical:
        return "critical"

    if "industrial" in asset_type or "legacy" in asset_type or "mainframe" in asset_type:
        return "high"

    if asset.migration_effort == RiskLevel.high or fragmentation_risk in {"high", "critical"}:
        return "high"

    if asset.migration_effort == RiskLevel.medium:
        return "medium"

    return "low"


def _warnings(
    *,
    asset: CryptographicAsset,
    scenario: MigrationScenario,
    estimated_handshake_bytes: int,
    mtu_ratio: float,
    fragmentation_risk: str,
    middlebox_risk: str,
    compatibility_risk: str,
    crypto_dependency_count: int,
) -> list[str]:
    warnings: list[str] = []

    if estimated_handshake_bytes > scenario.mtu_bytes:
        warnings.append(
            f"Estimated handshake size {estimated_handshake_bytes} bytes exceeds MTU {scenario.mtu_bytes} bytes."
        )

    if fragmentation_risk in {"high", "critical"}:
        warnings.append(
            f"Fragmentation risk is {fragmentation_risk}; test path MTU and packet handling before rollout."
        )

    if middlebox_risk in {"high", "critical"}:
        warnings.append(
            f"Middlebox risk is {middlebox_risk}; TLS inspection, proxies, gateways, or firewalls may reject larger handshakes."
        )

    if compatibility_risk in {"high", "critical"}:
        warnings.append(
            f"Compatibility risk is {compatibility_risk}; use staged simulation before touching production."
        )

    if crypto_dependency_count > 0:
        warnings.append(
            f"Asset has {crypto_dependency_count} crypto-bearing downstream dependencies that may amplify migration impact."
        )

    if "industrial" in asset.asset_type.lower() or asset.migration_effort == RiskLevel.critical:
        warnings.append(
            "Constrained or OT-like environment detected; avoid assuming standard TLS migration behavior."
        )

    if mtu_ratio >= 1.0 and ("public" in asset.exposure.lower() or "partner" in asset.exposure.lower()):
        warnings.append(
            "Externally exposed path detected; validate client, partner, CDN, WAF, and gateway compatibility."
        )

    return warnings
