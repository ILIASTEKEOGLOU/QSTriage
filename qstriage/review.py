from __future__ import annotations

from dataclasses import dataclass

from qstriage.models import CryptographicAsset, Inventory, RiskLevel


@dataclass(frozen=True)
class ContextIssue:
    field: str
    message: str


@dataclass(frozen=True)
class AssetContextReview:
    asset_id: str
    asset_name: str
    status: str
    issues: tuple[ContextIssue, ...]
    recommended_action: str


@dataclass(frozen=True)
class InventoryContextReview:
    status: str
    asset_reviews: tuple[AssetContextReview, ...]
    inventory_issues: tuple[str, ...]

    @property
    def incomplete_asset_count(self) -> int:
        return sum(1 for review in self.asset_reviews if review.status == "incomplete")

    @property
    def issue_count(self) -> int:
        return sum(len(review.issues) for review in self.asset_reviews) + len(
            self.inventory_issues
        )


def review_decision_context(inventory: Inventory) -> InventoryContextReview:
    asset_reviews = tuple(_review_asset_context(asset) for asset in inventory.assets)
    inventory_issues = _review_inventory_context(inventory)

    status = "complete"
    if inventory_issues or any(review.status == "incomplete" for review in asset_reviews):
        status = "incomplete"

    return InventoryContextReview(
        status=status,
        asset_reviews=asset_reviews,
        inventory_issues=inventory_issues,
    )


def _review_asset_context(asset: CryptographicAsset) -> AssetContextReview:
    issues: list[ContextIssue] = []
    imported_from_cbom = _is_cbom_imported_asset(asset)

    if asset.data_class.strip().lower() == "unknown":
        issues.append(
            ContextIssue(
                field="data_class",
                message="data_class is unknown; business data sensitivity is required for decision-grade scoring.",
            )
        )

    if asset.retention_years == 0:
        issues.append(
            ContextIssue(
                field="retention_years",
                message="retention_years is 0; shelf-life risk needs business context.",
            )
        )

    if asset.exposure.strip().lower() == "unknown":
        issues.append(
            ContextIssue(
                field="exposure",
                message="exposure is unknown; public, partner, internal, or restricted exposure should be reviewed.",
            )
        )

    if imported_from_cbom and asset.criticality == RiskLevel.medium:
        issues.append(
            ContextIssue(
                field="criticality",
                message="criticality is the CBOM import default medium; confirm business criticality.",
            )
        )

    if imported_from_cbom and asset.local_blast_radius == RiskLevel.medium:
        issues.append(
            ContextIssue(
                field="local_blast_radius",
                message="local_blast_radius is the CBOM import default medium; confirm local impact.",
            )
        )

    if imported_from_cbom and asset.migration_effort == RiskLevel.medium:
        issues.append(
            ContextIssue(
                field="migration_effort",
                message="migration_effort is the CBOM import default medium; confirm migration complexity.",
            )
        )

    status = "complete" if not issues else "incomplete"
    recommended_action = (
        "Decision context appears complete for current review rules."
        if status == "complete"
        else "Add business context before treating this asset score as decision-grade."
    )

    return AssetContextReview(
        asset_id=asset.id,
        asset_name=asset.name,
        status=status,
        issues=tuple(issues),
        recommended_action=recommended_action,
    )


def _review_inventory_context(inventory: Inventory) -> tuple[str, ...]:
    issues: list[str] = []

    if not inventory.dependencies:
        issues.append(
            "No QSTriage business/security dependencies declared; graph-amplified blast radius may be limited."
        )

    return tuple(issues)


def _is_cbom_imported_asset(asset: CryptographicAsset) -> bool:
    return (
        asset.asset_type == "cbom_cryptographic_asset"
        or "Imported from CycloneDX CBOM" in asset.notes
    )
