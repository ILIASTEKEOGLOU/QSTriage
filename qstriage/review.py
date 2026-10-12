from __future__ import annotations

from dataclasses import dataclass

from qstriage.context import (
    is_cbom_imported_asset,
    normalize_asset_context,
)
from qstriage.models import AssetEvidenceAssertions, CryptographicAsset, Inventory


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
    evidence_by_asset = (
        inventory.evidence.assets if inventory.evidence is not None else {}
    )
    asset_reviews = tuple(
        _review_asset_context(asset, evidence_by_asset.get(asset.id))
        for asset in inventory.assets
    )
    inventory_issues = _review_inventory_context(inventory)

    status = "complete"
    if inventory_issues or any(review.status == "incomplete" for review in asset_reviews):
        status = "incomplete"

    return InventoryContextReview(
        status=status,
        asset_reviews=asset_reviews,
        inventory_issues=inventory_issues,
    )


def _review_asset_context(
    asset: CryptographicAsset,
    asset_evidence: AssetEvidenceAssertions | None = None,
) -> AssetContextReview:
    context = normalize_asset_context(asset, asset_evidence)
    issues = [
        ContextIssue(
            field=resolved.field,
            message=resolved.message or f"{resolved.field_path} is unresolved.",
        )
        for resolved in context.unresolved_fields
    ]

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
    return is_cbom_imported_asset(asset)
