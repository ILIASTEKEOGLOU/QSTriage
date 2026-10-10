"""Comparison of two PDR documents.

``diff_pdr_files`` verifies both documents first and refuses to compare a
document that fails verification. Records are matched by ``record_id``. For
each matched record the fields of ``decision`` and ``observed_state`` are
compared. Provenance items are compared to show what differs between the two
runs; a decision change is never attributed to one item by inference. When
the two documents have different ``pdr_version`` values, fields that exist in
only one version are reported as format differences, not as changes.

The comparison reads both files once and never writes. See
``design/r0-architecture.md``, section 5.4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from qstriage.pdr_verify import (
    PDRVerificationInputError,
    VerificationResult,
    load_pdr_file,
    verify_pdr_document,
)
from qstriage.presentation import markdown_inline


COMPARED_SECTIONS = ("decision", "observed_state")
ABSENT = "(absent)"

MULTIPLE_CAUSES_TEXT = (
    "More than one of these changed. This report cannot attribute a decision "
    "change to a single one of them."
)
SINGLE_CAUSE_TEXT = "Only one of these changed: {item}."
NO_CAUSE_TEXT = "None of these changed."
FORMAT_DIFFERENCES_TEXT = (
    "PDR {after} records fields that PDR {before} does not have. They are "
    "listed here so they are not mistaken for decision changes:"
)
FORMAT_DIFFERENCES_REMOVED_TEXT = (
    "PDR {before} records fields that PDR {after} does not have. They are "
    "listed here so they are not mistaken for decision changes:"
)


class PDRDiffError(ValueError):
    """Raised when two PDR documents cannot be compared."""


@dataclass(frozen=True)
class FieldChange:
    record_id: str
    field: str
    before: Any
    after: Any


@dataclass(frozen=True)
class ProvenanceItem:
    key: str
    label: str
    changed: bool
    before: Any
    after: Any
    # Human-readable labels for the markdown summary. None means the item has
    # no label to show (the input file is identified only by its hash).
    before_label: str | None = None
    after_label: str | None = None


@dataclass(frozen=True)
class RecordChange:
    record_id: str
    asset_name: str
    decision_changed: bool
    changes: tuple[FieldChange, ...]
    before_record: dict[str, Any]
    after_record: dict[str, Any]


@dataclass(frozen=True)
class PDRDiff:
    before_path: str
    after_path: str
    before_version: str
    after_version: str
    before_verification: VerificationResult
    after_verification: VerificationResult
    before_document_hash: str
    after_document_hash: str
    provenance: tuple[ProvenanceItem, ...]
    matched_count: int
    added: tuple[dict[str, Any], ...]
    removed: tuple[dict[str, Any], ...]
    changed: tuple[RecordChange, ...]
    format_differences: tuple[str, ...] = field(default_factory=tuple)
    format_differences_added: bool = True

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    @property
    def changed_provenance(self) -> tuple[ProvenanceItem, ...]:
        return tuple(item for item in self.provenance if item.changed)


def diff_pdr_files(before_path: str | Path, after_path: str | Path) -> PDRDiff:
    before = load_pdr_file(before_path)
    after = load_pdr_file(after_path)
    before_result = _verify_or_raise(before, "Before")
    after_result = _verify_or_raise(after, "After")
    return diff_pdr_documents(
        before,
        after,
        before_path=str(before_path),
        after_path=str(after_path),
        before_verification=before_result,
        after_verification=after_result,
    )


def diff_pdr_documents(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    before_path: str,
    after_path: str,
    before_verification: VerificationResult,
    after_verification: VerificationResult,
) -> PDRDiff:
    before_records = _records_by_id(before, "Before")
    after_records = _records_by_id(after, "After")
    version_changed = before["pdr_version"] != after["pdr_version"]

    added = tuple(after_records[key] for key in sorted(after_records.keys() - before_records.keys()))
    removed = tuple(before_records[key] for key in sorted(before_records.keys() - after_records.keys()))
    matched = sorted(before_records.keys() & after_records.keys())

    format_paths: set[str] = set()
    changed: list[RecordChange] = []
    for record_id in matched:
        old = before_records[record_id]
        new = after_records[record_id]
        changes: list[FieldChange] = []
        decision_changed = False
        for section in COMPARED_SECTIONS:
            old_section = _mapping(old.get(section))
            new_section = _mapping(new.get(section))
            for key in sorted(old_section.keys() | new_section.keys()):
                path = f"{section}.{key}"
                if version_changed and (key in old_section) != (key in new_section):
                    format_paths.add(path)
                    continue
                old_value = old_section.get(key, ABSENT)
                new_value = new_section.get(key, ABSENT)
                if old_value != new_value:
                    changes.append(FieldChange(record_id, path, old_value, new_value))
                    if section == "decision":
                        decision_changed = True
        if changes:
            changed.append(
                RecordChange(
                    record_id=record_id,
                    asset_name=_asset_name(new) or _asset_name(old) or record_id,
                    decision_changed=decision_changed,
                    changes=tuple(changes),
                    before_record=old,
                    after_record=new,
                )
            )

    if version_changed:
        for key in sorted((before.keys() ^ after.keys()) - {"records"}):
            format_paths.add(key)
    # Fields that exist only in the AFTER document were added by its format
    # version; otherwise the AFTER document is the older format.
    format_added = any(
        path in after or _path_in_records(after_records, path) for path in format_paths
    )

    return PDRDiff(
        before_path=before_path,
        after_path=after_path,
        before_version=str(before["pdr_version"]),
        after_version=str(after["pdr_version"]),
        before_verification=before_verification,
        after_verification=after_verification,
        before_document_hash=str(before["document_hash"]),
        after_document_hash=str(after["document_hash"]),
        provenance=_provenance(before, after),
        matched_count=len(matched),
        added=added,
        removed=removed,
        changed=tuple(changed),
        format_differences=tuple(sorted(format_paths)),
        format_differences_added=format_added,
    )


def render_markdown(diff: PDRDiff) -> str:
    lines = ["# PDR comparison", "", "## Result", ""]
    decision_changes = [change for change in diff.changed if change.decision_changed]
    state_only = [change for change in diff.changed if not change.decision_changed]

    lines.append(
        f"{len(decision_changes)} of {diff.matched_count} decisions changed. "
        f"{_count(len(diff.added), 'record was', 'records were')} added. "
        f"{_count(len(diff.removed), 'record was', 'records were')} removed."
    )
    if state_only:
        lines.append(
            f"{_count(len(state_only), 'record changed', 'records changed')} "
            "only in observed state."
        )
    lines.extend(["", "Both files passed integrity verification:"])
    lines.append(_verification_line("Before", diff.before_path, diff.before_version, diff.before_verification))
    lines.append(_verification_line("After", diff.after_path, diff.after_version, diff.after_verification))

    lines.extend(["", "## What changed between the two runs", ""])
    for item in diff.provenance:
        lines.append(f"- {item.label}: {_provenance_summary(item)}.")
    lines.append("")
    changed_items = diff.changed_provenance
    if len(changed_items) > 1:
        lines.append(MULTIPLE_CAUSES_TEXT)
    elif len(changed_items) == 1:
        lines.append(SINGLE_CAUSE_TEXT.format(item=changed_items[0].label))
    else:
        lines.append(NO_CAUSE_TEXT)

    if decision_changes:
        lines.extend(["", "## Decisions that changed"])
        for change in decision_changes:
            lines.extend(_render_record_change(change))

    if state_only:
        lines.extend(["", "## Observed state changed, decision unchanged"])
        for change in state_only:
            lines.extend(_render_record_change(change))

    if diff.added:
        lines.extend(["", "## Records added", ""])
        for record in diff.added:
            lines.append(_record_line(record))

    if diff.removed:
        lines.extend(["", "## Records removed", ""])
        for record in diff.removed:
            lines.append(_record_line(record))

    if diff.format_differences:
        template = (
            FORMAT_DIFFERENCES_TEXT
            if diff.format_differences_added
            else FORMAT_DIFFERENCES_REMOVED_TEXT
        )
        lines.extend(["", "## Format differences (not decision changes)", ""])
        lines.append(
            template.format(before=diff.before_version, after=diff.after_version)
        )
        lines.append(", ".join(markdown_inline(path) for path in diff.format_differences) + ".")

    if diff.changed:
        lines.extend(["", "## Field details", ""])
        lines.append("| Record | Field | Before | After |")
        lines.append("|---|---|---|---|")
        for change in diff.changed:
            for item in change.changes:
                lines.append(
                    "| "
                    + " | ".join(
                        markdown_inline(value)
                        for value in (
                            item.record_id,
                            item.field,
                            _display(item.before),
                            _display(item.after),
                        )
                    )
                    + " |"
                )

    return "\n".join(lines) + "\n"


def to_dict(diff: PDRDiff) -> dict[str, Any]:
    changed_items = diff.changed_provenance
    return {
        "changed": diff.has_changes,
        "before": {
            "path": diff.before_path,
            "pdr_version": diff.before_version,
            "document_hash": diff.before_document_hash,
            "verification": diff.before_verification.to_dict(),
        },
        "after": {
            "path": diff.after_path,
            "pdr_version": diff.after_version,
            "document_hash": diff.after_document_hash,
            "verification": diff.after_verification.to_dict(),
        },
        "provenance": [
            {
                "item": item.key,
                "changed": item.changed,
                "before": item.before,
                "after": item.after,
            }
            for item in diff.provenance
        ],
        "attribution": {
            "changed_items": [item.key for item in changed_items],
            "single_cause": len(changed_items) == 1,
        },
        "counts": {
            "matched": diff.matched_count,
            "decisions_changed": sum(1 for change in diff.changed if change.decision_changed),
            "records_changed": len(diff.changed),
            "added": len(diff.added),
            "removed": len(diff.removed),
        },
        "records_added": [_record_summary(record) for record in diff.added],
        "records_removed": [_record_summary(record) for record in diff.removed],
        "records_changed": [
            {
                "record_id": change.record_id,
                "asset_name": change.asset_name,
                "decision_changed": change.decision_changed,
                "changes": [
                    {"field": item.field, "before": item.before, "after": item.after}
                    for item in change.changes
                ],
            }
            for change in diff.changed
        ],
        "format_differences": list(diff.format_differences),
    }


def render_json(diff: PDRDiff) -> str:
    return json.dumps(to_dict(diff), indent=2, ensure_ascii=True) + "\n"


def _verify_or_raise(document: Any, label: str) -> VerificationResult:
    result = verify_pdr_document(document)
    if not result.passed:
        failed = len([check for check in result.checks if not check.passed])
        raise PDRDiffError(
            f"{label} file failed integrity verification "
            f"({len(result.checks) - failed} of {len(result.checks)} checks passed). "
            "No comparison was produced."
        )
    return result


def _records_by_id(document: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(document["records"]):
        if not isinstance(record, dict) or not isinstance(record.get("record_id"), str):
            raise PDRDiffError(f"{label} file record {index} has no record_id.")
        record_id = record["record_id"]
        if record_id in records:
            raise PDRDiffError(f"{label} file repeats record_id {record_id!r}.")
        records[record_id] = record
    return records


def _provenance(before: dict[str, Any], after: dict[str, Any]) -> tuple[ProvenanceItem, ...]:
    items = []

    old_source = _mapping(before.get("input_snapshot")).get("source_hash")
    new_source = _mapping(after.get("input_snapshot")).get("source_hash")
    items.append(ProvenanceItem("input", "Input file", old_source != new_source, old_source, new_source))

    old_policy = _mapping(before.get("policy_context"))
    new_policy = _mapping(after.get("policy_context"))
    policy_changed = old_policy.get("policy_pack_hash") != new_policy.get("policy_pack_hash")
    old_label = _policy_label(old_policy)
    new_label = _policy_label(new_policy)
    before_label, after_label = old_label, new_label
    same_pack = old_policy.get("policy_pack_id") == new_policy.get("policy_pack_id")
    if policy_changed and same_pack and old_label != new_label:
        # Show the pack identifier once: "nist-pqc-basic 0.2 -> 0.3".
        after_label = str(new_policy.get("policy_pack_version", "unknown"))
    items.append(
        ProvenanceItem(
            "policy_pack",
            "Policy pack",
            policy_changed,
            {"label": old_label, "policy_pack_hash": old_policy.get("policy_pack_hash")},
            {"label": new_label, "policy_pack_hash": new_policy.get("policy_pack_hash")},
            before_label,
            after_label,
        )
    )

    old_registry = before.get("registry_context")
    new_registry = after.get("registry_context")
    old_registry_label = _registry_label(old_registry, before["pdr_version"])
    new_registry_label = _registry_label(new_registry, after["pdr_version"])
    old_registry_hash = _mapping(old_registry).get("registry_hash")
    new_registry_hash = _mapping(new_registry).get("registry_hash")
    registry_changed = old_registry_hash != new_registry_hash
    items.append(
        ProvenanceItem(
            "registry",
            "Algorithm registry",
            registry_changed,
            {"label": old_registry_label, "registry_hash": old_registry_hash},
            {"label": new_registry_label, "registry_hash": new_registry_hash},
            old_registry_label,
            new_registry_label,
        )
    )

    old_engine = _engine_version(before)
    new_engine = _engine_version(after)
    items.append(_versioned_item("engine", "QSTriage version", old_engine, new_engine))
    items.append(
        _versioned_item("pdr_version", "PDR format", before["pdr_version"], after["pdr_version"])
    )
    return tuple(items)


def _versioned_item(key: str, label: str, before: Any, after: Any) -> ProvenanceItem:
    return ProvenanceItem(key, label, before != after, before, after, str(before), str(after))


def _provenance_summary(item: ProvenanceItem) -> str:
    """Return "same", "same (x)", "changed", "changed (a -> b)", or
    "changed (x, different content)". Labels are escaped; the arrow is not."""

    if item.after_label is None:
        return "changed" if item.changed else "same"
    after = markdown_inline(item.after_label)
    if not item.changed:
        return f"same ({after})"
    if item.before_label == item.after_label:
        return f"changed ({after}, different content)"
    return f"changed ({markdown_inline(item.before_label)} -> {after})"


def _policy_label(policy: dict[str, Any]) -> str:
    return f"{policy.get('policy_pack_id', 'unknown')} {policy.get('policy_pack_version', 'unknown')}"


def _registry_label(registry: Any, pdr_version: Any) -> str:
    if not isinstance(registry, dict):
        return f"not recorded in PDR {pdr_version}"
    return f"version {registry.get('registry_version', 'unknown')}"


def _engine_version(document: dict[str, Any]) -> str:
    versions = sorted(
        {
            str(_mapping(record.get("engine")).get("version"))
            for record in document["records"]
            if isinstance(record, dict) and _mapping(record.get("engine")).get("version") is not None
        }
    )
    if not versions:
        return "not recorded"
    return ", ".join(versions)


def _render_record_change(change: RecordChange) -> list[str]:
    old_decision = _mapping(change.before_record.get("decision"))
    new_decision = _mapping(change.after_record.get("decision"))
    old_state = _mapping(change.before_record.get("observed_state"))
    new_state = _mapping(change.after_record.get("observed_state"))
    lines = [
        "",
        f"### {markdown_inline(change.asset_name)} ({markdown_inline(change.record_id)})",
        "",
        _transition_line("Action", old_decision.get("action_type", ABSENT), new_decision.get("action_type", ABSENT)),
        _transition_line(
            "Algorithm status",
            old_state.get("standard_status", ABSENT),
            new_state.get("standard_status", ABSENT),
        ),
        "- Human review: "
        f"{_review_text(old_decision.get('human_review_required'))} before; "
        f"{_review_text(new_decision.get('human_review_required'))} after.",
    ]
    reason_codes = new_decision.get("reason_codes")
    if isinstance(reason_codes, list) and reason_codes:
        lines.extend(
            [
                "",
                "Reason codes after: "
                + ", ".join(markdown_inline(code) for code in reason_codes),
            ]
        )
    return lines


def _transition_line(label: str, before: Any, after: Any) -> str:
    if before == after:
        return f"- {label}: {markdown_inline(_display(after))} (unchanged)"
    return f"- {label}: {markdown_inline(_display(before))} -> {markdown_inline(_display(after))}"


def _review_text(value: Any) -> str:
    if value is True:
        return "required"
    if value is False:
        return "not required"
    return "not recorded"


def _record_line(record: dict[str, Any]) -> str:
    decision = _mapping(record.get("decision"))
    name = _asset_name(record) or record["record_id"]
    return (
        f"- {markdown_inline(name)} ({markdown_inline(record['record_id'])}): "
        f"action {markdown_inline(_display(decision.get('action_type', ABSENT)))}"
    )


def _record_summary(record: dict[str, Any]) -> dict[str, Any]:
    decision = _mapping(record.get("decision"))
    return {
        "record_id": record["record_id"],
        "asset_name": _asset_name(record),
        "action_type": decision.get("action_type"),
    }


def _asset_name(record: dict[str, Any]) -> str | None:
    name = _mapping(record.get("observed_state")).get("asset_name")
    return name if isinstance(name, str) and name else None


def _path_in_records(records: dict[str, dict[str, Any]], path: str) -> bool:
    if "." not in path:
        return False
    section, key = path.split(".", 1)
    return any(key in _mapping(record.get(section)) for record in records.values())


def _display(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))


def _count(number: int, singular: str, plural: str) -> str:
    return f"{number} {singular if number == 1 else plural}"


def _verification_line(label: str, path: str, version: str, result: VerificationResult) -> str:
    passed = len([check for check in result.checks if check.passed])
    padding = " " if label == "After" else ""
    return (
        f"- {label}:{padding} {markdown_inline(path)} (PDR {markdown_inline(version)}), "
        f"{passed} of {len(result.checks)} checks passed."
    )


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


__all__ = [
    "PDRDiff",
    "PDRDiffError",
    "PDRVerificationInputError",
    "diff_pdr_documents",
    "diff_pdr_files",
    "render_json",
    "render_markdown",
    "to_dict",
]
