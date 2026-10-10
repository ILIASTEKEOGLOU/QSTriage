"""Integrity verification for PDR documents.

``verify_pdr_file`` recomputes the hashes and derived identifiers of a PDR
document and reports each check. It reads the file once within a size limit,
rejects duplicate JSON keys and non-finite numbers, and never writes.

Each PDR contract version is verified under its own rules. PDR 0.2 hashes the
output of Python ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`` encoded as UTF-8. That rule is frozen here so that 0.2
documents stay verifiable after later contract versions change the
serialization.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from qstriage.limits import MAX_PDR_FILE_BYTES, ResourceLimitError, read_text_limited


SUPPORTED_PDR_VERSIONS = frozenset({"0.2"})


class PDRVerificationInputError(ValueError):
    """Raised when a file cannot be read as a PDR document to verify."""


@dataclass(frozen=True)
class VerificationCheck:
    check: str
    subject: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class VerificationResult:
    pdr_version: str
    checks: tuple[VerificationCheck, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pdr_version": self.pdr_version,
            "passed": self.passed,
            "checks": [
                {
                    "check": check.check,
                    "subject": check.subject,
                    "passed": check.passed,
                    "detail": check.detail,
                }
                for check in self.checks
            ],
        }


def verify_pdr_file(path: str | Path) -> VerificationResult:
    try:
        text = read_text_limited(
            path,
            max_bytes=MAX_PDR_FILE_BYTES,
            label="PDR file",
        )
    except (OSError, ResourceLimitError, ValueError) as error:
        raise PDRVerificationInputError(str(error)) from error
    return verify_pdr_text(text)


def verify_pdr_text(text: str) -> VerificationResult:
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except RecursionError as error:
        raise PDRVerificationInputError(
            "PDR JSON exceeds the supported nesting depth."
        ) from error
    except json.JSONDecodeError as error:
        raise PDRVerificationInputError(f"PDR file is not valid JSON: {error}") from error
    return verify_pdr_document(document)


def verify_pdr_document(document: Any) -> VerificationResult:
    _require_structure(document)
    version = document["pdr_version"]
    if version not in SUPPORTED_PDR_VERSIONS:
        raise PDRVerificationInputError(
            f"Unsupported PDR version for verification: {version!r}"
        )
    return _verify_v0_2(document)


def pdr_v0_2_hash(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_v0_2(document: dict[str, Any]) -> VerificationResult:
    checks: list[VerificationCheck] = []

    neutral = copy.deepcopy(document)
    neutral["document_hash"] = None
    checks.append(
        _compare("document_hash", "document", document["document_hash"], pdr_v0_2_hash(neutral))
    )

    expected_run_id = "run:" + pdr_v0_2_hash(
        {
            "source_hash": document["input_snapshot"].get("source_hash"),
            "policy_pack_hash": document["policy_context"].get("policy_pack_hash"),
            "pdr_version": document["pdr_version"],
        }
    ).split(":", 1)[1][:16]
    checks.append(_compare("run_id", "document", document["run_id"], expected_run_id))

    for index, record in enumerate(document["records"]):
        subject = _record_subject(record, index)
        if not isinstance(record, dict) or not isinstance(
            record.get("record_integrity"), dict
        ):
            checks.append(
                VerificationCheck("record_structure", subject, False, "record_integrity is missing")
            )
            continue

        stated = record["record_integrity"].get("record_hash")
        neutral_record = copy.deepcopy(record)
        neutral_record["record_integrity"]["record_hash"] = None
        checks.append(
            _compare("record_hash", subject, stated, pdr_v0_2_hash(neutral_record))
        )
        for key in ("pdr_version", "run_id", "input_snapshot", "policy_context"):
            checks.append(
                VerificationCheck(
                    f"record_{key}_matches_document",
                    subject,
                    record.get(key) == document.get(key),
                    "" if record.get(key) == document.get(key) else f"{key} differs from the document",
                )
            )

    return VerificationResult(pdr_version=document["pdr_version"], checks=tuple(checks))


def _compare(check: str, subject: str, stated: Any, computed: str) -> VerificationCheck:
    if stated == computed:
        return VerificationCheck(check, subject, True)
    return VerificationCheck(
        check,
        subject,
        False,
        f"stated {stated!r}, computed {computed!r}",
    )


def _record_subject(record: Any, index: int) -> str:
    if isinstance(record, dict) and isinstance(record.get("record_id"), str):
        return record["record_id"]
    return f"records[{index}]"


def _require_structure(document: Any) -> None:
    if not isinstance(document, dict):
        raise PDRVerificationInputError("PDR document must be a JSON object.")
    required = {
        "pdr_version": str,
        "run_id": str,
        "input_snapshot": dict,
        "policy_context": dict,
        "records": list,
        "document_hash": str,
    }
    for key, expected_type in required.items():
        if not isinstance(document.get(key), expected_type):
            raise PDRVerificationInputError(
                f"PDR document field {key!r} is missing or has the wrong type."
            )


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PDRVerificationInputError(f"PDR JSON contains duplicate key {key!r}.")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise PDRVerificationInputError(f"PDR JSON contains the non-finite number {value}.")
