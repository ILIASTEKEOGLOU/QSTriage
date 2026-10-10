"""Versioned algorithm registry bundled with QSTriage.

The registry holds classification data: family, primitive, quantum and
standards status, rationale, and sources. Matching an identifier to an entry
stays in ``qstriage.standards``. See ``design/r0-architecture.md``, section 5.1.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from importlib import resources
import json

from pydantic import BaseModel, ConfigDict, Field, model_validator

from qstriage.canonical_json import canonical_sha256


REGISTRY_RESOURCE = "algorithm_registry.json"
REGISTRY_SCHEMA_VERSION = "1"

POSITIVE_QUANTUM_STATUSES = frozenset({"quantum_resistant"})
POSITIVE_STANDARD_STATUSES = frozenset({"standardized_pqc"})


class SourceStatus(str, Enum):
    final = "final"
    draft = "draft"
    project_policy = "project_policy"


class SchemeType(str, Enum):
    single = "single"
    pq_t_hybrid = "pq_t_hybrid"
    pq_pq_hybrid = "pq_pq_hybrid"


class Lifecycle(str, Enum):
    published = "published"
    draft = "draft"
    deprecated = "deprecated"
    withdrawn = "withdrawn"


class RegistrySource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    section: str | None = None
    status: SourceStatus
    date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}$")


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    identifiers: tuple[str, ...] = ()
    scheme_type: SchemeType
    algorithm_family: str = Field(min_length=1)
    primitive: str = Field(min_length=1)
    quantum_status: str = Field(min_length=1)
    standard_status: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    identifier_resolution: str = Field(min_length=1)
    sources: tuple[RegistrySource, ...] = Field(min_length=1)
    lifecycle: Lifecycle
    components: tuple[str, ...] = ()
    validation_component: str | None = None
    deadlines: tuple[dict[str, str], ...] = ()

    @property
    def source_ids(self) -> tuple[str, ...]:
        return tuple(source.source_id for source in self.sources)

    @property
    def is_positive(self) -> bool:
        return (
            self.quantum_status in POSITIVE_QUANTUM_STATUSES
            or self.standard_status in POSITIVE_STANDARD_STATUSES
        )

    @model_validator(mode="after")
    def validate_entry(self) -> RegistryEntry:
        if self.is_positive:
            if self.lifecycle != Lifecycle.published:
                raise ValueError(
                    f"Registry entry '{self.entry_id}' gives a positive "
                    "classification but is not published."
                )
            if not any(
                source.status == SourceStatus.final for source in self.sources
            ):
                raise ValueError(
                    f"Registry entry '{self.entry_id}' gives a positive "
                    "classification without a final published source."
                )
        if self.scheme_type == SchemeType.single:
            if self.components or self.validation_component is not None:
                raise ValueError(
                    f"Registry entry '{self.entry_id}' is a single scheme but "
                    "declares hybrid components."
                )
        elif len(self.components) < 2:
            raise ValueError(
                f"Hybrid registry entry '{self.entry_id}' needs at least two "
                "components."
            )
        return self


class AlgorithmRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    registry_schema_version: str
    registry_id: str = Field(min_length=1)
    registry_version: str = Field(min_length=1)
    entries: tuple[RegistryEntry, ...] = Field(min_length=1)
    signatures: tuple[dict[str, str], ...] = ()

    @model_validator(mode="after")
    def validate_registry(self) -> AlgorithmRegistry:
        if self.registry_schema_version != REGISTRY_SCHEMA_VERSION:
            raise ValueError(
                "Unsupported algorithm registry schema version: "
                f"{self.registry_schema_version}"
            )
        entry_ids = [entry.entry_id for entry in self.entries]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("Algorithm registry entry IDs must be unique.")
        seen: dict[str, str] = {}
        for entry in self.entries:
            for identifier in entry.identifiers:
                if identifier in seen:
                    raise ValueError(
                        f"Identifier '{identifier}' appears in registry entries "
                        f"'{seen[identifier]}' and '{entry.entry_id}'."
                    )
                seen[identifier] = entry.entry_id
        known = set(entry_ids)
        for entry in self.entries:
            for component in entry.components:
                if component not in known:
                    raise ValueError(
                        f"Registry entry '{entry.entry_id}' references unknown "
                        f"component '{component}'."
                    )
        return self

    def entry(self, entry_id: str) -> RegistryEntry:
        for candidate in self.entries:
            if candidate.entry_id == entry_id:
                return candidate
        raise KeyError(entry_id)


class RegistryLoadError(ValueError):
    """Raised when the bundled registry file is not well-formed JSON data."""


@lru_cache(maxsize=1)
def load_registry() -> AlgorithmRegistry:
    return AlgorithmRegistry.model_validate(_read_registry_data())


@lru_cache(maxsize=1)
def registry_hash() -> str:
    """Return the RFC 8785 SHA-256 hash of the bundled registry data.

    The hash covers the parsed JSON data, not the file bytes, so formatting
    changes do not change it. Any RFC 8785 implementation can recompute it
    from ``qstriage/algorithm_registry.json``.
    """

    return canonical_sha256(_read_registry_data())


def _read_registry_data() -> dict[str, object]:
    text = (
        resources.files("qstriage")
        .joinpath(REGISTRY_RESOURCE)
        .read_text(encoding="utf-8")
    )
    data = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    if not isinstance(data, dict):
        raise RegistryLoadError("Algorithm registry must be a JSON object.")
    return data


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryLoadError(
                f"Algorithm registry contains duplicate key {key!r}."
            )
        result[key] = value
    return result
