from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError


def format_inventory_load_error(error: Exception, *, path: str | Path | None = None) -> str:
    location = f" in {path}" if path is not None else ""

    if isinstance(error, FileNotFoundError):
        return f"Inventory file not found{location}."

    if isinstance(error, yaml.YAMLError):
        return _format_yaml_error(error, location)

    if isinstance(error, ValidationError):
        return _format_validation_error(error, location)

    if isinstance(error, ValueError):
        return f"Inventory validation failed{location}: {error}"

    return f"Inventory loading failed{location}: {error}"


def _format_yaml_error(error: yaml.YAMLError, location: str) -> str:
    mark = getattr(error, "problem_mark", None)
    problem = getattr(error, "problem", None)

    if mark is not None:
        line = mark.line + 1
        column = mark.column + 1
        detail = f" near line {line}, column {column}"
    else:
        detail = ""

    if problem:
        return f"Inventory YAML is malformed{location}{detail}: {problem}"

    return f"Inventory YAML is malformed{location}{detail}."


def _format_validation_error(error: ValidationError, location: str) -> str:
    messages = [f"Inventory validation failed{location}."]

    for item in error.errors():
        field_path = _format_location(item.get("loc", ()))
        message = item.get("msg", "Invalid value")
        error_type = item.get("type", "unknown_error")
        context = item.get("ctx") or {}

        if error_type == "extra_forbidden":
            messages.append(f"- Unknown field `{field_path}` is not allowed.")
        elif error_type == "missing":
            messages.append(f"- Missing required field `{field_path}`.")
        elif error_type == "enum":
            expected = context.get("expected")
            if expected:
                messages.append(
                    f"- Invalid value for `{field_path}`. Expected one of: {expected}."
                )
            else:
                messages.append(f"- Invalid enum value for `{field_path}`.")
        elif error_type == "greater_than_equal":
            limit = context.get("ge")
            messages.append(f"- `{field_path}` must be greater than or equal to {limit}.")
        elif error_type == "less_than_equal":
            limit = context.get("le")
            messages.append(f"- `{field_path}` must be less than or equal to {limit}.")
        elif error_type == "value_error":
            messages.append(f"- {message}")
        else:
            messages.append(f"- `{field_path}`: {message}")

    return "\n".join(messages)


def _format_location(location: Any) -> str:
    if not location:
        return "<root>"

    parts: list[str] = []

    for item in location:
        if isinstance(item, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{item}]"
            else:
                parts.append(f"[{item}]")
        else:
            parts.append(str(item))

    return ".".join(parts)
