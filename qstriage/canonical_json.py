"""RFC 8785 JSON Canonicalization Scheme (JCS).

Serializes the JSON data model used by QSTriage (dict with string keys, list,
str, int, float, bool, None) to the canonical UTF-8 form defined by RFC 8785:

- no whitespace between tokens;
- object members sorted by their names as UTF-16 code units;
- strings with only the escapes RFC 8785 requires;
- numbers in the ECMAScript ``Number.prototype.toString`` form.

Values that RFC 8785 cannot represent are rejected: NaN, infinities,
integers outside the IEEE 754 double range of exact integers, lone
surrogates, and non-string object keys.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import math
from typing import Any


MAX_SAFE_INTEGER = 2**53

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented under RFC 8785."""


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes for ``value``."""

    parts: list[str] = []
    _write(value, parts)
    return "".join(parts).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return ``sha256:`` followed by the hex digest of the canonical bytes."""

    return "sha256:" + hashlib.sha256(canonicalize(value)).hexdigest()


def _write(value: Any, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, int):
        parts.append(_integer(value))
    elif isinstance(value, float):
        parts.append(_number(value))
    elif isinstance(value, dict):
        _write_object(value, parts)
    elif isinstance(value, (list, tuple)):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _write(item, parts)
        parts.append("]")
    else:
        raise CanonicalizationError(
            f"Type {type(value).__name__} is not part of the JSON data model."
        )


def _write_object(value: dict[Any, Any], parts: list[str]) -> None:
    for key in value:
        if not isinstance(key, str):
            raise CanonicalizationError("JSON object keys must be strings.")
    parts.append("{")
    for index, key in enumerate(sorted(value, key=_utf16_sort_key)):
        if index:
            parts.append(",")
        parts.append(_string(key))
        parts.append(":")
        _write(value[key], parts)
    parts.append("}")


def _utf16_sort_key(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare in the same order as UTF-16 code units.
    return _checked(key).encode("utf-16-be")


def _checked(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CanonicalizationError(
            "Strings must not contain lone surrogates."
        ) from error
    return value


def _string(value: str) -> str:
    out = ['"']
    for character in _checked(value):
        code = ord(character)
        escape = _SHORT_ESCAPES.get(code)
        if escape is not None:
            out.append(escape)
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _integer(value: int) -> str:
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(
            "Integers must be within the exact IEEE 754 double range."
        )
    return str(value)


def _number(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and infinities are not valid JSON numbers.")
    if value == 0:
        return "0"

    sign = "-" if value < 0 else ""
    # repr() yields the shortest decimal string that round-trips, which is
    # the digit string ECMAScript selects.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    all_digits = "".join(str(digit) for digit in digit_tuple)
    digits = all_digits.rstrip("0")
    exponent += len(all_digits) - len(digits)
    k = len(digits)
    # Value is 0.<digits> x 10**n.
    n = exponent + k

    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        text = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + text
