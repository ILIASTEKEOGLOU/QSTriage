from __future__ import annotations

import json
from pathlib import Path
import struct

import pytest

from qstriage.canonical_json import (
    CanonicalizationError,
    canonical_sha256,
    canonicalize,
)


CROSSCHECK = json.loads(
    (Path(__file__).parent / "fixtures" / "rfc8785_crosscheck.json").read_text(
        encoding="utf-8"
    )
)

# RFC 8785, Appendix B.
APPENDIX_B = (
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
)


@pytest.mark.parametrize(("ieee754", "expected"), APPENDIX_B)
def test_rfc8785_appendix_b_numbers(ieee754: str, expected: str) -> None:
    value = struct.unpack(">d", bytes.fromhex(ieee754))[0]

    assert canonicalize(value) == expected.encode("ascii")


def test_rfc8785_section_3_2_2_primitives() -> None:
    value = json.loads(
        '{"numbers":[333333333.33333329,1E30,4.50,2e-3,'
        '0.000000000000000000000000001],'
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        '"literals":[null,true,false]}'
    )

    assert canonicalize(value) == (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    ).encode("utf-8")


def test_rfc8785_section_3_2_3_sorting_by_utf16_code_units() -> None:
    value = json.loads(
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return",'
        '"\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
        '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
        '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
    )

    assert list(json.loads(canonicalize(value)).values()) == [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]


def test_crosscheck_fixture_is_from_the_independent_implementation() -> None:
    assert CROSSCHECK["generator"].startswith("rfc8785 ")
    assert len(CROSSCHECK["cases"]) > 500


@pytest.mark.parametrize(
    "case",
    CROSSCHECK["cases"],
    ids=[str(index) for index in range(len(CROSSCHECK["cases"]))],
)
def test_matches_independent_rfc8785_output(case: dict[str, str]) -> None:
    assert canonicalize(json.loads(case["input"])) == case["canonical"].encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        2**53 + 1,
        -(2**53) - 1,
        {"key": "\ud800"},
        {"\udfff": 1},
        {1: "non-string key"},
        {"set": {1, 2}},
    ],
)
def test_values_outside_rfc8785_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_canonical_sha256_prefix_and_determinism() -> None:
    first = canonical_sha256({"b": 1.0, "a": [True, None]})
    second = canonical_sha256({"a": [True, None], "b": 1})

    assert first == second
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64
