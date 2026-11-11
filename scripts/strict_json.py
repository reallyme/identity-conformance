#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bounded JSON decoding shared by certification control-plane readers."""

from __future__ import annotations

import json
import math
from typing import Any


DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
MAX_NUMBER_CHARACTERS = 128


class StrictJsonError(Exception):
    """A stable parse failure that never contains attacker-controlled input."""


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("json_duplicate_member")
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> None:
    raise StrictJsonError("json_non_finite_number")


def _parse_integer(value: str) -> int:
    if len(value) > MAX_NUMBER_CHARACTERS:
        raise StrictJsonError("json_number_too_large")
    return int(value)


def _parse_float(value: str) -> float:
    if len(value) > MAX_NUMBER_CHARACTERS:
        raise StrictJsonError("json_number_too_large")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictJsonError("json_non_finite_number")
    return parsed


def _validate_tree(value: object, max_depth: int, max_nodes: int) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > max_nodes:
            raise StrictJsonError("json_node_limit_exceeded")
        if depth > max_depth:
            raise StrictJsonError("json_depth_limit_exceeded")
        if isinstance(current, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in current):
                raise StrictJsonError("json_invalid_unicode")
        elif isinstance(current, dict):
            stack.extend((key, depth + 1) for key in current)
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def loads(
    source: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> object:
    """Decode strict JSON with duplicate, numeric, and structure bounds."""

    if max_depth < 1 or max_nodes < 1:
        raise StrictJsonError("json_invalid_limits")
    try:
        value = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_non_finite_constant,
            parse_int=_parse_integer,
            parse_float=_parse_float,
        )
        _validate_tree(value, max_depth, max_nodes)
        return value
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise StrictJsonError("json_invalid") from error
