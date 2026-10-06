"""Safe nested dict/list navigation helpers."""

from __future__ import annotations

from typing import Any, Union


def get_nested(obj: dict, *keys: Union[str, int], default: Any = None) -> Any:
    """Safely navigate a nested dict/list structure.

    Args:
        obj: The root dictionary to traverse.
        *keys: Sequence of string keys or integer indices.
        default: Value returned when traversal fails.

    Returns:
        The value found at the nested path, or *default*.
    """
    cur: Any = obj
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list):
            try:
                cur = cur[k]
            except (IndexError, TypeError):
                return default
        else:
            return default
    return cur if cur is not None else default


def first_nested(obj: dict, *keys: Union[str, int], default: Any = None) -> Any:
    """Return the first element of a list nested at *keys*, or *default*.

    Args:
        obj: The root dictionary to traverse.
        *keys: Sequence of string keys or integer indices.
        default: Value returned when the list is empty or missing.

    Returns:
        First element of the nested list, or *default*.
    """
    lst: Any = get_nested(obj, *keys, default=[])
    if isinstance(lst, list) and lst:
        return lst[0]
    return default
