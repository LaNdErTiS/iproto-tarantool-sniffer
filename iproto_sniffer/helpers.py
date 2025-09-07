from typing import Any

# --- Type Aliases for clarity ---
CleanableStructure = dict[str, Any] | list[Any] | Any


def format_hex_with_spaces(data: bytes | str) -> str:
    """
    Formats a hexadecimal string or bytes object by adding a space between each byte.

    For example, '1a2b3c' or b'1a2b3c' becomes '1a 2b 3c'.

    Args:
        data: The input data, either as a bytes object or a hexadecimal string.
              If a string is provided, any existing spaces are removed before
              formatting.

    Returns:
        A formatted string with a space separating each byte (two hex characters).

    Raises:
        TypeError: If the input data is not bytes or str.
    """
    if not isinstance(data, bytes | str):
        raise TypeError(f"Input data must be bytes or str, but got {type(data).__name__}")

    hex_str = data.hex() if isinstance(data, bytes) else data.replace(" ", "")

    return " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def remove_none_recursive(data_structure: CleanableStructure) -> CleanableStructure:
    """
    Recursively removes keys with None values from a dictionary or None items from a list.

    This function traverses nested dictionaries and lists, cleaning out any None values.
    It preserves the original structure for all other data types.

    Args:
        data_structure: The structure to clean. Can be a dictionary, a list, or any
                        other type which will be returned as is.

    Returns:
        A new dictionary or list with all None values removed. If the input is not
        a dict or list, it is returned unchanged.

    Examples:
        >>> remove_none_recursive({"a": 1, "b": None, "c": {"d": None, "e": 2}})
        {'a': 1, 'c': {'e': 2}}

        >>> remove_none_recursive([1, None, [2, None, 3], 4])
        [1, [2, 3], 4]

        >>> remove_none_recursive("just a string")
        'just a string'
    """
    if isinstance(data_structure, dict):
        return {key: remove_none_recursive(value) for key, value in data_structure.items() if value is not None}
    elif isinstance(data_structure, list):
        return [remove_none_recursive(item) for item in data_structure if item is not None]
    else:
        return data_structure
