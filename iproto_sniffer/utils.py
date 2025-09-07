from pathlib import Path
from typing import TextIO

from rich import print


def get_output_writer(output_path: str) -> TextIO | None:
    """
    Opens a file for writing or returns None for stdout.

    Args:
        output_path: The path to the output file. If "/dev/stdout", returns None.

    Returns:
        A file object in write mode, or None if outputting to stdout.
    """
    if output_path == "/dev/stdout":
        return None

    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        return open(output_path, "w")
    except OSError as e:
        try:
            print(f"Error: Could not open output file '{output_path}': {e}")
        except ImportError:
            print(f"Error: Could not open output file '{output_path}': {e}")
        raise
