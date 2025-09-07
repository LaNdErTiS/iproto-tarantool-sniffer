from io import BytesIO
from typing import Any, cast

import msgpack  # type: ignore

from .data.body import BODY_MAP
from .data.header import HEADER_MAP
from .helpers import format_hex_with_spaces

# --- Type Aliases for clarity ---
MsgPackValue = int | str | float | bytes | bool | None
MsgPackObject = MsgPackValue | list[Any] | dict[str, Any]
FieldMap = dict[str, Any]
ProcessedPacket = dict[str, Any]


def _decode_mapped_value(current_map: FieldMap, raw_value: MsgPackObject) -> MsgPackObject:
    """
    Recursively decodes a raw value based on a provided mapping dictionary.

    It translates numeric keys/values to their string names if defined in the map.
    Handles nested dictionaries and lists.

    Args:
        current_map: The mapping dictionary (e.g., HEADER_MAP or BODY_MAP)
                     that defines how to decode parts of the raw_value.
        raw_value: The value to decode, which can be a primitive type, a list, or a dict.

    Returns:
        The decoded value, with names substituted for numbers where applicable.
    """
    if not isinstance(raw_value, list | dict):
        if current_map.get("values") and raw_value in current_map["values"]:
            return current_map["values"][raw_value]["name"]
        return raw_value

    if isinstance(raw_value, list):
        return [_decode_mapped_value(current_map, item) for item in raw_value]

    if isinstance(raw_value, dict):
        decoded_dict: dict[str, Any] = {}
        for key, value in raw_value.items():
            if key not in current_map:
                decoded_dict[key] = value
                continue

            field_definition = current_map[key]
            field_name = field_definition.get("name", key)

            # Handle special fields that should not be recursively processed
            # (as indicated by the TODO in the original code)
            # This list should ideally be defined elsewhere or made configurable
            special_field_names = {
                BODY_MAP[0x26]["name"],  # type: ignore
                BODY_MAP[0x30]["name"],  # type: ignore
                BODY_MAP[0x32]["name"],  # type: ignore
                BODY_MAP[0x42]["name"],  # type: ignore
                BODY_MAP[0x52]["name"],  # type: ignore
                BODY_MAP[0x5A]["name"],  # type: ignore
                BODY_MAP[0x58]["name"],  # type: ignore
            }

            if field_name in special_field_names:
                decoded_dict[field_name] = value
            else:
                decoded_dict[field_name] = _decode_mapped_value(field_definition, value)
        return decoded_dict


def _extract_msgpack_messages(payload: bytes) -> tuple[list[MsgPackObject], list[int]]:
    """
    Extracts all top-level MessagePack messages from a byte payload.

    It also calculates the byte positions of each message within the payload.

    Args:
        payload: The raw byte string containing one or more MessagePack messages.

    Returns:
        A tuple containing:
        - A list of the unpacked MessagePack objects.
        - A list of starting byte positions for each message in the payload.
          The list has one more element than messages, representing the end of the payload.
    """
    stream = BytesIO(payload)
    unpacker = msgpack.Unpacker(stream, strict_map_key=False)
    messages = list(unpacker)

    positions = [0]
    stream_for_positions = BytesIO(payload)

    # read_size=1 allows us to track the exact position after each object
    unpacker_for_positions = msgpack.Unpacker(stream_for_positions, strict_map_key=False, read_size=1)

    for _ in messages:
        try:
            next(unpacker_for_positions)
            positions.append(stream_for_positions.tell())
        except StopIteration:
            break

    return messages, positions


def _process_iproto_packet(payload: bytes, include_hex: bool) -> ProcessedPacket:
    """
    Processes a payload containing one or more Iproto packets.

    Each Iproto packet consists of a Size, Header, and Body.
    This function decodes each part using the provided HEADER_MAP and BODY_MAP.

    Args:
        payload: The raw byte payload of the Iproto packet(s).
        include_hex: If True, includes the hex representation of each part.

    Returns:
        A dictionary representing the fully decoded Iproto packet(s).
    """
    messages, positions = _extract_msgpack_messages(payload)

    # An Iproto packet is a group of 3 messages: Size, Header, Body
    if len(messages) % 3 != 0:
        # Or handle this as a warning/error
        pass

    result_dict: ProcessedPacket = {}
    num_iproto_packets = len(messages) // 3

    for i in range(num_iproto_packets):
        packet_key = f"Iproto{i}"
        result_dict[packet_key] = {
            "Size": {"Hex": None, "Decoded": None},
            "Header": {"Hex": None, "Decoded": None},
            "Body": {"Hex": None, "Decoded": None},
        }

    for i in range(num_iproto_packets):
        msg_idx = i * 3
        packet_key = f"Iproto{i}"

        # Size
        result_dict[packet_key]["Size"]["Decoded"] = messages[msg_idx]
        if include_hex:
            size_hex = format_hex_with_spaces(payload[positions[msg_idx] : positions[msg_idx + 1]])
            result_dict[packet_key]["Size"]["Hex"] = size_hex

        # Header
        result_dict[packet_key]["Header"]["Decoded"] = _decode_mapped_value(
            cast(FieldMap, HEADER_MAP), messages[msg_idx + 1]
        )
        if include_hex:
            header_hex = format_hex_with_spaces(payload[positions[msg_idx + 1] : positions[msg_idx + 2]])
            result_dict[packet_key]["Header"]["Hex"] = header_hex

        # Body
        result_dict[packet_key]["Body"]["Decoded"] = _decode_mapped_value(
            cast(FieldMap, BODY_MAP), messages[msg_idx + 2]
        )
        if include_hex:
            end_pos = positions[msg_idx + 3] if (msg_idx + 3) < len(positions) else len(payload)
            body_hex = format_hex_with_spaces(payload[positions[msg_idx + 2] : end_pos])
            result_dict[packet_key]["Body"]["Hex"] = body_hex

    return result_dict


def _process_greeting_message(payload: bytes, include_hex: bool) -> ProcessedPacket:
    """
    Processes the 128-byte text greeting message from a Tarantool instance.

    Args:
        payload: The 128-byte raw payload.
        include_hex: If True, includes hex representations of the decoded fields.

    Returns:
        A dictionary with the decoded Tarantool version, UUID, and salt.

    Raises:
        ValueError: If the payload cannot be decoded or is empty.
    """
    try:
        decoded_text = payload.decode("utf-8", errors="ignore")
        lines = [line.strip() for line in decoded_text.split("\n") if line.strip()]
        if not lines:
            raise ValueError("Empty greeting message after decoding.")
    except UnicodeDecodeError as e:
        raise ValueError(f"Error decoding greeting message: {e}") from e

    first_line_parts = lines[0].split(" ")
    if len(first_line_parts) < 2:
        raise ValueError("Malformed greeting message header.")

    uuid = first_line_parts[-1]
    version = " ".join(first_line_parts[:-1])

    salt = lines[1] if len(lines) > 1 else ""

    result_dict: ProcessedPacket = {
        "Greeting message": {
            "Tarantool Version": {"Hex": None, "Decoded": version},
            "Instance UUID": {"Hex": None, "Decoded": uuid},
            "Salt": {"Hex": None, "Decoded": salt},
        }
    }

    if include_hex:
        items_to_hex = [
            (version, "Tarantool Version"),
            (uuid, "Instance UUID"),
            (salt, "Salt"),
        ]
        for value, label in items_to_hex:
            value_bytes = value.encode("utf-8")
            start_index = payload.find(value_bytes)
            if start_index != -1:
                hex_representation = format_hex_with_spaces(payload[start_index : start_index + len(value_bytes)])
                result_dict["Greeting message"][label]["Hex"] = hex_representation
    return result_dict


def process_payload(payload: bytes, include_hex: bool = True) -> ProcessedPacket:
    """
    Main entry point to process a raw packet payload.

    Determines if the payload is a Tarantool greeting message or an Iproto packet
    and dispatches it to the appropriate processing function.

    Args:
        payload: The raw bytes of the packet payload.
        include_hex: If True, includes hex representations in the output.

    Returns:
        A dictionary containing the structured and decoded payload data.

    Raises:
        ValueError: If the payload is a greeting message but cannot be processed.
    """
    # Tarantool responds with a 128-byte text greeting message, not in MsgPack format.
    # Ref: https://www.tarantool.io/en/doc/latest/reference/internals/iproto/authentication/
    if len(payload) == 128:
        return _process_greeting_message(payload, include_hex)

    return _process_iproto_packet(payload, include_hex)
