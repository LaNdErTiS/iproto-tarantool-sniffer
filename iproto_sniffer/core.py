import json
import time
from typing import Any, TextIO

from rich import print
from scapy.all import Packet
from scapy.layers.inet import IP, TCP

from .helpers import remove_none_recursive
from .payload_process import process_payload


def format_headers(packet: Packet, layer_ip: IP, layer_tcp: TCP) -> str:
    """
    Formats IP and TCP headers into a readable string.

    Args:
        packet: The scapy Packet object.
        layer_ip: The IP layer of the packet.
        layer_tcp: The TCP layer of the packet.

    Returns:
        A formatted string containing header information.
    """
    return (
        f"\nPacket from {layer_ip.src}:{layer_tcp.sport} to {layer_ip.dst}:{layer_tcp.dport}\n"
        f"IP ID: {layer_ip.id} | TCP Seq: {layer_tcp.seq} | Ack: {layer_tcp.ack} | Window: {layer_tcp.window}\n"
        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time)))}\n"
    )


def process_packet_payload(payload: bytes, include_hex: bool = False) -> dict[str, Any] | list[Any] | Any:
    """
    Processes the packet payload and returns a structured dictionary.

    Args:
        payload: The raw bytes of the packet payload.
        include_hex: If True, includes a hex representation of the payload.

    Returns:
        A dictionary representing the processed payload.

    Raises:
        ValueError: If an error occurs during payload processing.
    """
    try:
        payload_dict = process_payload(payload, include_hex=include_hex)
        return remove_none_recursive(payload_dict)
    except Exception as e:
        raise ValueError(f"Error processing payload: {e}") from e


def format_packet_output(
    packet: Packet,
    layer_ip: IP,
    layer_tcp: TCP,
    include_hex: bool = False,
    show_headers: bool = True,
) -> str:
    """
    Formats the complete output for a single packet.

    Args:
        packet: The scapy Packet object.
        layer_ip: The IP layer of the packet.
        layer_tcp: The TCP layer of the packet.
        include_hex: If True, includes hex in the payload output.
        show_headers: If True, includes IP/TCP headers in the output.

    Returns:
        A fully formatted string ready for display or writing to a file.
    """
    output_lines: list[str] = []

    if show_headers:
        output_lines.append(format_headers(packet, layer_ip, layer_tcp))

    payload = bytes(layer_tcp.payload)
    if len(payload) > 0:
        try:
            payload_dict = process_packet_payload(payload, include_hex)
            output_lines.append(json.dumps(payload_dict, indent=4))
        except ValueError as e:
            output_lines.append(str(e))
    else:
        output_lines.append("Packet with empty payload\n")

    return "\n".join(output_lines) + "\n" + "=" * 80 + "\n"


def packet_callback(
    packet: Packet,
    *,
    include_hex: bool = False,
    output_writer: TextIO | None = None,
    empty_packet: bool = False,
    show_headers: bool = True,
) -> None:
    """
    Callback function for each captured packet.

    This function processes the packet, formats it, and writes the output.

    Args:
        packet: The scapy Packet object.
        include_hex: Flag to include hex in payload output.
        output_writer: A file-like object to write output to. If None, prints to console.
        empty_packet: Flag to process packets with empty payload.
        show_headers: Flag to show detailed headers.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        layer_ip = packet[IP]
        layer_tcp = packet[TCP]
        payload = bytes(layer_tcp.payload)

        if len(payload) == 0 and not empty_packet:
            return

        output_text = format_packet_output(
            packet,
            layer_ip,
            layer_tcp,
            include_hex=include_hex,
            show_headers=show_headers,
        )

        if output_writer:
            output_writer.write(output_text)
            output_writer.flush()
        else:
            print(output_text)

    except Exception as e:
        error_msg = f"Error processing packet: {e}\n" + "=" * 80 + "\n"
        if output_writer:
            output_writer.write(error_msg)
        else:
            print(error_msg)
