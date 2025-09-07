from typing import Any

import click
from scapy.all import conf, sniff

from .core import packet_callback
from .utils import get_output_writer


@click.command()
@click.option("--interface", default="lo0", help="Network interface to sniff on.")
@click.option(
    "--filter",
    default="tcp port 3301",
    help="Traffic filter for sniffing (e.g., 'tcp port 3301').",
)
@click.option("--from_pcap", default="", help="Path to a .pcap file to read from.")
@click.option("--hex", is_flag=True, default=False, help="Include payload hex in output.")
@click.option("--output", default="/dev/stdout", help="Path to the output file.")
@click.option(
    "--empty_packet",
    is_flag=True,
    default=False,
    help="Show packets with empty payload.",
)
@click.option("--show_headers", is_flag=True, default=False, help="Show detailed IP/TCP headers.")
def main(
    interface: str,
    filter: str,
    from_pcap: str,
    hex: bool,
    output: str,
    empty_packet: bool,
    show_headers: bool,
) -> None:
    """
    A command-line network packet sniffer that captures and processes TCP packets.

    This tool captures TCP packets based on a specified filter, processes their payloads,
    and outputs the results in a structured format, either to the console or a file.
    It can read packets from a live network interface or a .pcap file.
    """
    conf.iface = interface  # type: ignore

    output_writer = get_output_writer(output)

    def callback_with_options(packet: Any) -> None:
        packet_callback(
            packet,
            include_hex=hex,
            output_writer=output_writer,
            empty_packet=empty_packet,
            show_headers=show_headers,
        )

    try:
        if from_pcap:
            click.echo(f"Reading packets from file: {from_pcap}")
            sniff(offline=from_pcap, prn=callback_with_options, filter="", store=0)
        else:
            click.echo(f"Starting sniffing on interface: {interface} with filter: '{filter}'")
            sniff(filter="", prn=callback_with_options, store=0)
    except PermissionError:
        click.echo(
            f"Error: Permission denied. Try running with sudo/administrator privileges to sniff on '{interface}'"
        )
    except Exception as e:
        click.echo(f"An unexpected error occurred: {e}")
    finally:
        if output != "/dev/stdout" and output_writer:
            click.echo(f"Closing output file: {output}")
            output_writer.close()


if __name__ == "__main__":
    main()
