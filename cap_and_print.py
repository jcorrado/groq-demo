import socket
from scapy.all import sniff, IP, TCP
from datetime import datetime
from termcolor import colored
import argparse


def decode_ip_id(ip_id):
    """
    Decode 16-bit IP ID field to ASCII chars.
    """
    high_byte = ip_id >> 8
    low_byte = ip_id & 0xFF
    decoded = chr(high_byte) + chr(low_byte)
    return decoded.replace("\0", " ")


def maybe_colorize(s):
    if s in "Groq":
        return colored(s, "red")
    elif s in "+Jereme+":
        return colored(s, "green")
    else:
        return s


def process_packet(packet, fqdn_ip, port):
    """
    Process a captured packet, printing relevant details.
    """
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Filter
        if fqdn_ip in {ip_layer.src, ip_layer.dst} and port in {
            tcp_layer.sport,
            tcp_layer.dport,
        }:
            timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")
            ip_id_ascii = decode_ip_id(ip_layer.id)

            flags = []
            if tcp_layer.flags & 0x02:
                flags.append("SYN")
            if tcp_layer.flags & 0x10:
                flags.append("ACK")
            if tcp_layer.flags & 0x01:
                flags.append("FIN")
            flags_str = ",".join(flags) if flags else "NONE"

            tcp_len = len(tcp_layer.payload)

            from_tuple = f"{ip_layer.src}:{tcp_layer.sport}"
            to_tuple = f"{ip_layer.dst}:{tcp_layer.dport}"

            ip_id_ascii = maybe_colorize(ip_id_ascii)
            print(
                f"{timestamp} {from_tuple} -> {to_tuple} IP ID: {ip_id_ascii} [{flags_str}] Segment Length: {tcp_len}"
            )


def main(fqdn, port):
    # Resolve FQDN
    try:
        fqdn_ip = socket.gethostbyname(fqdn)
        print(f"Resolved {fqdn} to {fqdn_ip}")
    except socket.gaierror as e:
        print(f"Error resolving {fqdn}: {e}")
        return

    print(f"Capturing traffic for {fqdn}:{port} (IP: {fqdn_ip})...")
    sniff(
        filter=f"host {fqdn_ip} and tcp port {port}",
        prn=lambda pkt: process_packet(pkt, fqdn_ip, port),
        store=False,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture bidirectional traffic for FQDN and dst port,  printing packet details."
    )

    # positional arguments
    parser.add_argument(
        "fqdn",
        type=str,
        help="The fully qualified domain name to monitor (e.g., example.com).",
    )
    parser.add_argument(
        "port",
        type=int,
        nargs="?",
        default=443,
        help="The TCP port to monitor (default: 443).",
    )

    args = parser.parse_args()
    main(args.fqdn, args.port)
