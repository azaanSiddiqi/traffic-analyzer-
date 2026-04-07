"""
sniffer.py — Core packet capture and parsing module.

Captures live network traffic using Scapy and extracts:
  - Source / destination IP and port
  - Protocol (TCP, UDP, ICMP, ARP, Other)
  - Payload size
  - Timestamp

Usage:
  Run directly to start capturing with default settings, or import
  PacketSniffer into your own scripts.
"""

import time
import socket
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
    from scapy.packet import Packet
except ImportError:
    raise SystemExit("Scapy is not installed. Run: pip install scapy")


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────

@dataclass
class CapturedPacket:
    """Simplified, serialisable representation of a captured packet."""
    timestamp: float
    protocol:  str
    src_ip:    str
    dst_ip:    str
    src_port:  Optional[int]
    dst_port:  Optional[int]
    size:      int          # bytes
    flags:     str = ""     # TCP flags if applicable

    @property
    def direction(self) -> str:
        """Heuristic: classify as INBOUND or OUTBOUND relative to the local machine."""
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return "UNKNOWN"
        return "OUTBOUND" if self.src_ip == local_ip else "INBOUND"

    def __str__(self) -> str:
        port_info = (
            f":{self.src_port} → :{self.dst_port}"
            if self.src_port and self.dst_port
            else ""
        )
        flags = f" [{self.flags}]" if self.flags else ""
        ts    = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return (
            f"[{ts}] {self.protocol:<5}{flags:10} "
            f"{self.src_ip}{port_info} → {self.dst_ip}  "
            f"({self.size} bytes)"
        )


# ──────────────────────────────────────────────
# TCP flag helper
# ──────────────────────────────────────────────

_TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
}

def _parse_tcp_flags(flag_int: int) -> str:
    return "/".join(name for bit, name in _TCP_FLAGS.items() if flag_int & bit)


# ──────────────────────────────────────────────
# Packet parsing
# ──────────────────────────────────────────────

def parse_packet(pkt: Packet) -> Optional[CapturedPacket]:
    """
    Convert a raw Scapy packet into a CapturedPacket.
    Returns None if the packet doesn't have a recognisable IP/ARP layer.
    """
    ts = pkt.time if hasattr(pkt, "time") else time.time()

    # ── ARP (no IP layer) ──────────────────────
    if ARP in pkt:
        return CapturedPacket(
            timestamp=ts,
            protocol="ARP",
            src_ip=pkt[ARP].psrc,
            dst_ip=pkt[ARP].pdst,
            src_port=None,
            dst_port=None,
            size=len(pkt),
        )

    # ── IP-based protocols ─────────────────────
    if IP not in pkt:
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    size   = len(pkt)

    if TCP in pkt:
        return CapturedPacket(
            timestamp=ts,
            protocol="TCP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=pkt[TCP].sport,
            dst_port=pkt[TCP].dport,
            size=size,
            flags=_parse_tcp_flags(pkt[TCP].flags),
        )

    if UDP in pkt:
        return CapturedPacket(
            timestamp=ts,
            protocol="UDP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=pkt[UDP].sport,
            dst_port=pkt[UDP].dport,
            size=size,
        )

    if ICMP in pkt:
        return CapturedPacket(
            timestamp=ts,
            protocol="ICMP",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            size=size,
        )

    # Catch-all for other IP protocols (IGMP, OSPF, etc.)
    proto_num = pkt[IP].proto
    return CapturedPacket(
        timestamp=ts,
        protocol=f"IP/{proto_num}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=None,
        size=size,
    )


# ──────────────────────────────────────────────
# Sniffer class
# ──────────────────────────────────────────────

class PacketSniffer:
    """
    Wraps Scapy's sniff() with filtering, callback support,
    and an optional packet log.
    """

    def __init__(
        self,
        interface:   Optional[str]             = None,
        bpf_filter:  str                       = "",
        callback:    Optional[Callable]        = None,
        store_limit: int                       = 1000,
    ):
        """
        Args:
            interface:   Network interface to listen on (e.g. "eth0").
                         None = Scapy picks the default.
            bpf_filter:  BPF filter string (e.g. "tcp port 80").
            callback:    Called with each CapturedPacket as it arrives.
            store_limit: Max packets kept in self.packets (circular).
        """
        self.interface   = interface
        self.bpf_filter  = bpf_filter
        self.callback    = callback
        self.store_limit = store_limit
        self.packets:    list[CapturedPacket] = []
        self._running    = False

    # ── internal handler ──────────────────────

    def _handle(self, pkt: Packet) -> None:
        captured = parse_packet(pkt)
        if captured is None:
            return
        if len(self.packets) >= self.store_limit:
            self.packets.pop(0)          # keep memory bounded
        self.packets.append(captured)
        if self.callback:
            self.callback(captured)

    # ── public API ────────────────────────────

    def start(self, count: int = 0, timeout: Optional[float] = None) -> None:
        """
        Begin capturing packets.

        Args:
            count:   Stop after this many packets (0 = run until timeout/KeyboardInterrupt).
            timeout: Stop after this many seconds (None = no limit).
        """
        self._running = True
        kwargs = dict(
            prn=self._handle,
            store=False,         # Scapy won't keep its own copy
            count=count,
            filter=self.bpf_filter,
        )
        if self.interface:
            kwargs["iface"] = self.interface
        if timeout:
            kwargs["timeout"] = timeout

        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the sniffer to stop (only effective when running in a thread)."""
        self._running = False

    def clear(self) -> None:
        """Discard all stored packets."""
        self.packets.clear()


# ──────────────────────────────────────────────
# Quick standalone demo
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple packet sniffer")
    parser.add_argument("-i", "--iface",   default=None,  help="Interface (e.g. eth0)")
    parser.add_argument("-f", "--filter",  default="",    help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("-n", "--count",   type=int, default=0,
                        help="Stop after N packets (0 = infinite)")
    parser.add_argument("-t", "--timeout", type=float, default=None,
                        help="Stop after T seconds")
    args = parser.parse_args()

    print(f"[*] Starting sniffer on {'default interface' if not args.iface else args.iface}")
    print(f"[*] Filter: '{args.filter}'" if args.filter else "[*] No BPF filter applied")
    print("[*] Press Ctrl+C to stop\n")

    def print_packet(pkt: CapturedPacket) -> None:
        print(pkt)

    sniffer = PacketSniffer(
        interface=args.iface,
        bpf_filter=args.filter,
        callback=print_packet,
    )
    sniffer.start(count=args.count, timeout=args.timeout)
    print(f"\n[*] Captured {len(sniffer.packets)} packets total.")
