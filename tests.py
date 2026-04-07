"""

Run with:  python -m pytest tests.py -v
           python tests.py          (no pytest needed)
"""

import time
import unittest
from unittest.mock import MagicMock, patch

# ── We mock Scapy before importing our module so tests don't need root ─────────
import sys, types

# Build a minimal fake scapy package so sniffer.py can be imported without root
def _make_fake_scapy():
    scapy_all = types.ModuleType("scapy.all")
    scapy_pkt = types.ModuleType("scapy.packet")
    scapy_mod = types.ModuleType("scapy")

    # Create fake layer classes
    class _Layer:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    class FakeIP(_Layer):  pass
    class FakeTCP(_Layer): pass
    class FakeUDP(_Layer): pass
    class FakeICMP(_Layer): pass
    class FakeARP(_Layer): pass
    class FakeRaw(_Layer): pass

    scapy_all.IP   = FakeIP
    scapy_all.TCP  = FakeTCP
    scapy_all.UDP  = FakeUDP
    scapy_all.ICMP = FakeICMP
    scapy_all.ARP  = FakeARP
    scapy_all.Raw  = FakeRaw
    scapy_all.sniff = MagicMock()

    scapy_pkt.Packet = object

    sys.modules["scapy"]         = scapy_mod
    sys.modules["scapy.all"]     = scapy_all
    sys.modules["scapy.packet"]  = scapy_pkt

    return FakeIP, FakeTCP, FakeUDP, FakeICMP, FakeARP

FakeIP, FakeTCP, FakeUDP, FakeICMP, FakeARP = _make_fake_scapy()
# ───────────────────────────────────────────────────────────────────────────────

from sniffer import parse_packet, CapturedPacket, _parse_tcp_flags  # noqa: E402
from monitor import TrafficStats  # noqa: E402


def _make_pkt(*layers, size: int = 60):
    """Helper: build a fake Scapy-style packet containing the given layer instances."""
    pkt = MagicMock()
    pkt.time = time.time()
    layer_map = {type(l): l for l in layers}

    def contains(cls):
        return cls in layer_map

    def getitem(cls):
        return layer_map[cls]

    pkt.__contains__ = lambda _, cls: contains(cls)
    pkt.__getitem__  = lambda _, cls: getitem(cls)
    pkt.__len__      = lambda _: size
    return pkt


class TestParseTcpFlags(unittest.TestCase):

    def test_syn_flag(self):
        self.assertEqual(_parse_tcp_flags(0x02), "SYN")

    def test_syn_ack(self):
        result = _parse_tcp_flags(0x12)
        self.assertIn("SYN", result)
        self.assertIn("ACK", result)

    def test_fin_ack(self):
        result = _parse_tcp_flags(0x11)
        self.assertIn("FIN", result)
        self.assertIn("ACK", result)

    def test_no_flags(self):
        self.assertEqual(_parse_tcp_flags(0x00), "")


class TestParsePacket(unittest.TestCase):

    def test_arp_packet(self):
        arp = FakeARP(psrc="192.168.1.1", pdst="192.168.1.100")
        pkt = _make_pkt(arp, size=42)
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "ARP")
        self.assertEqual(result.src_ip, "192.168.1.1")
        self.assertEqual(result.dst_ip, "192.168.1.100")
        self.assertIsNone(result.src_port)
        self.assertEqual(result.size, 42)

    def test_tcp_packet(self):
        ip  = FakeIP(src="10.0.0.1", dst="8.8.8.8", proto=6)
        tcp = FakeTCP(sport=54321, dport=443, flags=0x02)  # SYN
        pkt = _make_pkt(ip, tcp, size=74)
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "TCP")
        self.assertEqual(result.src_port, 54321)
        self.assertEqual(result.dst_port, 443)
        self.assertIn("SYN", result.flags)

    def test_udp_packet(self):
        ip  = FakeIP(src="192.168.1.5", dst="8.8.8.8", proto=17)
        udp = FakeUDP(sport=12345, dport=53)
        pkt = _make_pkt(ip, udp, size=72)
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "UDP")
        self.assertEqual(result.dst_port, 53)

    def test_icmp_packet(self):
        ip   = FakeIP(src="10.0.0.1", dst="10.0.0.2", proto=1)
        icmp = FakeICMP()
        pkt  = _make_pkt(ip, icmp, size=84)
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "ICMP")
        self.assertIsNone(result.src_port)

    def test_non_ip_non_arp_returns_none(self):
        pkt = MagicMock()
        pkt.time = time.time()
        pkt.__contains__ = lambda _, cls: False
        pkt.__len__      = lambda _: 14
        result = parse_packet(pkt)
        self.assertIsNone(result)

    def test_str_representation(self):
        ip  = FakeIP(src="1.2.3.4", dst="5.6.7.8", proto=6)
        tcp = FakeTCP(sport=1234, dport=80, flags=0x10)
        pkt = _make_pkt(ip, tcp, size=100)
        result = parse_packet(pkt)
        s = str(result)
        self.assertIn("TCP", s)
        self.assertIn("1.2.3.4", s)
        self.assertIn("100 bytes", s)


class TestTrafficStats(unittest.TestCase):

    def _pkt(self, src="1.2.3.4", dst="5.6.7.8", proto="TCP",
             sport=1234, dport=80, size=100):
        return CapturedPacket(
            timestamp=time.time(),
            protocol=proto,
            src_ip=src, dst_ip=dst,
            src_port=sport, dst_port=dport,
            size=size,
        )

    def test_record_increments_counters(self):
        stats = TrafficStats()
        stats.record(self._pkt(size=200))
        stats.record(self._pkt(size=300))
        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.total_bytes, 500)

    def test_protocol_counts(self):
        stats = TrafficStats()
        stats.record(self._pkt(proto="TCP"))
        stats.record(self._pkt(proto="TCP"))
        stats.record(self._pkt(proto="UDP"))
        self.assertEqual(stats.protocol_counts["TCP"], 2)
        self.assertEqual(stats.protocol_counts["UDP"], 1)

    def test_top_talkers(self):
        stats = TrafficStats()
        for _ in range(5):
            stats.record(self._pkt(src="10.0.0.1"))
        for _ in range(3):
            stats.record(self._pkt(src="10.0.0.2"))
        talkers = stats.top_talkers(n=2)
        self.assertEqual(talkers[0][0], "10.0.0.1")
        self.assertEqual(talkers[0][1], 5)

    def test_port_scan_detection(self):
        stats = TrafficStats()
        for port in range(1, 20):   # 19 unique ports → above the 15-port default
            stats.record(self._pkt(src="9.9.9.9", dport=port))
        candidates = stats.port_scan_candidates(min_unique_ports=15)
        ips = [ip for ip, _ in candidates]
        self.assertIn("9.9.9.9", ips)

    def test_snapshot_keys(self):
        stats = TrafficStats()
        snap = stats.snapshot()
        for key in ("total_packets", "total_bytes", "bytes_per_second",
                    "protocols", "top_talkers", "top_ports"):
            self.assertIn(key, snap)


if __name__ == "__main__":
    unittest.main(verbosity=2)
