"""
Learned JSON files, applied threading and OS understanding
Run:
  sudo python monitor.py
  sudo python monitor.py --iface eth0 --alert-threshold 100 --log logs/traffic.json
"""

import json
import time
import argparse
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from sniffer import PacketSniffer, CapturedPacket

@dataclass
class Alert:
    timestamp:   float
    level:       str    # "INFO" | "WARNING" | "CRITICAL"
    category:    str
    description: str
    src_ip:      str = ""

    def __str__(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] ⚠  {self.level:<8} {self.category}: {self.description}"

class TrafficStats:
    """Thread-safe accumulator for packet-level statistics."""

    def __init__(self, window_seconds: int = 60):
        self._lock = threading.Lock()

        # Counters
        self.total_packets:     int = 0
        self.total_bytes:       int = 0
        self.protocol_counts:   dict[str, int]   = defaultdict(int)
        self.src_ip_packets:    dict[str, int]    = defaultdict(int)
        self.src_ip_bytes:      dict[str, int]    = defaultdict(int)
        self.dst_port_counts:   dict[int, int]    = defaultdict(int)

        # Sliding window for per-second throughput (stores (timestamp, bytes) tuples)
        self._window:  deque   = deque()
        self._window_s: int    = window_seconds

        # Port-scan detection: track unique dst_ports per src_ip
        self._src_port_hits: dict[str, set] = defaultdict(set)

    def record(self, pkt: CapturedPacket) -> None:
        with self._lock:
            self.total_packets           += 1
            self.total_bytes             += pkt.size
            self.protocol_counts[pkt.protocol] += 1
            self.src_ip_packets[pkt.src_ip]    += 1
            self.src_ip_bytes[pkt.src_ip]      += pkt.size

            if pkt.dst_port:
                self.dst_port_counts[pkt.dst_port] += 1

            # Port scan tracking
            if pkt.dst_port:
                self._src_port_hits[pkt.src_ip].add(pkt.dst_port)

            # Sliding window entry
            self._window.append((pkt.timestamp, pkt.size))
            cutoff = pkt.timestamp - self._window_s
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()


    @property
    def bytes_per_second(self) -> float:
        """Average bytes/second over the sliding window."""
        with self._lock:
            if len(self._window) < 2:
                return 0.0
            elapsed = self._window[-1][0] - self._window[0][0]
            if elapsed == 0:
                return 0.0
            total = sum(b for _, b in self._window)
            return total / elapsed

    def top_talkers(self, n: int = 5) -> list[tuple[str, int, int]]:
        with self._lock:
            ranked = sorted(
                self.src_ip_packets.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            return [(ip, pkts, self.src_ip_bytes[ip]) for ip, pkts in ranked[:n]]

    def top_ports(self, n: int = 5) -> list[tuple[int, int]]:
      
        with self._lock:
            ranked = sorted(
                self.dst_port_counts.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            return ranked[:n]

    def port_scan_candidates(self, min_unique_ports: int = 15) -> list[tuple[str, int]]:
  
        with self._lock:
            return [
                (ip, len(ports))
                for ip, ports in self._src_port_hits.items()
                if len(ports) >= min_unique_ports
            ]

    def snapshot(self) -> dict:
     
        with self._lock:
            return {
                "timestamp":       time.time(),
                "total_packets":   self.total_packets,
                "total_bytes":     self.total_bytes,
                "bytes_per_second": round(self.bytes_per_second, 2),
                "protocols":       dict(self.protocol_counts),
                "top_talkers":     self.top_talkers(),
                "top_ports":       self.top_ports(),
            }


class AlertEngine:
    """Checks stats and fires alerts when thresholds are crossed."""

    def __init__(
        self,
        packet_rate_threshold: int = 200,   # packets/second
        bw_threshold_kbps:     float = 5000, # KB/s
        port_scan_threshold:   int = 15,    # unique ports per source
    ):
        self.packet_rate_threshold = packet_rate_threshold
        self.bw_threshold_kbps     = bw_threshold_kbps
        self.port_scan_threshold   = port_scan_threshold
        self.alerts: list[Alert]   = []
        self._last_packet_count    = 0
        self._last_check_time      = time.time()

    def check(self, stats: TrafficStats) -> list[Alert]:
        """Run all checks; return any new alerts generated."""
        new_alerts: list[Alert] = []
        now = time.time()

        # ── Bandwidth threshold ───────────────
        bps = stats.bytes_per_second / 1024  # convert to KB/s
        if bps > self.bw_threshold_kbps:
            new_alerts.append(Alert(
                timestamp=now, level="WARNING",
                category="HIGH BANDWIDTH",
                description=f"{bps:.1f} KB/s exceeds threshold of {self.bw_threshold_kbps} KB/s",
            ))

        # ── Packet rate threshold ─────────────
        elapsed = now - self._last_check_time
        if elapsed > 0:
            rate = (stats.total_packets - self._last_packet_count) / elapsed
            if rate > self.packet_rate_threshold:
                new_alerts.append(Alert(
                    timestamp=now, level="WARNING",
                    category="HIGH PACKET RATE",
                    description=f"{rate:.0f} pkt/s exceeds threshold of {self.packet_rate_threshold} pkt/s",
                ))
        self._last_packet_count = stats.total_packets
        self._last_check_time   = now

        # ── Port scan detection ───────────────
        for ip, count in stats.port_scan_candidates(self.port_scan_threshold):
            new_alerts.append(Alert(
                timestamp=now, level="CRITICAL",
                category="PORT SCAN DETECTED",
                description=f"{ip} probed {count} unique ports",
                src_ip=ip,
            ))

        self.alerts.extend(new_alerts)
        return new_alerts



def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


_WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 3306: "MySQL", 3389: "RDP", 5432: "Postgres",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

def _port_label(port: int) -> str:
    name = _WELL_KNOWN_PORTS.get(port, "")
    return f"{port} ({name})" if name else str(port)


def print_dashboard(stats: TrafficStats, alerts: list[Alert]) -> None:
    """Clear the terminal and redraw a live dashboard."""
    print("\033[2J\033[H", end="")  # ANSI: clear screen + cursor to top

    print("━" * 60)
    print("  🔍  NET-MONITOR  —  live traffic dashboard")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("━" * 60)

    snap = stats.snapshot()

    # Overview
    print(f"\n  Total packets : {snap['total_packets']:,}")
    print(f"  Total bytes   : {_fmt_bytes(snap['total_bytes'])}")
    print(f"  Throughput    : {_fmt_bytes(int(snap['bytes_per_second']))}/s")

    # Protocol breakdown
    print("\n  ── Protocol breakdown ──────────────────")
    for proto, count in sorted(snap["protocols"].items(), key=lambda kv: -kv[1]):
        bar = "█" * min(count // max(snap["total_packets"] // 20, 1), 20)
        print(f"  {proto:<10} {count:>6}  {bar}")

    # Top talkers
    print("\n  ── Top talkers (by packets) ────────────")
    for ip, pkts, bts in snap["top_talkers"]:
        print(f"  {ip:<18}  {pkts:>6} pkt   {_fmt_bytes(bts)}")

    # Top destination ports
    print("\n  ── Top destination ports ───────────────")
    for port, count in snap["top_ports"]:
        print(f"  {_port_label(port):<22}  {count:>6} hits")

    # Recent alerts
    print("\n  ── Alerts ──────────────────────────────")
    if not alerts:
        print("  (none)")
    else:
        for alert in alerts[-6:]:   # show last 6
            print(f"  {alert}")

    print("\n  [Ctrl+C to stop]\n")


class NetworkMonitor:
    """
    Ties together PacketSniffer, TrafficStats, and AlertEngine.
    Prints a refreshing dashboard to the terminal.
    """

    def __init__(
        self,
        interface:        Optional[str]  = None,
        bpf_filter:       str            = "",
        refresh_interval: float          = 2.0,
        alert_threshold:  int            = 200,
        log_file:         Optional[str]  = None,
    ):
        self.refresh_interval = refresh_interval
        self.log_file         = log_file
        self.stats            = TrafficStats()
        self.alert_engine     = AlertEngine(packet_rate_threshold=alert_threshold)
        self.all_alerts:      list[Alert] = []

        self.sniffer = PacketSniffer(
            interface=interface,
            bpf_filter=bpf_filter,
            callback=self._on_packet,
        )

    def _on_packet(self, pkt: CapturedPacket) -> None:
        self.stats.record(pkt)

    def _refresh_loop(self) -> None:
        """Background thread: refresh dashboard and run alert checks."""
        while self._running:
            new_alerts = self.alert_engine.check(self.stats)
            self.all_alerts.extend(new_alerts)
            print_dashboard(self.stats, self.all_alerts)
            if self.log_file:
                self._write_log()
            time.sleep(self.refresh_interval)

    def _write_log(self) -> None:
        """Append a JSON snapshot to the log file."""
        snap = self.stats.snapshot()
        snap["alerts"] = [
            {"level": a.level, "category": a.category, "description": a.description}
            for a in self.all_alerts[-20:]
        ]
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(snap) + "\n")
        except OSError as e:
            print(f"[!] Log write failed: {e}")

    def start(self) -> None:
        self._running = True

        # Dashboard refresh runs in a background thread
        refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        refresh_thread.start()

        print(f"[*] Network monitor started. Ctrl+C to stop.")
        try:
            self.sniffer.start()
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            print("\n[*] Monitor stopped.")
            if self.log_file:
                print(f"[*] Log written to: {self.log_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time network monitor")
    parser.add_argument("-i", "--iface",           default=None,
                        help="Interface to sniff (default: auto)")
    parser.add_argument("-f", "--filter",          default="",
                        help="BPF filter string (e.g. 'tcp port 443')")
    parser.add_argument("-r", "--refresh",         type=float, default=2.0,
                        help="Dashboard refresh interval in seconds (default: 2)")
    parser.add_argument("-a", "--alert-threshold", type=int, default=200,
                        help="Packet-rate alert threshold (packets/sec, default: 200)")
    parser.add_argument("-l", "--log",             default=None,
                        help="Path to write JSON log snapshots (optional)")
    args = parser.parse_args()

    monitor = NetworkMonitor(
        interface=args.iface,
        bpf_filter=args.filter,
        refresh_interval=args.refresh,
        alert_threshold=args.alert_threshold,
        log_file=args.log,
    )
    monitor.start()
