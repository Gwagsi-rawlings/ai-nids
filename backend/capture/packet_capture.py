"""
AI-NIDS — Packet Capture Engine
FR1.1, FR1.3, FR1.5–FR1.9, FR1.13, FR1.14, FR1.15

Captures raw packets from a live NIC (promiscuous mode) or reads from a PCAP
file. Each packet is parsed into a structured dict and enqueued to raw_packet_q
for downstream processing by the Flow Aggregator.

Output dict schema:
    timestamp     : float       — libpcap capture time (epoch seconds)
    src_ip        : str | None  — IPv4/IPv6 source address
    dst_ip        : str | None  — IPv4/IPv6 destination address
    src_port      : int | None  — TCP/UDP source port (None for ICMP/other)
    dst_port      : int | None  — TCP/UDP destination port
    protocol      : str         — "TCP" | "UDP" | "ICMP" | "ICMPv6" | "OTHER"
    length        : int         — total packet length in bytes
    tcp_flags     : str | None  — flag string e.g. "SYN", "ACK", "SYN-ACK"
    payload_bytes : bytes       — transport-layer payload (empty if none)
    raw_packet    : Packet      — original Scapy object (for Signature Engine)
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional

from scapy.all import AsyncSniffer, rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

logger = logging.getLogger(__name__)

# ── TCP flag map ─────────────────────────────────────────────────────────────
_TCP_FLAG_NAMES = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x12: "SYN-ACK",
    0x11: "FIN-ACK",
}


def _decode_tcp_flags(flags: int) -> str:
    """Return a human-readable flag string for a TCP flags bitmask."""
    if flags in _TCP_FLAG_NAMES:
        return _TCP_FLAG_NAMES[flags]
    active = [name for mask, name in _TCP_FLAG_NAMES.items()
              if flags & mask and bin(mask).count("1") == 1]
    return "-".join(active) if active else str(flags)


# ── PacketParser ─────────────────────────────────────────────────────────────

class PacketParser:
    """
    Stateless parser. Converts a raw Scapy Packet into a structured dict.
    Returns None for packets that cannot be parsed (non-IP frames, etc.).
    """

    @staticmethod
    def parse(pkt: Packet) -> Optional[dict]:
        """
        Parse a Scapy packet into the AI-NIDS structured dict format.

        Args:
            pkt: Raw Scapy Packet object.

        Returns:
            Parsed dict, or None if the packet is not IP-based.
        """
        try:
            # ── Timestamp ────────────────────────────────────────────────
            timestamp = float(pkt.time) if hasattr(pkt, "time") else time.time()

            # ── IP layer (v4 or v6) ──────────────────────────────────────
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ip_proto = ip.proto          # numeric: 6=TCP, 17=UDP, 1=ICMP
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                ip_proto = ip.nh             # next header
            else:
                # Non-IP frame (ARP, etc.) — skip
                return None

            total_length = len(pkt)

            # ── Transport layer ──────────────────────────────────────────
            src_port = None
            dst_port = None
            tcp_flags = None
            payload_bytes = b""
            protocol = "OTHER"

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = _decode_tcp_flags(int(tcp.flags))
                payload_bytes = bytes(tcp.payload) if tcp.payload else b""
                protocol = "TCP"

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                payload_bytes = bytes(udp.payload) if udp.payload else b""
                protocol = "UDP"

            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                payload_bytes = bytes(pkt[ICMP].payload) if pkt[ICMP].payload else b""

            elif ip_proto == 58:  # ICMPv6
                protocol = "ICMPv6"

            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": total_length,
                "tcp_flags": tcp_flags,
                "payload_bytes": payload_bytes,
                "raw_packet": pkt,
            }

        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("PacketParser: failed to parse packet — %s", exc)
            return None


# ── CaptureStats ─────────────────────────────────────────────────────────────

@dataclass
class CaptureStats:
    """Live counters for FR1.16 (capture statistics dashboard)."""
    packets_captured: int = 0
    packets_dropped: int = 0    # queue full
    packets_malformed: int = 0  # parse returned None
    packets_enqueued: int = 0

    def summary(self) -> dict:
        return {
            "captured": self.packets_captured,
            "enqueued": self.packets_enqueued,
            "dropped": self.packets_dropped,
            "malformed": self.packets_malformed,
        }


# ── PacketCapture ────────────────────────────────────────────────────────────

class PacketCapture:
    """
    Packet Capture Engine — FR1.1, FR1.3, FR1.14, FR1.15.

    Supports two modes:
        1. Live capture  — start_live(interface, queue)
        2. PCAP replay   — read_pcap(filepath, queue)

    Each captured packet is parsed by PacketParser and placed on the provided
    asyncio.Queue. If the queue is full, the packet is dropped and
    stats.packets_dropped is incremented (back-pressure strategy per ADD §4.3).

    Args:
        queue_maxsize: Maximum depth of raw_packet_q. Default 10,000.
    """

    def __init__(self, queue_maxsize: int = 10_000):
        self.queue_maxsize = queue_maxsize
        self.stats = CaptureStats()
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._queue: Optional[asyncio.Queue] = None

    # ── Public API ────────────────────────────────────────────────────────

    def start_live(self, interface: str, queue: asyncio.Queue) -> None:
        """
        Begin live packet capture on `interface` in promiscuous mode.
        Runs in a background thread via Scapy AsyncSniffer.

        Args:
            interface: Network interface name, e.g. "eth0".
            queue:     asyncio.Queue to receive parsed packet dicts.
        """
        if self._running:
            raise RuntimeError("Capture already running. Call stop() first.")

        self._queue = queue
        self._running = True

        self._sniffer = AsyncSniffer(
            iface=interface,
            prn=self._process_packet,
            store=False,          # don't accumulate in memory
            promisc=True,
        )
        self._sniffer.start()
        logger.info("PacketCapture: live capture started on %s", interface)

    def read_pcap(self, filepath: str, queue: asyncio.Queue) -> int:
        """
        Read and parse all packets from a PCAP/PCAPNG file (FR1.3).
        Processes synchronously — suitable for background thread or executor.

        Args:
            filepath: Path to the .pcap or .pcapng file.
            queue:    asyncio.Queue to receive parsed packet dicts.

        Returns:
            Number of packets successfully enqueued.
        """
        self._queue = queue
        packets = rdpcap(filepath)
        logger.info("PacketCapture: loaded %d packets from %s", len(packets), filepath)

        for pkt in packets:
            self._process_packet(pkt)

        logger.info(
            "PacketCapture PCAP complete — %s",
            self.stats.summary()
        )
        return self.stats.packets_enqueued

    def stop(self) -> CaptureStats:
        """
        Stop live capture gracefully.

        Returns:
            Final CaptureStats snapshot.
        """
        self._running = False
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            logger.info("PacketCapture: sniffer stopped — %s", self.stats.summary())
        return self.stats

    def get_stats(self) -> dict:
        """Return current capture statistics (FR1.16)."""
        return self.stats.summary()

    # ── Internal ──────────────────────────────────────────────────────────

    def _process_packet(self, pkt: Packet) -> None:
        """
        Called by Scapy for every captured packet.
        Parses and attempts to enqueue; drops if queue is full.
        """
        self.stats.packets_captured += 1

        parsed = PacketParser.parse(pkt)

        if parsed is None:
            self.stats.packets_malformed += 1
            return

        # Non-blocking put — drop if queue is at capacity (back-pressure)
        try:
            self._queue.put_nowait(parsed)
            self.stats.packets_enqueued += 1
        except asyncio.QueueFull:
            self.stats.packets_dropped += 1
            logger.debug(
                "PacketCapture: queue full — dropped packet from %s",
                parsed.get("src_ip", "unknown"),
            )
