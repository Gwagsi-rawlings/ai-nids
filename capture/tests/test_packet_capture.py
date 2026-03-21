"""
Unit tests for PacketCapture and PacketParser.
Run with: pytest capture/tests/test_packet_capture.py -v
"""

import asyncio
import pytest
from unittest.mock import MagicMock

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from capture.packet_capture import PacketCapture, PacketParser, CaptureStats


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_tcp_pkt(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80,
                 flags="S", payload=b"GET / HTTP/1.1"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                                 flags=flags) / Raw(payload)


def make_udp_pkt(src="10.0.0.1", dst="8.8.8.8", sport=53001, dport=53):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def make_icmp_pkt(src="10.0.0.1", dst="10.0.0.2"):
    return Ether() / IP(src=src, dst=dst) / ICMP()


def make_arp_pkt():
    from scapy.layers.l2 import ARP
    return Ether() / ARP()


# ── PacketParser tests ────────────────────────────────────────────────────────

class TestPacketParser:

    def test_tcp_packet_parsed_correctly(self):
        pkt = make_tcp_pkt()
        result = PacketParser.parse(pkt)

        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "10.0.0.2"
        assert result["src_port"] == 12345
        assert result["dst_port"] == 80
        assert result["protocol"] == "TCP"
        assert result["tcp_flags"] == "SYN"
        assert result["length"] > 0
        assert isinstance(result["timestamp"], float)
        assert result["raw_packet"] is pkt

    def test_udp_packet_parsed_correctly(self):
        pkt = make_udp_pkt()
        result = PacketParser.parse(pkt)

        assert result is not None
        assert result["protocol"] == "UDP"
        assert result["src_port"] == 53001
        assert result["dst_port"] == 53
        assert result["tcp_flags"] is None

    def test_icmp_packet_parsed_correctly(self):
        pkt = make_icmp_pkt()
        result = PacketParser.parse(pkt)

        assert result is not None
        assert result["protocol"] == "ICMP"
        assert result["src_port"] is None
        assert result["dst_port"] is None

    def test_non_ip_packet_returns_none(self):
        """ARP frames should be discarded — not IP-based."""
        pkt = make_arp_pkt()
        result = PacketParser.parse(pkt)
        assert result is None

    def test_tcp_syn_ack_flags(self):
        pkt = make_tcp_pkt(flags="SA")
        result = PacketParser.parse(pkt)
        assert result["tcp_flags"] == "SYN-ACK"

    def test_payload_bytes_captured(self):
        pkt = make_tcp_pkt(payload=b"UNION SELECT")
        result = PacketParser.parse(pkt)
        assert b"UNION SELECT" in result["payload_bytes"]

    def test_empty_payload(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        result = PacketParser.parse(pkt)
        assert result is not None
        assert isinstance(result["payload_bytes"], bytes)


# ── PacketCapture tests ───────────────────────────────────────────────────────

class TestPacketCapture:

    def test_stats_initial_state(self):
        cap = PacketCapture()
        stats = cap.get_stats()
        assert stats["captured"] == 0
        assert stats["enqueued"] == 0
        assert stats["dropped"] == 0
        assert stats["malformed"] == 0

    def test_process_valid_packet_increments_counters(self):
        cap = PacketCapture()
        queue = asyncio.Queue(maxsize=100)
        cap._queue = queue

        pkt = make_tcp_pkt()
        cap._process_packet(pkt)

        assert cap.stats.packets_captured == 1
        assert cap.stats.packets_enqueued == 1
        assert cap.stats.packets_dropped == 0
        assert cap.stats.packets_malformed == 0

    def test_malformed_packet_increments_malformed_counter(self):
        cap = PacketCapture()
        queue = asyncio.Queue(maxsize=100)
        cap._queue = queue

        pkt = make_arp_pkt()  # non-IP → parse returns None
        cap._process_packet(pkt)

        assert cap.stats.packets_captured == 1
        assert cap.stats.packets_malformed == 1
        assert cap.stats.packets_enqueued == 0

    def test_full_queue_increments_drop_counter(self):
        cap = PacketCapture(queue_maxsize=1)
        queue = asyncio.Queue(maxsize=1)
        cap._queue = queue

        # Fill the queue
        cap._process_packet(make_tcp_pkt())
        # This one should be dropped
        cap._process_packet(make_tcp_pkt())

        assert cap.stats.packets_dropped == 1
        assert cap.stats.packets_enqueued == 1

    def test_start_live_raises_if_already_running(self):
        cap = PacketCapture()
        cap._running = True
        with pytest.raises(RuntimeError, match="already running"):
            cap.start_live("eth0", asyncio.Queue())

    def test_stop_returns_stats(self):
        cap = PacketCapture()
        cap._running = True
        cap._sniffer = MagicMock()
        cap._sniffer.running = False

        stats = cap.stop()
        assert isinstance(stats, CaptureStats)
        assert cap._running is False