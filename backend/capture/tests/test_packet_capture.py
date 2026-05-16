"""
AI-NIDS — Unit Tests: Packet Capture Engine
tests/test_packet_capture.py

Tests the PacketParser (stateless parser) and PacketCapture (capture engine).
All tests use synthetic Scapy packets — no live network interface required.

FR Traceability:
    FR1.1  — Capture from network interface in promiscuous mode
    FR1.3  — Accept PCAP file uploads for offline analysis
    FR1.5  — Parse TCP packets and extract header fields
    FR1.6  — Parse UDP packets and extract header fields
    FR1.7  — Parse ICMP packets and extract header fields
    FR1.13 — Timestamp each packet with millisecond precision
    FR1.16 — Display capture statistics

March 24, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import asyncio
import tempfile
import os

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.all import wrpcap

from capture.packet_capture import PacketParser, PacketCapture, CaptureStats


# ---------------------------------------------------------------------------
# Synthetic packet builders
# ---------------------------------------------------------------------------

def make_tcp_packet(
    src="192.168.1.10",
    dst="10.0.0.1",
    sport=54321,
    dport=80,
    flags="S",
    payload=b"",
):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / payload
    return pkt


def make_udp_packet(
    src="192.168.1.10",
    dst="8.8.8.8",
    sport=12345,
    dport=53,
    payload=b"\x00\x01",
):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload


def make_icmp_packet(src="192.168.1.10", dst="10.0.0.1"):
    return Ether() / IP(src=src, dst=dst) / ICMP()


def make_arp_packet():
    from scapy.layers.l2 import ARP
    return Ether() / ARP()


# ===========================================================================
# PacketParser tests
# ===========================================================================

class TestPacketParserTCP:
    """FR1.5 — TCP packet parsing."""

    def test_returns_dict_for_tcp(self):
        result = PacketParser.parse(make_tcp_packet())
        assert result is not None
        assert isinstance(result, dict)

    def test_src_ip_extracted(self):
        result = PacketParser.parse(make_tcp_packet(src="192.168.1.10"))
        assert result["src_ip"] == "192.168.1.10"

    def test_dst_ip_extracted(self):
        result = PacketParser.parse(make_tcp_packet(dst="10.0.0.1"))
        assert result["dst_ip"] == "10.0.0.1"

    def test_src_port_extracted(self):
        result = PacketParser.parse(make_tcp_packet(sport=54321))
        assert result["src_port"] == 54321

    def test_dst_port_extracted(self):
        result = PacketParser.parse(make_tcp_packet(dport=80))
        assert result["dst_port"] == 80

    def test_protocol_is_tcp(self):
        result = PacketParser.parse(make_tcp_packet())
        assert result["protocol"] == "TCP"

    def test_syn_flag_decoded(self):
        result = PacketParser.parse(make_tcp_packet(flags="S"))
        assert result["tcp_flags"] == "SYN"

    def test_syn_ack_flag_decoded(self):
        result = PacketParser.parse(make_tcp_packet(flags="SA"))
        assert result["tcp_flags"] == "SYN-ACK"

    def test_fin_ack_flag_decoded(self):
        result = PacketParser.parse(make_tcp_packet(flags="FA"))
        assert result["tcp_flags"] == "FIN-ACK"

    def test_payload_bytes_extracted(self):
        result = PacketParser.parse(make_tcp_packet(payload=b"GET / HTTP/1.1"))
        assert b"GET" in result["payload_bytes"]

    def test_timestamp_is_float(self):
        result = PacketParser.parse(make_tcp_packet())
        assert isinstance(result["timestamp"], float)

    def test_length_is_positive_int(self):
        result = PacketParser.parse(make_tcp_packet())
        assert isinstance(result["length"], int)
        assert result["length"] > 0

    def test_raw_packet_preserved(self):
        pkt = make_tcp_packet()
        result = PacketParser.parse(pkt)
        assert result["raw_packet"] is pkt


class TestPacketParserUDP:
    """FR1.6 — UDP packet parsing."""

    def test_returns_dict_for_udp(self):
        result = PacketParser.parse(make_udp_packet())
        assert result is not None

    def test_protocol_is_udp(self):
        result = PacketParser.parse(make_udp_packet())
        assert result["protocol"] == "UDP"

    def test_udp_ports_extracted(self):
        result = PacketParser.parse(make_udp_packet(sport=12345, dport=53))
        assert result["src_port"] == 12345
        assert result["dst_port"] == 53

    def test_udp_tcp_flags_is_none(self):
        result = PacketParser.parse(make_udp_packet())
        assert result["tcp_flags"] is None


class TestPacketParserICMP:
    """FR1.7 — ICMP packet parsing."""

    def test_returns_dict_for_icmp(self):
        result = PacketParser.parse(make_icmp_packet())
        assert result is not None

    def test_protocol_is_icmp(self):
        result = PacketParser.parse(make_icmp_packet())
        assert result["protocol"] == "ICMP"

    def test_icmp_has_no_ports(self):
        result = PacketParser.parse(make_icmp_packet())
        assert result["src_port"] is None
        assert result["dst_port"] is None


class TestPacketParserNonIP:
    """Non-IP frames should be rejected gracefully."""

    def test_arp_packet_returns_none(self):
        result = PacketParser.parse(make_arp_packet())
        assert result is None

    def test_empty_ethernet_returns_none(self):
        result = PacketParser.parse(Ether())
        assert result is None


class TestPacketParserOutputSchema:
    """Every parsed packet must contain the required schema keys."""

    REQUIRED_KEYS = {
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "length", "tcp_flags", "payload_bytes", "raw_packet",
    }

    def test_tcp_schema_complete(self):
        result = PacketParser.parse(make_tcp_packet())
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_udp_schema_complete(self):
        result = PacketParser.parse(make_udp_packet())
        assert self.REQUIRED_KEYS.issubset(result.keys())

    def test_icmp_schema_complete(self):
        result = PacketParser.parse(make_icmp_packet())
        assert self.REQUIRED_KEYS.issubset(result.keys())


# ===========================================================================
# CaptureStats tests
# ===========================================================================

class TestCaptureStats:
    """FR1.16 — Capture statistics tracking."""

    def test_default_values_are_zero(self):
        stats = CaptureStats()
        assert stats.packets_captured == 0
        assert stats.packets_dropped == 0
        assert stats.packets_malformed == 0
        assert stats.packets_enqueued == 0

    def test_summary_returns_dict(self):
        stats = CaptureStats()
        summary = stats.summary()
        assert isinstance(summary, dict)
        assert "captured" in summary
        assert "enqueued" in summary
        assert "dropped" in summary
        assert "malformed" in summary

    def test_summary_values_match_attributes(self):
        stats = CaptureStats()
        stats.packets_captured = 100
        stats.packets_enqueued = 95
        stats.packets_dropped = 3
        stats.packets_malformed = 2
        summary = stats.summary()
        assert summary["captured"] == 100
        assert summary["enqueued"] == 95
        assert summary["dropped"] == 3
        assert summary["malformed"] == 2


# ===========================================================================
# PacketCapture PCAP replay tests
# ===========================================================================

class TestPacketCapturePcap:
    """FR1.3 — PCAP file replay through the capture engine."""

    def _write_pcap(self, packets, path):
        wrpcap(str(path), packets)

    def test_read_pcap_enqueues_tcp_packets(self, tmp_path):
        pcap_path = tmp_path / "test.pcap"
        pkts = [make_tcp_packet(), make_tcp_packet(sport=11111, dport=443)]
        self._write_pcap(pkts, pcap_path)

        queue = asyncio.Queue(maxsize=100)
        capture = PacketCapture()
        enqueued = capture.read_pcap(str(pcap_path), queue)

        assert enqueued == 2
        assert queue.qsize() == 2

    def test_read_pcap_skips_arp(self, tmp_path):
        """ARP packets must be counted as malformed, not enqueued."""
        pcap_path = tmp_path / "mixed.pcap"
        pkts = [make_tcp_packet(), make_arp_packet(), make_udp_packet()]
        self._write_pcap(pkts, pcap_path)

        queue = asyncio.Queue(maxsize=100)
        capture = PacketCapture()
        enqueued = capture.read_pcap(str(pcap_path), queue)

        # TCP + UDP enqueued, ARP skipped
        assert enqueued == 2
        assert capture.stats.packets_malformed == 1

    def test_read_pcap_queue_full_drops_packets(self, tmp_path):
        """When queue is full, excess packets must be dropped — not crash."""
        pcap_path = tmp_path / "overflow.pcap"
        # 5 packets, queue size 2
        pkts = [make_tcp_packet(sport=i) for i in range(10000, 10005)]
        self._write_pcap(pkts, pcap_path)

        queue = asyncio.Queue(maxsize=2)
        capture = PacketCapture()
        capture.read_pcap(str(pcap_path), queue)

        assert capture.stats.packets_captured == 5
        assert capture.stats.packets_enqueued == 2
        assert capture.stats.packets_dropped == 3

    def test_read_pcap_stats_captured_count(self, tmp_path):
        pcap_path = tmp_path / "stats.pcap"
        pkts = [make_icmp_packet(), make_icmp_packet(), make_icmp_packet()]
        self._write_pcap(pkts, pcap_path)

        queue = asyncio.Queue(maxsize=100)
        capture = PacketCapture()
        capture.read_pcap(str(pcap_path), queue)

        assert capture.stats.packets_captured == 3

    def test_get_stats_returns_dict(self, tmp_path):
        pcap_path = tmp_path / "getstats.pcap"
        self._write_pcap([make_tcp_packet()], pcap_path)

        queue = asyncio.Queue(maxsize=100)
        capture = PacketCapture()
        capture.read_pcap(str(pcap_path), queue)

        stats = capture.get_stats()
        assert isinstance(stats, dict)

    def test_enqueued_packets_have_correct_schema(self, tmp_path):
        """Every packet dict in the queue must have all required keys."""
        pcap_path = tmp_path / "schema.pcap"
        self._write_pcap([make_tcp_packet(), make_udp_packet()], pcap_path)

        queue = asyncio.Queue(maxsize=100)
        capture = PacketCapture()
        capture.read_pcap(str(pcap_path), queue)

        required = {
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "length", "tcp_flags", "payload_bytes", "raw_packet",
        }
        while not queue.empty():
            pkt_dict = queue.get_nowait()
            assert required.issubset(pkt_dict.keys())


class TestPacketCaptureLifecycle:
    """stop() and state management tests."""

    def test_stop_returns_capture_stats(self):
        capture = PacketCapture()
        stats = capture.stop()
        assert isinstance(stats, CaptureStats)

    def test_double_start_raises(self):
        """Starting capture twice must raise RuntimeError."""
        import unittest.mock as mock
        capture = PacketCapture()
        capture._running = True  # simulate already-running state
        queue = asyncio.Queue()
        with pytest.raises(RuntimeError):
            capture.start_live("eth0", queue)