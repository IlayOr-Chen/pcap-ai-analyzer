"""
packet_capture_loader.py
------------------------
Loads and parses PCAP/PCAPNG files uploaded via Streamlit's st.file_uploader,
providing summary statistics and per-packet metadata for downstream analysis.
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

try:
    import scapy.all as scapy
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning(
        "scapy is not installed. Install it with: pip install scapy\n"
        "PacketCaptureLoader will not be able to parse PCAP files without scapy."
    )


class PacketCaptureLoader:
    """
    Parses PCAP/PCAPNG files from a Streamlit-uploaded file-like object.

    Attributes
    ----------
    packets : list
        Raw scapy packet objects after a successful :meth:`load` call.
    error_message : str
        Human-readable error description if any operation fails; empty otherwise.
    """

    def __init__(self) -> None:
        """
        This function initialises the loader with empty packet storage and a blank error message.
        Input: None.
        Output: None — sets self.packets (list), self.error_message (str), and self._temp_file_path.
        """
        self.packets: list[Any] = []
        self.error_message: str = ""
        self._temp_file_path: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, file_obj: Any) -> bool:
        """
        This function saves the uploaded file bytes to a temporary file and parses all packets with scapy.
        Input: file_obj (Any) — a file-like object from st.file_uploader that supports .read().
        Output: bool — True on success; False on any error (self.error_message is set with details).
        """
        if not SCAPY_AVAILABLE:
            self.error_message = (
                "scapy is not installed. Run `pip install scapy` and restart."
            )
            return False

        self.packets = []
        self.error_message = ""

        tmp_path: str | None = None
        try:
            raw_bytes: bytes = file_obj.read()

            # Use NamedTemporaryFile so scapy's rdpcap can receive a real filesystem path.
            # Streamlit's uploaded file object is an in-memory buffer without a path attribute,
            # so we must materialise it on disk first; delete=False keeps it alive after close.
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcap"
            ) as tmp_file:
                tmp_path = tmp_file.name
                tmp_file.write(raw_bytes)

            # rdpcap reads the entire PCAP/PCAPNG file from disk and returns a PacketList
            # (which we immediately convert to a plain Python list for consistent indexing).
            self.packets = list(scapy.rdpcap(tmp_path))
            return True

        except Exception as exc:  # noqa: BLE001
            self.error_message = f"Failed to load PCAP: {exc}"
            logger.exception("PacketCaptureLoader.load() encountered an error.")
            return False

        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError as cleanup_exc:
                    logger.warning("Could not delete temp file %s: %s", tmp_path, cleanup_exc)

    def get_packets(self) -> list[Any]:
        """
        This function returns the list of raw scapy packet objects loaded from the PCAP file.
        Input: None.
        Output: list[Any] — scapy packet objects; empty list if load() has not been called or failed.
        """
        return self.packets

    def get_summary(self) -> dict[str, Any]:
        """
        This function computes high-level statistics across all loaded packets.
        Input: None — operates on self.packets set by load().
        Output: dict containing total_packets, start_time, end_time, duration_seconds,
                protocols, top_src_ips, top_dst_ips, top_src_macs, top_dst_macs,
                bytes_per_second, and packets_per_second.
        """
        if not self.packets:
            return self._empty_summary()

        timestamps: list[float] = []
        # Counter objects tally occurrences of each protocol, IP, and MAC seen in the capture.
        protocol_counter: Counter[str] = Counter()
        src_ip_counter: Counter[str] = Counter()
        dst_ip_counter: Counter[str] = Counter()
        src_mac_counter: Counter[str] = Counter()
        dst_mac_counter: Counter[str] = Counter()
        bytes_by_second: defaultdict[int, int] = defaultdict(int)
        packets_by_second: defaultdict[int, int] = defaultdict(int)

        for packet in self.packets:
            # Timestamp
            pkt_time: float = float(packet.time)
            timestamps.append(pkt_time)

            # Port-based protocol detection: check the highest-level layer present
            # (DNS → HTTP port 80 → HTTPS port 443 → TCP → UDP → ICMP → ARP → Other).
            protocol_name = self._detect_protocol(packet)
            protocol_counter[protocol_name] += 1

            # IP addresses — only available for packets that carry an IP layer.
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip_counter[ip_layer.src] += 1
                dst_ip_counter[ip_layer.dst] += 1

            # MAC addresses — only available when an Ethernet frame header is present.
            if packet.haslayer(Ether):
                eth_layer = packet[Ether]
                src_mac_counter[eth_layer.src] += 1
                dst_mac_counter[eth_layer.dst] += 1

            # Byte/packet bucketing by whole second offset from start
            pkt_len = len(packet)
            bucket_second = int(pkt_time)
            bytes_by_second[bucket_second] += pkt_len
            packets_by_second[bucket_second] += 1

        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration_seconds = end_ts - start_ts

        # Build a contiguous time-series from start_bucket to end_bucket inclusive.
        # Seconds with no packets are filled with 0 so charts render without gaps.
        start_bucket = int(start_ts)
        end_bucket = int(end_ts)
        bytes_per_second: list[dict[str, Any]] = []
        packets_per_second: list[dict[str, Any]] = []
        for bucket in range(start_bucket, end_bucket + 1):
            relative_time = float(bucket - start_bucket)
            bytes_per_second.append(
                {"time": relative_time, "bytes": bytes_by_second.get(bucket, 0)}
            )
            packets_per_second.append(
                {"time": relative_time, "count": packets_by_second.get(bucket, 0)}
            )

        return {
            "total_packets": len(self.packets),
            "start_time": self._epoch_to_iso(start_ts),
            "end_time": self._epoch_to_iso(end_ts),
            "duration_seconds": round(duration_seconds, 6),
            "protocols": dict(protocol_counter),
            "top_src_ips": protocol_counter and src_ip_counter.most_common(10),
            "top_dst_ips": dst_ip_counter.most_common(10),
            "top_src_macs": src_mac_counter.most_common(5),
            "top_dst_macs": dst_mac_counter.most_common(5),
            "bytes_per_second": bytes_per_second,
            "packets_per_second": packets_per_second,
        }

    def get_raw_packets_info(self) -> list[dict[str, Any]]:
        """
        Return per-packet metadata as a flat list of dicts.

        Returns
        -------
        list[dict] where each dict contains:
            ``frame_num``, ``timestamp``, ``src_ip``, ``dst_ip``,
            ``src_mac``, ``dst_mac``, ``protocol``, ``length``,
            ``src_port``, ``dst_port``, ``info``
        """
        rows: list[dict[str, Any]] = []
        for frame_num, packet in enumerate(self.packets, start=1):
            src_ip = dst_ip = src_port = dst_port = None
            src_mac = dst_mac = None

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

            if packet.haslayer(Ether):
                eth_layer = packet[Ether]
                src_mac = eth_layer.src
                dst_mac = eth_layer.dst

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)

            protocol = self._detect_protocol(packet)
            info = self._build_info_string(packet, protocol)

            rows.append(
                {
                    "frame_num": frame_num,
                    "timestamp": float(packet.time),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "protocol": protocol,
                    "length": len(packet),
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "info": info,
                }
            )
        return rows

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_protocol(packet: Any) -> str:
        """
        Description: Determines the most specific network protocol name for a single scapy packet.
                     Checks layers in order: DNS → HTTP (port 80) → HTTPS/TLS (port 443) → TCP → UDP → ICMP → ARP.
        Input: packet (Any) — a single scapy packet object
        Output: str — protocol name such as "HTTP", "DNS", "TCP", "ARP", or "Other"
        """
        if not SCAPY_AVAILABLE:
            return "Unknown"

        if packet.haslayer(DNS):
            return "DNS"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dport = int(tcp_layer.dport)
            sport = int(tcp_layer.sport)
            if dport == 80 or sport == 80:
                return "HTTP"
            if dport == 443 or sport == 443:
                return "HTTPS/TLS"
            return "TCP"

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            dport = int(udp_layer.dport)
            sport = int(udp_layer.sport)
            # DNS over UDP (redundant but explicit)
            if dport == 53 or sport == 53:
                return "DNS"
            return "UDP"

        if packet.haslayer(ICMP):
            return "ICMP"

        if packet.haslayer(ARP):
            return "ARP"

        return "Other"

    @staticmethod
    def _build_info_string(packet: Any, protocol: str) -> str:
        """
        Description: Builds a short, human-readable info string for a packet (similar to Wireshark's Info column).
        Input: packet (Any) — a scapy packet object; protocol (str) — the detected protocol name
        Output: str — a one-line description of the packet, e.g. "TCP 80 → 54321 [PA] Seq=100 Ack=200"
        """
        try:
            if protocol == "ARP" and packet.haslayer(ARP):
                arp = packet[ARP]
                op = "request" if arp.op == 1 else "reply"
                return f"ARP {op}: {arp.psrc} → {arp.pdst}"

            if protocol in ("HTTP", "HTTPS/TLS", "TCP") and packet.haslayer(TCP):
                tcp = packet[TCP]
                flags = tcp.sprintf("%flags%")
                return f"TCP {tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"

            if protocol in ("UDP", "DNS") and packet.haslayer(UDP):
                udp = packet[UDP]
                return f"UDP {udp.sport} → {udp.dport} Len={udp.len}"

            if protocol == "ICMP" and packet.haslayer(ICMP):
                icmp = packet[ICMP]
                return f"ICMP type={icmp.type} code={icmp.code}"

            return packet.summary()
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _epoch_to_iso(epoch: float) -> str:
        """
        Description: Converts a Unix timestamp (seconds since 1970) to a human-readable
                     date/time string in UTC, formatted as YYYY-MM-DD HH:MM:SS.
        Input: epoch (float) — Unix timestamp from a scapy packet
        Output: str — formatted UTC datetime string, e.g. "2024-03-15 09:42:11"
        """
        # Format without microseconds for clean display in the dashboard metrics
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _empty_summary() -> dict[str, Any]:
        """
        Description: Returns a zeroed-out summary dictionary used as a safe fallback when no packets are loaded.
        Input: None
        Output: dict — all summary keys set to 0, empty string, or empty list
        """
        return {
            "total_packets": 0,
            "start_time": "",
            "end_time": "",
            "duration_seconds": 0.0,
            "protocols": {},
            "top_src_ips": [],
            "top_dst_ips": [],
            "top_src_macs": [],
            "top_dst_macs": [],
            "bytes_per_second": [],
            "packets_per_second": [],
        }
