"""
http_stream_analyzer.py
------------------------
Extracts and correlates HTTP/1.x requests and responses from raw scapy
packet objects captured in a PCAP file.

Relies on scapy's ``Raw`` layer to access TCP payload bytes; HTTP parsing
is done entirely with Python's standard library so no extra dependencies
are required beyond scapy itself.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

try:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False
    logger.warning("scapy is not installed; HttpStreamAnalyzer requires scapy.")

# HTTP method prefixes we recognise as request starters
_HTTP_REQUEST_METHODS: tuple[bytes, ...] = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

_HTTP_RESPONSE_PREFIX: bytes = b"HTTP/"


def _normalise_stream_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> str:
    """
    This function produces a stable, direction-independent key for a TCP stream.
    Input: src_ip (str), src_port (int), dst_ip (str), dst_port (int) — the four
           fields that identify a TCP connection endpoint pair.
    Output: str — canonical key in the form "<low_ip>:<low_port>-<high_ip>:<high_port>".
    """
    # Sort the two endpoints so that the key is the same regardless of which side
    # sent the packet — this lets us group A→B and B→A packets under one stream.
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    low, high = (
        (endpoint_a, endpoint_b)
        if (src_ip, src_port) <= (dst_ip, dst_port)
        else (endpoint_b, endpoint_a)
    )
    return f"{low[0]}:{low[1]}-{high[0]}:{high[1]}"


def _parse_http_message(raw_bytes: bytes) -> dict[str, Any]:
    """
    This function parses a raw HTTP/1.x request or response from a bytes payload.
    Input: raw_bytes (bytes) — raw TCP payload starting with an HTTP method verb or "HTTP/".
    Output: dict containing keys: is_request, is_response, first_line, headers, body_bytes,
            body, method, uri, http_version, status_code, status_message.
    """
    result: dict[str, Any] = {
        "is_request": False,
        "is_response": False,
        "first_line": "",
        "headers": {},
        "body_bytes": b"",
        "body": "",
        "method": "",
        "uri": "",
        "http_version": "",
        "status_code": None,
        "status_message": "",
    }

    # Split headers block from body on the first blank line (\r\n\r\n or \n\n)
    if b"\r\n\r\n" in raw_bytes:
        header_block, _, body_bytes = raw_bytes.partition(b"\r\n\r\n")
        line_sep = b"\r\n"
    elif b"\n\n" in raw_bytes:
        header_block, _, body_bytes = raw_bytes.partition(b"\n\n")
        line_sep = b"\n"
    else:
        # No body separator found – treat entire payload as headers
        header_block = raw_bytes
        body_bytes = b""
        line_sep = b"\r\n"

    result["body_bytes"] = body_bytes
    try:
        result["body"] = body_bytes.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        result["body"] = repr(body_bytes)

    lines = header_block.split(line_sep)
    if not lines:
        return result

    try:
        first_line = lines[0].decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return result

    result["first_line"] = first_line

    # Determine whether this is a request or response by checking the start of the first line.
    # HTTP responses always begin with "HTTP/" while requests start with a verb like GET/POST.
    if first_line.upper().startswith("HTTP/"):
        result["is_response"] = True
        parts = first_line.split(" ", 2)
        result["http_version"] = parts[0] if len(parts) > 0 else ""
        if len(parts) > 1:
            try:
                result["status_code"] = int(parts[1])
            except ValueError:
                result["status_code"] = None
        result["status_message"] = parts[2] if len(parts) > 2 else ""
    else:
        result["is_request"] = True
        parts = first_line.split(" ", 2)
        result["method"] = parts[0] if len(parts) > 0 else ""
        result["uri"] = parts[1] if len(parts) > 1 else ""
        result["http_version"] = parts[2] if len(parts) > 2 else ""

    # Parse remaining header lines into a dict
    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        try:
            line_str = raw_line.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            continue
        if not line_str:
            continue
        if ":" in line_str:
            key, _, value = line_str.partition(":")
            headers[key.strip()] = value.strip()

    result["headers"] = headers
    return result


class HttpStreamAnalyzer:
    """
    Extracts HTTP/1.x transactions from a list of scapy packet objects.

    Each TCP stream is identified by a normalised 4-tuple key so that
    packets flowing in both directions are grouped together.  Single-packet
    HTTP messages are matched without reassembly (``reassembled`` is always
    ``False`` in this implementation).

    Parameters
    ----------
    packets :
        List of scapy packet objects, typically from
        ``PacketCaptureLoader.get_packets()``.
    """

    def __init__(self, packets: list[Any]) -> None:
        """
        This function initialises the analyzer with a list of raw scapy packet objects.
        Input: packets (list[Any]) — scapy packet objects, typically from PacketCaptureLoader.get_packets().
        Output: None — sets up internal storage dicts for requests, responses, and stream payloads.
        """
        self._packets: list[Any] = packets

        # Internal storage keyed by normalised stream key string
        # Each value is a list of raw message dicts in arrival order
        self._requests: dict[str, list[dict[str, Any]]] = {}
        self._responses: dict[str, list[dict[str, Any]]] = {}

        # Full raw payloads per stream, per direction
        # direction "client" and "server"
        self._stream_client_payload: dict[str, list[bytes]] = {}
        self._stream_server_payload: dict[str, list[bytes]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> None:
        """
        This function iterates all packets and extracts HTTP requests and responses into internal storage.
        Input: None — operates on self._packets set during __init__.
        Output: None — populates self._requests, self._responses, self._stream_client_payload,
                and self._stream_server_payload for later retrieval.
        """
        if not SCAPY_AVAILABLE:
            logger.error("scapy is unavailable; cannot analyze HTTP streams.")
            return

        for frame_num, packet in enumerate(self._packets, start=1):
            if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
                continue

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            raw_payload: bytes = bytes(packet[Raw].load)

            src_ip: str = ip_layer.src
            dst_ip: str = ip_layer.dst
            src_port: int = int(tcp_layer.sport)
            dst_port: int = int(tcp_layer.dport)
            pkt_time: float = float(packet.time)

            stream_key = _normalise_stream_key(src_ip, src_port, dst_ip, dst_port)

            # Classify as request or response by checking byte-level prefixes of the payload.
            # We use raw bytes here (not decoded strings) to avoid encoding errors on binary
            # or partial payloads, and to match the exact ASCII verb bytes that begin HTTP messages.
            if any(raw_payload.startswith(method) for method in _HTTP_REQUEST_METHODS):
                parsed = _parse_http_message(raw_payload)
                entry = {
                    "frame_num": frame_num,
                    "timestamp": pkt_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "stream_key": stream_key,
                    "parsed": parsed,
                    "raw": raw_payload,
                }
                self._requests.setdefault(stream_key, []).append(entry)
                self._stream_client_payload.setdefault(stream_key, []).append(raw_payload)

            elif raw_payload.startswith(_HTTP_RESPONSE_PREFIX):
                parsed = _parse_http_message(raw_payload)
                entry = {
                    "frame_num": frame_num,
                    "timestamp": pkt_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "stream_key": stream_key,
                    "parsed": parsed,
                    "raw": raw_payload,
                }
                self._responses.setdefault(stream_key, []).append(entry)
                self._stream_server_payload.setdefault(stream_key, []).append(raw_payload)

    def get_transactions(self) -> list[dict[str, Any]]:
        """
        This function matches HTTP requests to their corresponding responses and returns paired transaction records.
        Input: None — uses internally stored request/response data populated by analyze().
        Output: list[dict] — one dict per request; each contains request_frame, response_frame, method,
                host, uri, src_ip, dst_ip, src_port, dst_port, status_code, response_time_ms,
                request_headers, response_headers, request_body, response_body_preview,
                stream_key, request_timestamp, response_timestamp, reassembled.
        """
        transactions: list[dict[str, Any]] = []

        all_stream_keys = set(self._requests.keys()) | set(self._responses.keys())

        for stream_key in sorted(all_stream_keys):
            requests_on_stream = self._requests.get(stream_key, [])
            responses_on_stream = self._responses.get(stream_key, [])

            # Match requests to responses by positional index within the same stream.
            # HTTP/1.1 is pipelined in order, so the Nth request is answered by the Nth response.
            for idx, req_entry in enumerate(requests_on_stream):
                req_parsed = req_entry["parsed"]
                req_headers: dict[str, str] = req_parsed.get("headers", {})

                # Try to find the matching response (same stream, same position)
                resp_entry: dict[str, Any] | None = (
                    responses_on_stream[idx] if idx < len(responses_on_stream) else None
                )

                resp_parsed = resp_entry["parsed"] if resp_entry else {}
                resp_headers: dict[str, str] = resp_parsed.get("headers", {}) if resp_parsed else {}

                response_time_ms: float | None = None
                if resp_entry is not None:
                    # Subtract the request timestamp from the response timestamp (both are UNIX epoch
                    # floats from scapy) and convert the difference from seconds to milliseconds.
                    delta_s = resp_entry["timestamp"] - req_entry["timestamp"]
                    response_time_ms = round(delta_s * 1000.0, 3)

                # Build response body preview — full body, no truncation
                resp_body_raw: str = resp_parsed.get("body", "") if resp_parsed else ""
                response_body_preview: str = resp_body_raw  # Full body — no truncation

                transaction: dict[str, Any] = {
                    "request_frame": req_entry["frame_num"],
                    "response_frame": resp_entry["frame_num"] if resp_entry else None,
                    "method": req_parsed.get("method", ""),
                    "host": req_headers.get("Host", req_headers.get("host", "")),
                    "uri": req_parsed.get("uri", ""),
                    "src_ip": req_entry["src_ip"],
                    "dst_ip": req_entry["dst_ip"],
                    "src_port": req_entry["src_port"],
                    "dst_port": req_entry["dst_port"],
                    "status_code": resp_parsed.get("status_code") if resp_parsed else None,
                    "response_time_ms": response_time_ms,
                    "request_headers": req_headers,
                    "response_headers": resp_headers,
                    "request_body": req_parsed.get("body", ""),
                    "response_body_preview": response_body_preview,
                    "stream_key": stream_key,
                    "request_timestamp": req_entry["timestamp"],
                    "response_timestamp": resp_entry["timestamp"] if resp_entry else None,
                    "reassembled": False,
                }
                transactions.append(transaction)

        return transactions

    def get_stream_detail(self, stream_key: str) -> dict[str, Any]:
        """
        This function returns the concatenated raw TCP payloads for both directions of a given stream.
        Input: stream_key (str) — the canonical stream identifier from a transaction dict.
        Output: dict with keys: client_payload (str), server_payload (str), reassembled (bool).
        """
        client_chunks = self._stream_client_payload.get(stream_key, [])
        server_chunks = self._stream_server_payload.get(stream_key, [])

        client_text = b"\n---\n".join(client_chunks).decode("utf-8", errors="replace")
        server_text = b"\n---\n".join(server_chunks).decode("utf-8", errors="replace")

        return {
            "client_payload": client_text,
            "server_payload": server_text,
            "reassembled": False,
        }

    def get_post_params(self, transaction: dict[str, Any]) -> dict[str, list[str]]:
        """
        This function parses URL-encoded POST body parameters from a transaction dict.
        Input: transaction (dict[str, Any]) — a transaction record as returned by get_transactions().
        Output: dict[str, list[str]] — parameter name → list of values via urllib.parse.parse_qs;
                empty dict if the content type is not application/x-www-form-urlencoded or the body is empty.
        """
        content_type: str = ""
        req_headers: dict[str, str] = transaction.get("request_headers", {})
        # Header names are case-insensitive; check common casings
        for key in req_headers:
            if key.lower() == "content-type":
                content_type = req_headers[key]
                break

        if "application/x-www-form-urlencoded" not in content_type.lower():
            return {}

        body: str = transaction.get("request_body", "")
        if not body.strip():
            return {}

        try:
            return urllib.parse.parse_qs(body, keep_blank_values=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse POST params: %s", exc)
            return {}
