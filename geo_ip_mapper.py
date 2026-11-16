"""
geo_ip_mapper.py
================
Resolves public IP addresses found in a captured packet list to their
geographic locations using the ip-api.com batch API, with in-memory and
on-disk caching for efficiency across dashboard sessions.
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any

import requests


class GeoIpMapper:
    """
    Maps public IP addresses extracted from raw packet info to their
    geographic locations using the `ip-api.com <http://ip-api.com>`_ free
    batch API.

    The mapper maintains an in-memory cache (:attr:`_cache`) so that IP
    addresses already looked up in the current session are never queried
    again.  The cache can also be persisted to disk (JSON) via
    :meth:`save_cache` / :meth:`load_cache` for reuse across separate
    dashboard runs.

    Parameters
    ----------
    packets_info:
        List of raw packet info dicts as returned by
        ``PacketCaptureLoader.get_raw_packets_info()``.  Each dict must
        contain at least ``src_ip`` and ``dst_ip`` string keys.

    Attributes
    ----------
    _cache : dict[str, dict]
        In-memory mapping of ``ip -> geo_info_dict`` for all IPs that have
        been successfully resolved (or attempted) during the session.
    geo_data : dict[str, dict]
        Populated after :meth:`resolve_all` is called.  Maps each
        successfully resolved public IP to its full geo-info dict.
    error_message : str
        Human-readable description of the last network error encountered
        during batch resolution, or an empty string if no error occurred.
    """

    # ip-api.com batch endpoint and the fields we request
    _BATCH_API_URL = (
        "http://ip-api.com/batch"
        "?fields=status,country,countryCode,city,lat,lon,isp,org,query"
    )
    _BATCH_SIZE = 100   # ip-api.com allows up to 100 IPs per batch request
    _RATE_LIMIT_SLEEP = 1.0   # seconds to sleep between successive batch calls

    # ------------------------------------------------------------------ #
    # Construction                                                         #
    # ------------------------------------------------------------------ #

    def __init__(self, packets_info: list[dict[str, Any]]) -> None:
        """
        This function initialises the mapper with a list of raw packet info dicts.
        Input: packets_info (list[dict]) — packet dicts from PacketCaptureLoader,
               each must contain at least src_ip and dst_ip string keys
        Output: None — sets up internal cache, geo_data store, and error_message string
        """
        self._packets_info: list[dict[str, Any]] = packets_info
        self._cache: dict[str, dict[str, Any]] = {}
        self.geo_data: dict[str, dict[str, Any]] = {}
        self.error_message: str = ""

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _is_private_ip(self, ip: str) -> bool:
        """
        This function checks whether an IP address belongs to a private, loopback, or link-local range.
        Input: ip (str) — a dotted-decimal IPv4 or colon-separated IPv6 address string
        Output: bool — True if the address is private/special and should not be sent to the geo API,
                False if it is a routable public address
        """
        try:
            # ipaddress.ip_address() parses both IPv4 and IPv6 strings and raises
            # ValueError for anything that is not a valid IP address.
            # RFC 1918 private ranges (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
            # link-local (169.254/16, fe80::/10), reserved, and unspecified addresses
            # are all excluded from geo-resolution to avoid unnecessary API calls.
            addr = ipaddress.ip_address(ip)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_unspecified
            )
        except ValueError:
            # Unparseable string – treat as private to avoid API calls
            return True

    def _extract_public_ips(
        self,
        packets_info: list[dict[str, Any]],
    ) -> dict[str, int]:
        """
        This function walks all packet dicts and collects unique public IPs with their packet counts.
        Input: packets_info (list[dict]) — the same list passed to the constructor,
               each dict expected to have src_ip and dst_ip keys
        Output: dict[str, int] — mapping of public_ip -> total packet appearances
        """
        ip_counts: dict[str, int] = {}

        for packet in packets_info:
            for key in ("src_ip", "dst_ip"):
                ip: str | None = packet.get(key)
                if not ip:
                    continue
                if self._is_private_ip(ip):
                    continue
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        return ip_counts

    def _query_batch(self, ip_batch: list[str]) -> list[dict[str, Any]]:
        """
        POST a batch of up to :data:`_BATCH_SIZE` IP addresses to the
        ip-api.com batch endpoint and return the parsed JSON response.

        Parameters
        ----------
        ip_batch:
            List of public IP address strings to resolve.

        Returns
        -------
        list[dict]
            Parsed JSON list from the API, or an empty list on error.

        Raises
        ------
        Does **not** raise – connection / HTTP errors are caught internally
        and recorded in :attr:`error_message`.
        """
        payload = [{"query": ip} for ip in ip_batch]
        try:
            response = requests.post(
                self._BATCH_API_URL,
                json=payload,
                timeout=15,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError as exc:
            self.error_message = f"Connection error while contacting ip-api.com: {exc}"
        except requests.exceptions.Timeout:
            self.error_message = "Request to ip-api.com timed out."
        except requests.exceptions.HTTPError as exc:
            self.error_message = f"HTTP error from ip-api.com: {exc}"
        except (ValueError, json.JSONDecodeError) as exc:
            self.error_message = f"Failed to parse ip-api.com response: {exc}"
        return []

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def resolve_all(self) -> None:
        """
        Resolve all public IP addresses found in :attr:`_packets_info`.

        Steps
        -----
        1. Extract public IPs and their packet counts via
           :meth:`_extract_public_ips`.
        2. Skip any IP already present in :attr:`_cache`.
        3. Send the remaining IPs to ip-api.com in batches of
           :data:`_BATCH_SIZE`, sleeping :data:`_RATE_LIMIT_SLEEP` seconds
           between requests to respect the free-tier rate limit.
        4. Merge results into :attr:`_cache` and populate
           :attr:`geo_data` for all successfully resolved IPs.
        """
        self.error_message = ""
        ip_packet_counts: dict[str, int] = self._extract_public_ips(
            self._packets_info
        )

        # Determine which IPs still need to be fetched
        uncached_ips: list[str] = [
            ip for ip in ip_packet_counts if ip not in self._cache
        ]

        # Query the API in batches
        for batch_start in range(0, len(uncached_ips), self._BATCH_SIZE):
            batch = uncached_ips[batch_start : batch_start + self._BATCH_SIZE]
            results = self._query_batch(batch)

            for result in results:
                queried_ip: str = result.get("query", "")
                if not queried_ip:
                    continue
                self._cache[queried_ip] = result

            # Respect the rate limit between batch calls (not after the last)
            is_last_batch = (batch_start + self._BATCH_SIZE) >= len(uncached_ips)
            if not is_last_batch:
                time.sleep(self._RATE_LIMIT_SLEEP)

        # Build geo_data from the cache for all public IPs found in this capture
        self.geo_data = {}
        for ip, packet_count in ip_packet_counts.items():
            cached = self._cache.get(ip)
            if cached is None:
                continue
            if cached.get("status") != "success":
                continue

            self.geo_data[ip] = {
                "ip": ip,
                "country": cached.get("country", ""),
                "country_code": cached.get("countryCode", ""),
                "city": cached.get("city", ""),
                "lat": cached.get("lat"),
                "lon": cached.get("lon"),
                "isp": cached.get("isp", ""),
                "org": cached.get("org", ""),
                "packet_count": packet_count,
            }

    def get_map_data(self) -> list[dict[str, Any]]:
        """
        Description: Returns all successfully geo-resolved public IPs as a flat list,
                     ready to be loaded into a Plotly scatter-geo map widget.
        Input: None — reads from self.geo_data populated by resolve_all()
        Output: list[dict] — each dict has keys: ip, country, country_code, city, lat, lon, isp, org, packet_count
        """
        return list(self.geo_data.values())

    def get_country_summary(self) -> list[dict[str, Any]]:
        """
        Description: Groups all resolved IPs by country and returns aggregated statistics.
                     Useful for showing a country-level breakdown table in the dashboard.
        Input: None — reads from self.geo_data populated by resolve_all()
        Output: list[dict] — one dict per country sorted by total_packets descending;
                each dict has: country, country_code, total_packets, ip_count, cities (list)
        """
        aggregation: dict[str, dict[str, Any]] = {}

        for geo_info in self.geo_data.values():
            country_code: str = geo_info["country_code"] or "UNKNOWN"

            if country_code not in aggregation:
                aggregation[country_code] = {
                    "country": geo_info["country"],
                    "country_code": country_code,
                    "total_packets": 0,
                    "ip_count": 0,
                    "cities": set(),
                }

            entry = aggregation[country_code]
            entry["total_packets"] += geo_info["packet_count"]
            entry["ip_count"] += 1
            if geo_info["city"]:
                entry["cities"].add(geo_info["city"])

        # Convert sets to sorted lists and sort by total_packets descending
        summary: list[dict[str, Any]] = []
        for entry in aggregation.values():
            summary.append(
                {
                    "country": entry["country"],
                    "country_code": entry["country_code"],
                    "total_packets": entry["total_packets"],
                    "ip_count": entry["ip_count"],
                    "cities": sorted(entry["cities"]),
                }
            )

        summary.sort(key=lambda x: x["total_packets"], reverse=True)
        return summary

    def get_resolved_count(self) -> int:
        """
        Description: Returns how many public IP addresses were successfully resolved to geographic data.
        Input: None
        Output: int — number of entries in self.geo_data
        """
        return len(self.geo_data)

    # ------------------------------------------------------------------ #
    # Cache persistence                                                    #
    # ------------------------------------------------------------------ #

    def save_cache(self, path: str) -> None:
        """
        Persist the in-memory cache to a JSON file so that previously
        resolved IP addresses do not need to be re-queried in future
        dashboard sessions.

        Parameters
        ----------
        path:
            Absolute or relative file-system path where the JSON file will
            be written.  Parent directories are created automatically.
        """
        cache_path = Path(path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w", encoding="utf-8") as file_handle:
            json.dump(self._cache, file_handle, indent=2, ensure_ascii=False)

    def load_cache(self, path: str) -> None:
        """
        Load a previously saved cache from a JSON file and merge it into
        :attr:`_cache`.

        Existing in-memory entries are **not** overwritten — the on-disk
        cache is used only to fill gaps, so that any fresher in-memory
        results are preserved.

        Parameters
        ----------
        path:
            Path to the JSON cache file created by :meth:`save_cache`.
            If the file does not exist the method returns silently.
        """
        cache_path = Path(path)
        if not cache_path.exists():
            return

        try:
            with cache_path.open("r", encoding="utf-8") as file_handle:
                on_disk_cache: dict[str, dict[str, Any]] = json.load(file_handle)

            # Merge: in-memory entries take precedence
            for ip, geo_info in on_disk_cache.items():
                if ip not in self._cache:
                    self._cache[ip] = geo_info

        except (json.JSONDecodeError, OSError) as exc:
            self.error_message = f"Failed to load geo-IP cache from '{path}': {exc}"
