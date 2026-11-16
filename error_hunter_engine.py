"""
error_hunter_engine.py
======================
Analyzes HTTP transactions produced by HttpStreamAnalyzer and classifies them
into errors (4xx / 5xx / no-response) and warnings (3xx redirects).
"""

from __future__ import annotations

from collections import Counter
from typing import Any


class ErrorHunterEngine:
    """
    Scans a list of HTTP transactions and classifies each one by its HTTP
    status code into errors, warnings, or clean traffic.

    Attributes
    ----------
    transactions : list[dict]
        Raw transaction records from HttpStreamAnalyzer.
    errors : list[dict]
        Transactions whose status code is >= 400 or whose response is absent.
    warnings : list[dict]
        Transactions whose status code is in the 3xx redirect range.
    """

    # ------------------------------------------------------------------ #
    # Construction                                                         #
    # ------------------------------------------------------------------ #

    def __init__(self, transactions: list[dict[str, Any]]) -> None:
        """
        This function initialises the engine with a list of HTTP transactions to analyse.
        Input: transactions (list[dict]) — HTTP transaction dicts from HttpStreamAnalyzer,
               each expected to contain at minimum the keys used by scan()
        Output: None — sets up self.transactions, self.errors, and self.warnings lists
        """
        self.transactions: list[dict[str, Any]] = transactions
        self.errors: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _build_record(
        self,
        transaction: dict[str, Any],
        error_category: str,
    ) -> dict[str, Any]:
        """
        This function normalises a raw transaction dict into a standard error/warning record.
        Input: transaction (dict) — a single HTTP transaction dict from HttpStreamAnalyzer;
               error_category (str) — human-readable label such as "4xx Client Error" or "No Response"
        Output: dict — standardised record with well-known keys consumed by the dashboard
        """
        # Build the error record by extracting all relevant fields from the
        # raw transaction, filling in safe defaults for any missing keys
        return {
            "request_frame": transaction.get("request_frame"),
            "response_frame": transaction.get("response_frame"),
            "status_code": transaction.get("status_code"),
            "method": transaction.get("method", "UNKNOWN"),
            "host": transaction.get("host", ""),
            "uri": transaction.get("uri", ""),
            "src_ip": transaction.get("src_ip", ""),
            "dst_ip": transaction.get("dst_ip", ""),
            # Include ports so the diagnostic card can show IP:Port properly
            "src_port": transaction.get("src_port", ""),
            "dst_port": transaction.get("dst_port", ""),
            "error_category": error_category,
            "request_timestamp": transaction.get("request_timestamp"),
            "response_timestamp": transaction.get("response_timestamp"),
            "response_time_ms": transaction.get("response_time_ms"),
            # Preserve stream_key so the Inspect button can link to the right transaction
            "stream_key": transaction.get("stream_key", ""),
            # Preserve headers/body so the Stream Inspector can display full detail
            "request_headers": transaction.get("request_headers", {}),
            "response_headers": transaction.get("response_headers", {}),
            "request_body": transaction.get("request_body", ""),
            "response_body_preview": transaction.get("response_body_preview", ""),
        }

    @staticmethod
    def _classify_category(status_code: int | None) -> str:
        """
        This function maps an HTTP status code (or None) to a human-readable category label.
        Input: status_code (int | None) — the HTTP status code, or None when no response was captured
        Output: str — one of "5xx Server Error", "4xx Client Error", "3xx Redirect", or "No Response"
        """
        # Classify by status code range:
        # - None means the request got no response at all (timeout / RST / capture gap)
        # - 5xx: server-side failures (500 Internal Server Error, 503 Service Unavailable, etc.)
        # - 4xx: client-side errors (404 Not Found, 401 Unauthorized, etc.)
        # - 3xx: redirects (301 Moved Permanently, 302 Found, etc.)
        if status_code is None:
            return "No Response"
        if status_code >= 500:
            return "5xx Server Error"
        if status_code >= 400:
            return "4xx Client Error"
        if status_code >= 300:
            return "3xx Redirect"
        return "OK"

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def scan(self) -> None:
        """
        This function iterates over all transactions and populates the errors and warnings lists.
        Input: None — reads from self.transactions set during __init__
        Output: None — populates self.errors (4xx / 5xx / no-response) and self.warnings (3xx)
        """
        self.errors = []
        self.warnings = []

        for transaction in self.transactions:
            status_code: int | None = transaction.get("status_code")
            category = self._classify_category(status_code)

            if category in ("4xx Client Error", "5xx Server Error", "No Response"):
                self.errors.append(self._build_record(transaction, category))

            elif category == "3xx Redirect":
                self.warnings.append(self._build_record(transaction, category))

    def get_errors(self) -> list[dict[str, Any]]:
        """
        This function returns the list of error records found during the last scan() call.
        Input: None
        Output: list[dict] — possibly empty list of standardised error records (4xx / 5xx / no-response)
        """
        return self.errors

    def get_warnings(self) -> list[dict[str, Any]]:
        """
        This function returns the list of warning records (3xx redirects) found during the last scan().
        Input: None
        Output: list[dict] — possibly empty list of standardised warning records with error_category "3xx Redirect"
        """
        return self.warnings

    def has_errors(self) -> bool:
        """
        This function checks whether any HTTP errors were found during the last scan().
        Input: None
        Output: bool — True if self.errors is non-empty, False otherwise
        """
        return len(self.errors) > 0

    def get_error_summary(self) -> dict[str, Any]:
        """
        This function computes and returns a statistical summary of errors found during the last scan().
        Input: None
        Output: dict with keys: total_errors, errors_4xx, errors_5xx, no_response,
                most_common_error_code (int or None), top_error_host (str or None)
        """
        total_errors = len(self.errors)

        # Count errors by category: 4xx client errors, 5xx server errors, and no-response (timeout/reset)
        errors_4xx = sum(
            1 for e in self.errors if e["error_category"] == "4xx Client Error"
        )
        errors_5xx = sum(
            1 for e in self.errors if e["error_category"] == "5xx Server Error"
        )
        no_response = sum(
            1 for e in self.errors if e["error_category"] == "No Response"
        )

        # Most common numeric status code (excludes None / no-response entries)
        # Counter tallies each distinct code and most_common(1) returns the top-ranked one
        numeric_codes = [
            e["status_code"] for e in self.errors if e["status_code"] is not None
        ]
        most_common_error_code: int | None = None
        if numeric_codes:
            most_common_error_code = Counter(numeric_codes).most_common(1)[0][0]

        # Host with the most errors — Counter ranks hosts by frequency
        hosts = [e["host"] for e in self.errors if e.get("host")]
        top_error_host: str | None = None
        if hosts:
            top_error_host = Counter(hosts).most_common(1)[0][0]

        return {
            "total_errors": total_errors,
            "errors_4xx": errors_4xx,
            "errors_5xx": errors_5xx,
            "no_response": no_response,
            "most_common_error_code": most_common_error_code,
            "top_error_host": top_error_host,
        }

    @staticmethod
    def get_severity_color(status_code: int | None) -> str:
        """
        This function maps an HTTP status code to a hex colour representing its severity level.
        Input: status_code (int | None) — an HTTP status code, or None for missing/timed-out responses
        Output: str — hex colour string: red (#E53E3E) for 5xx, orange (#DD6B20) for 4xx,
                gray (#718096) for None/unknown
        """
        if status_code is None:
            return "#718096"   # gray – no response
        if status_code >= 500:
            return "#E53E3E"   # red – server error
        if status_code >= 400:
            return "#DD6B20"   # orange – client error
        # Callers should not normally request a colour for non-error codes,
        # but we return a neutral colour as a safe fallback.
        return "#718096"
