"""
ai_evidence_assistant.py
------------------------
AI-powered evidence assistant for network forensics analysis.

Uses Google Gemini exclusively via its REST API (no SDK required).
API calls are made with Python's standard `requests` library to avoid
DLL/binary dependency issues on Windows.
"""

from __future__ import annotations

import json
import logging
import os
import re

import requests
from dotenv import load_dotenv

# Load .env file at module import time so os.environ picks up the keys.
load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_TEMPLATE = """
You are "NetAI Antigravity Argon 6", a Tier-1 Network Traffic Intelligence Engine. Your objective is to analyze the injected JSON PCAP context and provide highly professional network forensics.

**CRITICAL BEHAVIOR & FORMATTING RULES:**
1. CONVERSATIONAL AWARENESS (THE "HELLO" RULE): 
   - If the user sends a simple greeting (e.g., "היי", "שלום", "מה קורה"), DO NOT generate a technical report. Respond strictly with a polite, short, conversational greeting in Hebrew (e.g., "שלום! איך אוכל לעזור לך בניתוח קובץ הלכידה היום?").
   - ONLY generate the structured technical report if the user asks a specific question about the network data (e.g., latency, hosts, errors).

2. VISUAL HIERARCHY (FOR TECHNICAL QUERIES ONLY): 
   - Break down the data into clean, readable lists using bold headers and bullet points. 
   - Always include the Frame and Timestamp as dedicated bullet points.

3. HEBREW UI & RTL INTEGRITY (STRICT):
   - Respond ONLY in formal, grammatically flawless Hebrew.
   - DO NOT use markdown backticks (`). Use standard parentheses ( ) for ALL English terms, IP addresses, exact file names, variables, and protocols.
   - Always structure sentences so they end with a Hebrew word. Never place an English term or a number at the absolute end of a sentence to prevent UI punctuation glitches.

**EXAMPLE FORMAT (ONLY FOR TECHNICAL QUERIES):**
**ניתוח בקשת הרשת:**
הבקשה האיטית ביותר נרשמה אל השרת (httpbin.org).

**פרטים טכניים והוכחות:**
- **יעד (Host/URI):** (httpbin.org/post)
- **זמן השהייה (Latency):** (170.5ms)
- **מספר מסגרת (Frame):** (6874)
- **חותמת זמן (Timestamp):** (1794409196)

=== PCAP JSON CONTEXT ===
{structured_json}
=========================
"""

SYSTEM_PROMPT = SYSTEM_PROMPT_TEMPLATE.format(structured_json="{}")

MAX_CONTEXT_CHARS = 8_000

# Available Gemini model choices exposed in the UI selectbox.
GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-3.0-flash",
    "gemini-3.5-flash-lite",
]

DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"

# REST endpoint template for Gemini generateContent.
GEMINI_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{selected_model}:generateContent?key={api_key}"
)


class AiEvidenceAssistant:
    """
    Gemini-only AI assistant for network traffic forensics.

    Makes all API calls via Python's `requests` library directly against
    the Gemini REST endpoint — no google-generativeai SDK is imported.
    API key is loaded from the GEMINI_API_KEY environment variable (via .env)
    or accepted as a manual override string.
    """

    def __init__(self) -> None:
        """
        Description: Initialises the assistant with no model or key configured yet.
        Input: None
        Output: None
        """
        # Provider is set later via configure(); no client object needed (pure REST).
        self._api_key: str = ""
        self._model: str = DEFAULT_GEMINI_MODEL  # default: gemini-3.5-flash-lite

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def configure(self, model: str, api_key_override: str = "") -> None:
        """
        Description: Sets the Gemini model and loads the API key. If api_key_override
                     is provided, it is used directly (UI manual entry). Otherwise the
                     key is read from the GEMINI_API_KEY environment variable.
        Input: model (str) — one of the GEMINI_MODELS list;
               api_key_override (str) — optional key entered manually in the UI.
        Output: None; raises ValueError if no key is available.
        """
        self._model = model

        # Reload .env so any local edits to .env take effect immediately.
        load_dotenv(override=True)
        env_key = os.environ.get("GEMINI_API_KEY", "").strip()
        manual_key = api_key_override.strip() if api_key_override else ""
        key = manual_key or env_key
        if not key or key == "your_gemini_api_key_here":
            raise ValueError(
                "No Gemini API key found. Configure GEMINI_API_KEY in the local .env file "
                "in the root directory."
            )
        self._api_key = key

    def is_configured(self) -> bool:
        """
        Description: Returns True if both a model and API key are set.
        Input: None
        Output: bool
        """
        return bool(self._api_key and self._model)

    def build_context(self, summary: dict, transactions: list[dict]) -> str:
        """
        Description: Serialises capture metadata and HTTP transactions into a compact
                     JSON string capped at MAX_CONTEXT_CHARS characters for the LLM prompt.
        Input: summary (dict) — capture stats from PacketCaptureLoader;
               transactions (list[dict]) — HTTP transactions from HttpStreamAnalyzer.
        Output: str — compact JSON string safe to embed in the AI prompt.
        """
        # Only keep the fields the LLM needs; discard bulky raw payload data.
        transaction_keys = (
            "request_frame", "response_frame", "method", "host", "uri",
            "status_code", "response_time_ms", "src_ip", "src_port",
            "dst_ip", "dst_port", "stream_key", "request_timestamp", "response_timestamp",
        )

        def _filter(txn: dict) -> dict:
            return {k: txn.get(k) for k in transaction_keys}

        filtered = [_filter(t) for t in transactions]
        truncated = False

        # Iteratively drop the last transaction until the payload fits the char limit.
        while True:
            payload = {
                "capture_summary": summary,
                "http_transactions": filtered,
                "truncated": truncated,
            }
            serialised = json.dumps(payload, separators=(",", ":"), default=str)
            if len(serialised) <= MAX_CONTEXT_CHARS or not filtered:
                return serialised
            filtered = filtered[:-1]
            truncated = True

    def ask(
        self,
        question: str,
        context: str,
        chat_history: list[dict],
        system_prompt: str | None = None,
        raise_on_error: bool = False,
    ) -> dict:
        """
        Description: Sends a question to the Gemini REST API with the capture context
                     and returns a structured answer.
        Input: question (str) — analyst's natural-language question;
               context (str) — JSON context string;
               chat_history (list[dict]) — prior turns with keys role, content;
               system_prompt (str | None) — optional explicit system prompt with embedded context;
               raise_on_error (bool) — if True, re-raises exceptions for caller retry loops.
        Output: dict — {"answer": str, "evidence": list[dict]}
        """
        if not self.is_configured():
            raise RuntimeError("Assistant is not configured. Call configure() first.")

        active_system_prompt = (
            system_prompt
            if system_prompt is not None
            else SYSTEM_PROMPT_TEMPLATE.format(structured_json=context)
        )

        user_message = question

        try:
            raw_response = self._ask_gemini(
                user_message,
                chat_history,
                system_prompt=active_system_prompt,
            )
        except PermissionError as exc:
            if raise_on_error:
                raise
            err_resp = self._error_response(exc)
            err_resp["invalid_key"] = True
            return err_resp
        except Exception as exc:  # noqa: BLE001
            if raise_on_error:
                raise
            return self._error_response(exc)

        return self._parse_response(raw_response)

    def get_suggested_questions(self, summary: dict) -> list[str]:  # noqa: ARG002
        """
        Description: Returns five starter questions suited for network forensics analysis.
        Input: summary (dict) — capture summary (reserved for future dynamic generation).
        Output: list[str] — five suggested question strings.
        """
        return [
            "Which HTTP request had the longest response time, and what was its frame number?",
            "List all 4xx and 5xx HTTP errors with their frame numbers and timestamps.",
            "Are there any repeated connection attempts to the same host that might indicate scanning or brute-force?",
            "Summarise all unique hosts contacted and the number of requests made to each.",
            "Identify any suspicious or unusual HTTP methods (e.g. PUT, DELETE, CONNECT) and cite their frame numbers.",
        ]

    # ------------------------------------------------------------------
    # Private - Gemini REST helper
    # ------------------------------------------------------------------

    def _ask_gemini(
        self,
        user_message: str,
        chat_history: list[dict],
        system_prompt: str | None = None,
    ) -> str:
        """
        Description: Sends a generateContent POST request to the Gemini REST API
                     and returns the raw response text. No SDK is used — only `requests`.
        Input: user_message (str) — user question;
               chat_history (list[dict]) — prior conversation turns;
               system_prompt (str | None) — runtime system prompt string.
        Output: str — raw LLM response text.
        """
        # Build the contents list from chat history.
        # Gemini uses "model" for assistant turns (not "assistant").
        # Content must always be a plain string — never a dict.
        contents: list[dict] = []
        for m in chat_history:
            gemini_role = "user" if m["role"] == "user" else "model"
            text_content = (
                m["content"] if isinstance(m["content"], str)
                else str(m.get("content", ""))
            )
            contents.append({
                "role": gemini_role,
                "parts": [{"text": text_content}],
            })

        # Append the new user message.
        contents.append({
            "role": "user",
            "parts": [{"text": user_message}],
        })

        body = {
            "contents": contents,
            # systemInstruction keeps the system prompt separate from chat turns —
            # this is the correct Gemini REST API pattern.
            "systemInstruction": {
                "parts": [{"text": system_prompt or SYSTEM_PROMPT}]
            },
        }

        selected_model = self._model
        api_key = self._api_key
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{selected_model}:generateContent?key={api_key}"
        )
        try:
            response = requests.post(url, json=body, timeout=60)
            response.raise_for_status()
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]

        except requests.exceptions.Timeout:
            raise RuntimeError(
                "Gemini request timed out after 60 seconds. "
                "Check your connection or try again."
            )
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                "Could not connect to Gemini API. "
                "Check your internet connection."
            )
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            body_text = exc.response.text[:300] if exc.response is not None else ""
            if status in (400, 401, 403) and (
                "API_KEY_INVALID" in body_text
                or "API key not valid" in body_text
                or "invalid" in body_text.lower()
                or status in (401, 403)
            ):
                raise PermissionError(
                    "Invalid Gemini API key. API keys must not be entered via the UI; "
                    "please configure GEMINI_API_KEY locally in the .env file in the root directory."
                ) from exc
            raise RuntimeError(
                f"Gemini API returned HTTP {status}: {body_text}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(
                f"Unexpected Gemini response format — could not parse reply: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Private - response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(raw_text: str) -> dict:
        """
        Description: Splits the LLM response into a human-readable answer and a
                     structured evidence list by finding the EVIDENCE_JSON: marker.
        Input: raw_text (str) — raw response string from the LLM.
        Output: dict — {"answer": str, "evidence": list[dict]}
        """
        evidence: list[dict] = []
        answer = raw_text.strip()

        # The model is prompted to end its response with EVIDENCE_JSON: [...]
        # re.DOTALL makes . match newlines so multi-line JSON arrays are captured.
        pattern = re.compile(
            r"EVIDENCE_JSON\s*:\s*(\[.*?\])\s*$", re.DOTALL | re.IGNORECASE
        )
        match = pattern.search(raw_text)

        if match:
            evidence_json_str = match.group(1).strip()
            try:
                raw_evidence = json.loads(evidence_json_str)
                if isinstance(raw_evidence, list):
                    # Normalise each item to the expected schema.
                    evidence = [
                        {
                            "frame_num": item.get("frame_num"),
                            "timestamp": str(item.get("timestamp", "")),
                            "description": str(item.get("description", "")),
                        }
                        for item in raw_evidence
                        if isinstance(item, dict)
                    ]
            except json.JSONDecodeError:
                logger.warning("Failed to parse EVIDENCE_JSON block from LLM response.")

            # Remove the evidence block from the displayed answer text.
            answer = raw_text[: match.start()].strip()

        # Enforce strict no-backticks rule: convert any `term` to (term) and remove stray backticks.
        answer = re.sub(r"`([^`]+)`", r"(\1)", answer).replace("`", "")

        return {"answer": answer, "evidence": evidence}

    @staticmethod
    def _error_response(exc: Exception) -> dict:
        """
        Description: Builds a user-friendly error response dict from an exception.
        Input: exc (Exception) — the exception raised during the API call.
        Output: dict — {"answer": str, "evidence": []}
        """
        message = str(exc) or "An unexpected error occurred with the AI provider."
        logger.error("AI assistant error: %s", message)
        return {
            "answer": f"⚠️ **Error communicating with Gemini:** {message}",
            "evidence": [],
        }
