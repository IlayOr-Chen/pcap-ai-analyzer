# 🔬 NetAI Analyzer — Network Traffic & HTTP AI Dashboard

## Overview

NetAI Analyzer is a Streamlit-based forensic dashboard that lets analysts upload PCAP or PCAPNG capture files, parse every packet with **scapy**, and automatically reconstruct full HTTP request/response transactions — including headers, bodies, frame numbers, and response times. The tool detects HTTP errors (4xx/5xx) the moment a file is loaded, maps every public server IP to its geographic location on an interactive world map, and provides a conversational **AI Traffic Investigator** that answers forensic questions about the capture using only the extracted, structured data — with every answer backed by exact frame numbers and timestamps as evidence.

---

## Features

| Tab | What It Does |
|-----|--------------|
| **Overview & Error Hunter** | Displays packet statistics, protocol distribution charts, and a traffic timeline. Automatically scans all HTTP transactions for 4xx/5xx errors and timeouts, surfacing an alert banner with full details (status code meaning, URL, IPs, frame numbers, timestamps). |
| **HTTP Transactions & Stream Inspector** | Fully reconstructs HTTP request/response pairs from raw TCP payloads, showing method, host, URI, status code, response time, and expandable headers and body for every transaction. |
| **GeoIP Server Map** | Resolves all unique public server IPs to real-world countries via the ip-api.com batch REST API, then plots them on an interactive Plotly world map — sized by traffic volume. Private/LAN and multicast addresses are filtered out with a clear in-UI explanation. |
| **AI Traffic Investigator** | Evidence-cited Q&A powered by the OpenAI or Gemini REST API (no SDK). The AI receives a compact JSON snapshot of the capture data and must cite exact frame numbers and timestamps for every claim it makes. |

---

## Project Architecture

The project follows a clean separation of concerns: each Python module owns exactly one responsibility — loading, analyzing, mapping, or presenting — and the Streamlit controller wires them together through Streamlit session state so that heavy parsing only runs once per upload.

| File | Class | Responsibility |
|------|-------|----------------|
| `main_dashboard.py` | `DashboardController` | Streamlit app entry point; renders the 4-tab layout and manages session state so parsing and analysis run only once per file upload. |
| `packet_capture_loader.py` | `PacketCaptureLoader` | Reads PCAP/PCAPNG files via scapy; computes packet statistics, protocol distribution counts, and a time-bucketed traffic timeline. |
| `http_stream_analyzer.py` | `HttpStreamAnalyzer` | Reassembles TCP streams, extracts raw HTTP payloads, and reconstructs request/response transaction objects with full metadata. |
| `error_hunter_engine.py` | `ErrorHunterEngine` | Iterates over all reconstructed HTTP transactions, flags any with status codes ≥ 400 or missing responses (timeouts), and structures the findings for the alert banner. |
| `geo_ip_mapper.py` | `GeoIpMapper` | Extracts unique IP addresses from the capture, filters RFC1918 and multicast ranges, and batch-queries ip-api.com for geolocation data with an in-memory cache. |
| `ai_evidence_assistant.py` | `AiEvidenceAssistant` | Calls OpenAI or Gemini REST APIs directly (no SDK); serializes capture data to a compact JSON context; parses the AI's `EVIDENCE_JSON` array from its response. |
| `ui_theme_manager.py` | `UiThemeManager` | Injects custom CSS into the Streamlit page and provides reusable HTML card, badge, and banner components, plus the stream viewer widget. |

---

## How Data is Passed to the AI (Important)

> [!IMPORTANT]
> The raw PCAP binary file is **NEVER** sent to the LLM. Only structured, human-readable data extracted by the Python layer is transmitted.

The pipeline works as follows:

1. **Extraction** — `PacketCaptureLoader` and `HttpStreamAnalyzer` extract:
   - Capture metadata: total packet count, capture duration, protocol distribution counts.
   - Per-transaction records: frame numbers, timestamps, HTTP method, host, URI, status code, response time (ms), source/destination IPs and ports, request and response headers, and body snippets.

2. **Serialization** — `AiEvidenceAssistant` serializes this structured data into a compact JSON string, capped at **8,000 characters** to stay well within model context limits while preserving the most forensically relevant transactions.

3. **Prompt injection** — The JSON is injected directly into the AI system prompt alongside strict instructions:
   > *"Answer ONLY based on the provided data. For every claim you make, cite the exact Frame Number and Timestamp. Append an `EVIDENCE_JSON: [...]` array at the end of your response listing each piece of evidence."*

4. **Response parsing** — The dashboard splits the AI's reply at the `EVIDENCE_JSON:` marker, displays the natural-language answer in one panel, and renders the evidence array as a structured table in a second panel — making every assertion independently verifiable against the original capture.

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Windows:** scapy works for offline PCAP reading without Npcap (live capture requires Npcap, but is not needed for this tool)
- An **OpenAI API key** (`sk-...`) **or** a **Gemini API key** (`AIza...`)

### Steps

```bash
# 1. Clone or download the project
cd pcap-ai-analyzer

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
copy .env.example .env
# Edit .env and add your key:
# OPENAI_API_KEY=sk-...
# or
# GEMINI_API_KEY=AIza...

# 5. Run the dashboard
streamlit run main_dashboard.py
```

The dashboard will open automatically in your default browser at `http://localhost:8501`.

---

## Usage Guide

### Tab 1 — Overview & Error Hunter

Upload a PCAP or PCAPNG file using the file picker at the top of the page. The dashboard immediately parses the capture and displays:
- A summary card with total packets, capture duration, and unique IP count.
- A protocol distribution pie chart and a traffic-volume timeline.
- If any HTTP errors are found, a **red alert banner** appears automatically listing every error with its status code, URL, client/server IPs, and frame numbers — no manual searching required.

### Tab 2 — HTTP Transactions & Stream Inspector

Browse the full table of reconstructed HTTP transactions. Click any row to expand it into the **Stream Inspector**, which shows the raw request and response headers, the body content, the response time in milliseconds, and the exact frame numbers from the PCAP — useful for cross-referencing in Wireshark.

### Tab 3 — GeoIP Server Map

An interactive Plotly world map renders automatically after the file is loaded. Each dot represents a unique public server IP; dot size scales with the number of packets exchanged with that server. Hover over a dot to see the IP, country, and packet count. A panel beneath the map explains which addresses were excluded and why (private RFC1918 ranges, multicast, localhost).

### Tab 4 — AI Traffic Investigator

Type any forensic question in plain English (or Hebrew) about the capture — for example:
- *"Which server returned the most errors?"*
- *"Was there any suspicious redirect chain?"*
- *"What is the average response time for requests to api.example.com?"*

The AI answers using only the extracted data and appends a structured evidence table with the exact frame numbers and timestamps that support each claim.

---

## Custom Features — Why We Built Them

### Automated HTTP Error Hunter

The moment a PCAP is loaded, `ErrorHunterEngine` automatically scans **all** reconstructed HTTP transactions for status codes ≥ 400 and for requests that received no response within the capture window (timeouts). The result is an alert banner at the top of Tab 1 that immediately surfaces every failure — including the HTTP status code with its standard meaning (e.g., *404 Not Found*, *503 Service Unavailable*), the full requested URL, the client and server IP addresses, and the precise frame numbers and timestamps. This eliminates the need to manually scroll through hundreds of rows to identify failures, which in a large capture file can take significant time and is error-prone.

### GeoIP Server Load Map

`GeoIpMapper` extracts all unique IP addresses observed in the capture and applies RFC1918 filtering to remove private/LAN addresses (`10.x.x.x`, `192.168.x.x`, `172.16.x.x–172.31.x.x`) and multicast addresses (`224.x.x.x`), since these have no meaningful geographic location. The remaining public IPs are submitted to the **ip-api.com** batch REST endpoint in a single request, with an in-memory cache preventing duplicate lookups when the same IP appears across many packets. The resolved coordinates are then passed to a Plotly scatter-geo figure that renders an interactive world map — each server is plotted as a circle whose size reflects the volume of traffic exchanged with it. A clear explanation panel directly in the UI tells analysts exactly why certain IPs do not appear on the map, preventing confusion over "missing" private or internal addresses.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `streamlit` | ≥ 1.35 | Web UI framework — renders the multi-tab dashboard in the browser |
| `scapy` | ≥ 2.5 | PCAP/PCAPNG parsing — reads packet layers, TCP streams, and raw payloads |
| `plotly` | ≥ 5.20 | Interactive charts and world map (scatter-geo, pie, bar, line) |
| `pandas` | ≥ 2.0 | Data tables for transaction display and evidence rendering |
| `requests` | ≥ 2.31 | REST API calls to OpenAI, Gemini, and ip-api.com — **no SDKs required** |
| `python-dotenv` | ≥ 1.0 | Secure API key loading from `.env` file at startup |

---

## Security Notes

> [!CAUTION]
> Never commit your `.env` file to version control. It contains your API keys.

- **API keys** are loaded exclusively from the `.env` file via `python-dotenv` — they are never hardcoded in source files and never displayed anywhere in the UI.
- **`.env` is listed in `.gitignore`** to prevent accidental inclusion in commits or pull requests. Use `.env.example` (which contains only placeholder values) as the committed reference.
- **Uploaded PCAP files** are written to a temporary file on disk, parsed in memory by scapy, and then deleted immediately — they are never stored permanently or transmitted anywhere.
- **Network calls** made by the application are limited to: (a) the OpenAI or Gemini REST endpoint for the AI assistant, and (b) the ip-api.com batch endpoint for geolocation — both only when explicitly triggered by the user.

---

---

## סקיצה בעברית — מדריך קצר

### מנתח תעבורת רשת עם בינה מלאכותית

NetAI Analyzer הוא כלי לניתוח קבצי PCAP ו-PCAPNG — קבצי לכידת רשת — בעזרת ממשק ויזואלי מבוסס Streamlit. הכלי מנתח את הפקטות בעזרת ספריית scapy, משחזר עסקאות HTTP מלאות כולל כותרות וגוף הבקשה, מאתר שגיאות HTTP אוטומטית, ממפה כתובות IP של שרתים על גבי מפה גיאוגרפית אינטראקטיבית, ומאפשר לשאול שאלות פורנזיות בשפה טבעית בעזרת מודלי בינה מלאכותית (OpenAI או Gemini).

**התקנה:**
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # הוסיפו את מפתח ה-API בקובץ .env
streamlit run main_dashboard.py
```

**Error Hunter אוטומטי:** ברגע שקובץ PCAP נטען, המערכת סורקת אוטומטית את כל עסקאות ה-HTTP ומציגה באנר התראה עם כל השגיאות (קודי 4xx/5xx), כולל ה-URL המלא, כתובות ה-IP של הלקוח והשרת, ומספרי הפריימים המדויקים — ללא צורך בגלילה ידנית.

**מפת GeoIP:** המערכת מסננת כתובות IP פרטיות (RFC1918) וכתובות multicast, ולאחר מכן שולחת את כתובות ה-IP הציבוריות לשירות ip-api.com כדי לאתר את מיקומן הגיאוגרפי. התוצאה מוצגת כמפת עולם אינטראקטיבית שבה כל שרת מסומן בנקודה שגודלה משקף את נפח התנועה אליו.
