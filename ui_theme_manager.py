"""
ui_theme_manager.py
-------------------
Centralised Streamlit UI theming and HTML component helpers for the
PCAP AI Analyser dashboard.

All methods are static/class methods — no instantiation required.
"""

from __future__ import annotations

import html


class UiThemeManager:
    """
    Manages the visual theme and reusable HTML components for the dashboard.

    All methods are static; import the class and call directly::

        UiThemeManager.apply_theme()
        card_html = UiThemeManager.metric_card_html("Packets", "12,345")

    The theme uses a dark colour palette with CSS custom properties so that
    individual component colours can be overridden at a single point.
    """

    # ------------------------------------------------------------------
    # Colour palette (mirrored in CSS :root variables)
    # ------------------------------------------------------------------
    COLOR_PRIMARY   = "#2563EB"  # blue-600
    COLOR_SUCCESS   = "#10B981"  # emerald-500
    COLOR_WARNING   = "#F59E0B"  # amber-500
    COLOR_ERROR     = "#EF4444"  # red-500
    COLOR_BG_DARK   = "#0F172A"  # slate-900
    COLOR_BG_CARD   = "#1E293B"  # slate-800
    COLOR_BORDER    = "#334155"  # slate-700

    # Status-code range → colour
    _STATUS_COLORS: dict[str, str] = {
        "2xx": COLOR_SUCCESS,
        "3xx": "#60A5FA",   # blue-400
        "4xx": COLOR_WARNING,
        "5xx": COLOR_ERROR,
    }

    # ------------------------------------------------------------------
    # Theme injection
    # ------------------------------------------------------------------

    @classmethod
    def apply_theme(cls) -> None:
        """
        This function injects the global CSS theme block into the active Streamlit page.
        Input: None (uses class-level colour constants internally)
        Output: None — side-effect only: calls st.markdown with unsafe_allow_html=True
        """
        import streamlit as st  # local import – not available at module level in tests

        st.markdown(cls._build_css(), unsafe_allow_html=True)

    @classmethod
    def _build_css(cls) -> str:
        """Return the full ``<style>`` block as a string."""
        return f"""
<style>
/* ============================================================
   Google Fonts
   ============================================================ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* ============================================================
   CSS Custom Properties (design tokens)
   ============================================================ */
:root {{
    --color-primary:   {cls.COLOR_PRIMARY};
    --color-success:   {cls.COLOR_SUCCESS};
    --color-warning:   {cls.COLOR_WARNING};
    --color-error:     {cls.COLOR_ERROR};
    --color-bg-dark:   {cls.COLOR_BG_DARK};
    --color-bg-card:   {cls.COLOR_BG_CARD};
    --color-border:    {cls.COLOR_BORDER};
    --color-text:      #E2E8F0;
    --color-muted:     #94A3B8;
    --radius-sm:       6px;
    --radius-md:       10px;
    --radius-lg:       14px;
    --shadow-card:     0 4px 6px -1px rgba(0,0,0,.4), 0 2px 4px -2px rgba(0,0,0,.3);
    --transition-fast: 150ms ease;
    --transition-base: 250ms ease;
    --font-mono:       'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}}

/* ============================================================
   Keyframes
   ============================================================ */

/* Entrance animation for metric cards */
@keyframes fadeInUp {{
    from {{
        opacity: 0;
        transform: translateY(14px);
    }}
    to {{
        opacity: 1;
        transform: translateY(0);
    }}
}}

/* Pulsing border for the error alert banner */
@keyframes pulse-border {{
    0%   {{ border-color: var(--color-error); box-shadow: 0 0 0 0 rgba(239,68,68,.5); }}
    50%  {{ border-color: #FCA5A5;            box-shadow: 0 0 0 4px rgba(239,68,68,.0); }}
    100% {{ border-color: var(--color-error); box-shadow: 0 0 0 0 rgba(239,68,68,.5); }}
}}

/* ============================================================
   Global base
   ============================================================ */
html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {{
    background-color: var(--color-bg-dark) !important;
    color: var(--color-text);
    font-family: 'Inter', system-ui, sans-serif;
}}

/* ============================================================
   Metric card
   ============================================================ */
.metric-card {{
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-card);
    padding: 1.25rem 1.5rem;
    margin-bottom: .75rem;
    animation: fadeInUp 0.4s ease both;
    transition: transform var(--transition-base), box-shadow var(--transition-base);
    position: relative;
    overflow: hidden;
}}

.metric-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 3px; height: 100%;
    background: var(--card-accent, var(--color-primary));
    border-radius: var(--radius-sm) 0 0 var(--radius-sm);
}}

.metric-card:hover {{
    transform: translateY(-3px);
    box-shadow: 0 10px 20px -4px rgba(0,0,0,.5);
}}

.metric-card .mc-icon {{
    font-size: 1.6rem;
    line-height: 1;
    margin-bottom: .4rem;
}}

.metric-card .mc-title {{
    font-size: .72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--color-muted);
    margin-bottom: .25rem;
}}

.metric-card .mc-value {{
    font-size: 2rem;
    font-weight: 700;
    color: var(--card-accent, var(--color-primary));
    line-height: 1.1;
}}

.metric-card .mc-subtitle {{
    font-size: .78rem;
    color: var(--color-muted);
    margin-top: .3rem;
}}

/* ============================================================
   Error banner
   ============================================================ */
.error-banner {{
    background: linear-gradient(135deg, rgba(239,68,68,.15) 0%, rgba(239,68,68,.05) 100%);
    border: 1.5px solid var(--color-error);
    border-radius: var(--radius-md);
    padding: 1rem 1.25rem;
    margin-bottom: 1rem;
    animation: pulse-border 2.4s ease-in-out infinite;
}}

.error-banner .eb-header {{
    display: flex;
    align-items: center;
    gap: .5rem;
    font-weight: 600;
    font-size: .9rem;
    color: #FCA5A5;
    margin-bottom: .6rem;
}}

.error-banner .eb-item {{
    display: flex;
    align-items: flex-start;
    gap: .5rem;
    font-size: .82rem;
    color: var(--color-text);
    padding: .2rem 0;
    border-bottom: 1px solid rgba(239,68,68,.15);
}}

.error-banner .eb-item:last-child {{
    border-bottom: none;
}}

.error-banner .eb-frame {{
    font-family: var(--font-mono);
    font-size: .78rem;
    color: #FCA5A5;
    white-space: nowrap;
    min-width: 70px;
}}

/* ============================================================
   Success badge
   ============================================================ */
.success-badge {{
    display: inline-block;
    background: rgba(16,185,129,.18);
    color: {cls.COLOR_SUCCESS};
    border: 1px solid rgba(16,185,129,.35);
    border-radius: 999px;
    padding: .18rem .75rem;
    font-size: .75rem;
    font-weight: 600;
    letter-spacing: .04em;
    line-height: 1.4;
}}

/* ============================================================
   Evidence box
   ============================================================ */
.evidence-box {{
    background: rgba(15,23,42,.8);
    border: 1px solid var(--color-border);
    border-left: 3px solid var(--color-primary);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    padding: 1rem 1.25rem;
    font-family: var(--font-mono);
    font-size: .82rem;
    line-height: 1.6;
    margin: .75rem 0;
    max-height: 320px;
    overflow-y: auto;
}}

.evidence-box .ev-row {{
    display: grid;
    grid-template-columns: auto auto 1fr;
    gap: .4rem 1rem;
    padding: .3rem 0;
    border-bottom: 1px solid rgba(51,65,85,.5);
    align-items: start;
}}

.evidence-box .ev-row:last-child {{
    border-bottom: none;
}}

.evidence-box .ev-frame {{
    color: var(--color-primary);
    font-weight: 600;
    white-space: nowrap;
}}

.evidence-box .ev-ts {{
    color: var(--color-muted);
    white-space: nowrap;
}}

.evidence-box .ev-desc {{
    color: var(--color-text);
    word-break: break-word;
}}

/* ============================================================
   Stream viewer
   ============================================================ */
.stream-viewer {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: .75rem;
}}

.sv-panel {{
    background: rgba(15,23,42,.9);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    padding: .75rem 1rem;
    max-height: 420px;
    overflow-y: auto;
}}

.sv-panel pre {{
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: var(--font-mono);
    font-size: .78rem;
    color: var(--color-text);
    line-height: 1.55;
}}

.sv-label {{
    font-size: .7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .08em;
    padding: .2rem .6rem .5rem;
}}

.sv-label.client {{ color: {cls.COLOR_WARNING}; }}
.sv-label.server  {{ color: {cls.COLOR_SUCCESS}; }}

/* ============================================================
   HTTP status-code badge helpers
   ============================================================ */
.status-badge {{
    display: inline-block;
    border-radius: 999px;
    padding: .15rem .65rem;
    font-size: .72rem;
    font-weight: 700;
    letter-spacing: .04em;
    line-height: 1.4;
}}

.status-badge-2xx {{
    background: rgba(16,185,129,.18);
    color: {cls._STATUS_COLORS['2xx']};
    border: 1px solid rgba(16,185,129,.3);
}}

.status-badge-3xx {{
    background: rgba(96,165,250,.15);
    color: {cls._STATUS_COLORS['3xx']};
    border: 1px solid rgba(96,165,250,.3);
}}

.status-badge-4xx {{
    background: rgba(245,158,11,.15);
    color: {cls._STATUS_COLORS['4xx']};
    border: 1px solid rgba(245,158,11,.3);
}}

.status-badge-5xx {{
    background: rgba(239,68,68,.15);
    color: {cls._STATUS_COLORS['5xx']};
    border: 1px solid rgba(239,68,68,.3);
}}

/* ============================================================
   Sidebar
   ============================================================ */
[data-testid="stSidebar"] {{
    background-color: {cls.COLOR_BG_DARK} !important;
    border-right: 1px solid var(--color-border);
}}

[data-testid="stSidebar"] .stMarkdown,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] p {{
    color: var(--color-text) !important;
}}

/* ============================================================
   Tabs
   ============================================================ */
[data-testid="stTabs"] [data-baseweb="tab-list"] {{
    background: transparent !important;
    border-bottom: 1px solid var(--color-border);
    gap: .25rem;
}}

[data-testid="stTabs"] [data-baseweb="tab"] {{
    background: transparent !important;
    color: var(--color-muted) !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    padding: .5rem 1rem !important;
    font-weight: 500;
    transition: color var(--transition-fast), border-color var(--transition-fast);
}}

[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {{
    color: var(--color-primary) !important;
    border-bottom-color: var(--color-primary) !important;
}}

[data-testid="stTabs"] [data-baseweb="tab"]:hover {{
    color: var(--color-text) !important;
}}

/* ============================================================
   Dataframe / table row hover
   ============================================================ */
[data-testid="stDataFrame"] tbody tr:hover td,
.stDataFrame tbody tr:hover td {{
    background-color: rgba(37,99,235,.12) !important;
    transition: background-color var(--transition-fast);
}}

/* ============================================================
   Scrollbar (webkit)
   ============================================================ */
::-webkit-scrollbar               {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track         {{ background: var(--color-bg-dark); }}
::-webkit-scrollbar-thumb         {{ background: var(--color-border); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover   {{ background: #475569; }}

/* ============================================================
   IP Classification Table
   ============================================================ */
.ip-classification-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: .82rem;
    margin: .75rem 0;
}}

.ip-classification-table th {{
    background: var(--color-bg-card);
    color: var(--color-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .06em;
    font-size: .72rem;
    padding: .5rem .75rem;
    border-bottom: 1px solid var(--color-border);
    text-align: left;
}}

.ip-classification-table td {{
    padding: .45rem .75rem;
    border-bottom: 1px solid rgba(51,65,85,.4);
    color: var(--color-text);
}}

/* Alternating row backgrounds for readability */
.ip-classification-table tbody tr:nth-child(odd) td {{
    background: rgba(30,41,59,.5);
}}

.ip-classification-table tbody tr:nth-child(even) td {{
    background: rgba(15,23,42,.4);
}}

.ip-classification-table tbody tr:hover td {{
    background: rgba(37,99,235,.12) !important;
    transition: background-color var(--transition-fast);
}}

/* ============================================================
   Clean Dark Mode UI & RTL Bullet Point Fix
   ============================================================ */
[data-testid="stHeader"],
.stDeployButton,
[data-testid="stDeployButton"],
#MainMenu {{
    display: none !important;
    visibility: hidden !important;
}}

[data-testid="stMarkdownContainer"] ul,
[data-testid="stMarkdownContainer"] li {{
    direction: rtl;
    text-align: right;
}}

[data-testid="stChatMessageContent"] p {{
    unicode-bidi: plaintext;
    text-align: start;
}}
</style>
"""

    # ------------------------------------------------------------------
    # HTML component helpers
    # ------------------------------------------------------------------

    @classmethod
    def metric_card_html(
        cls,
        title: str,
        value: str,
        subtitle: str = "",
        icon: str = "",
        color: str = "#2563EB",
    ) -> str:
        """
        This function builds and returns an HTML string for a styled metric card widget.
        Input: title (str) label text, value (str) primary display value,
               subtitle (str) optional secondary text, icon (str) optional emoji/icon,
               color (str) optional hex accent color defaulting to blue #2563EB
        Output: str — self-contained HTML fragment ready for st.markdown
        """
        safe_title    = html.escape(title)
        safe_value    = html.escape(value)
        safe_subtitle = html.escape(subtitle) if subtitle else ""
        safe_icon     = html.escape(icon) if icon else ""
        safe_color    = html.escape(color)

        icon_html     = f'<div class="mc-icon">{safe_icon}</div>' if safe_icon else ""
        subtitle_html = f'<div class="mc-subtitle">{safe_subtitle}</div>' if safe_subtitle else ""

        return (
            f'<div class="metric-card" style="--card-accent:{safe_color};">'
            f"{icon_html}"
            f'<div class="mc-title">{safe_title}</div>'
            f'<div class="mc-value">{safe_value}</div>'
            f"{subtitle_html}"
            f"</div>"
        )

    @classmethod
    def error_banner_html(cls, errors: list[dict]) -> str:
        """
        This function builds a pulsing red HTML banner listing all HTTP error records.
        Input: errors (list[dict]) — list of error dicts, each may contain request_frame (or frame_num),
               status_code, host, uri, and/or description keys
        Output: str — self-contained HTML fragment, or empty string if errors is empty
        """
        if not errors:
            return ""

        items_html = ""
        for err in errors:
            raw_frame = err.get("request_frame")
            if raw_frame is None:
                raw_frame = err.get("frame_num")

            # Parse/validate frame number; hide the frame reference if missing or unparseable
            frame_html = ""
            if raw_frame is not None and str(raw_frame).strip() not in ("", "?", "None"):
                try:
                    parsed_frame = int(str(raw_frame).strip().lstrip("#"))
                    frame_html = f'<span class="eb-frame">Frame&nbsp;{parsed_frame}</span>'
                except (ValueError, TypeError):
                    frame_html = ""

            status      = html.escape(str(err.get("status_code") or ""))
            host        = html.escape(str(err.get("host") or ""))
            uri         = html.escape(str(err.get("uri") or ""))
            description = html.escape(str(err.get("description") or ""))

            if description:
                detail = description
            else:
                detail = " ".join(filter(None, [status, host, uri])) or "Error"

            items_html += (
                f'<div class="eb-item">'
                f"{frame_html}"
                f'<span>{detail}</span>'
                f"</div>"
            )

        count = len(errors)
        plural = "errors" if count != 1 else "error"

        return (
            f'<div class="error-banner">'
            f'<div class="eb-header">🚨 {count} HTTP {plural} detected</div>'
            f"{items_html}"
            f"</div>"
        )

    @classmethod
    def success_badge_html(cls, text: str) -> str:
        """
        This function returns a small green inline HTML badge element.
        Input: text (str) — the label to display inside the badge
        Output: str — an inline HTML <span> element with success styling
        """
        return f'<span class="success-badge">✓ {html.escape(text)}</span>'

    @classmethod
    def evidence_box_html(cls, evidence: list[dict]) -> str:
        """
        This function renders an HTML evidence box listing cited packet frames with timestamps.
        Input: evidence (list[dict]) — list of dicts each containing frame_num,
               timestamp, and description keys
        Output: str — self-contained HTML fragment, or empty string if evidence is empty
        """
        if not evidence:
            return ""

        rows_html = ""
        for item in evidence:
            frame_num   = html.escape(str(item.get("frame_num", "?")))
            timestamp   = html.escape(str(item.get("timestamp", "")))
            description = html.escape(str(item.get("description", "")))

            rows_html += (
                f'<div class="ev-row">'
                f'<span class="ev-frame">#{frame_num}</span>'
                f'<span class="ev-ts">{timestamp}</span>'
                f'<span class="ev-desc">{description}</span>'
                f"</div>"
            )

        return (
            f'<div class="evidence-box">'
            f"{rows_html}"
            f"</div>"
        )

    @classmethod
    def status_badge_html(cls, status_code: int | None) -> str:
        """
        This function returns a colour-coded pill badge for a given HTTP status code.
        Input: status_code (int | None) — an HTTP response code such as 200, 404, or 500;
               pass None to render a neutral N/A badge
        Output: str — an inline HTML <span> element with the appropriate colour class
        """
        if status_code is None:
            return '<span class="status-badge" style="background:rgba(148,163,184,.15);color:#94A3B8;border:1px solid rgba(148,163,184,.3);">N/A</span>'

        code = int(status_code)
        if 200 <= code < 300:
            css_class = "status-badge-2xx"
        elif 300 <= code < 400:
            css_class = "status-badge-3xx"
        elif 400 <= code < 500:
            css_class = "status-badge-4xx"
        elif 500 <= code < 600:
            css_class = "status-badge-5xx"
        else:
            css_class = ""

        badge_class = f"status-badge {css_class}".strip()
        return f'<span class="{badge_class}">{html.escape(str(code))}</span>'

    @classmethod
    def stream_viewer_html(cls, client_payload: str, server_payload: str) -> str:
        """
        This function builds a two-panel side-by-side HTML viewer for HTTP request/response payloads.
        Input: client_payload (str) — raw HTTP request text to show in the left panel;
               server_payload (str) — raw HTTP response text to show in the right panel
        Output: str — self-contained HTML fragment with two independently scrollable panels
        """
        safe_client = html.escape(client_payload or "(no client data)")
        safe_server = html.escape(server_payload or "(no server data)")

        return (
            f'<div class="stream-viewer">'
            # --- Client panel ---
            f'<div class="sv-panel">'
            f'<div class="sv-label client">⬆ Client Request</div>'
            f"<pre>{safe_client}</pre>"
            f"</div>"
            # --- Server panel ---
            f'<div class="sv-panel">'
            f'<div class="sv-label server">⬇ Server Response</div>'
            f"<pre>{safe_server}</pre>"
            f"</div>"
            f"</div>"
        )
