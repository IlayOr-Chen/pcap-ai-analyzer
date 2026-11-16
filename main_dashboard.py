import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from pathlib import Path
from dotenv import load_dotenv
import json
import os
import time

from packet_capture_loader import PacketCaptureLoader
from http_stream_analyzer import HttpStreamAnalyzer
from error_hunter_engine import ErrorHunterEngine
from geo_ip_mapper import GeoIpMapper
from ai_evidence_assistant import AiEvidenceAssistant
from ui_theme_manager import UiThemeManager

load_dotenv()
st.set_page_config(
    page_title="NetAI Analyzer",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded"
)


class DashboardController:
    """Orchestrates all UI rendering and session state for the NetAI Analyzer dashboard."""

    # ------------------------------------------------------------------ #
    #  Session-state helpers                                               #
    # ------------------------------------------------------------------ #

    def _init_state(self) -> None:
        """
        Description: Sets up all Streamlit session state keys with safe default values
                     on the very first run. Skips any key that already exists so that
                     re-runs do not reset live data.
        Input: None
        Output: None — writes directly into st.session_state
        """
        defaults: dict = {
            "loader": None,
            "analyzer": None,
            "error_engine": None,
            "geo_mapper": None,
            "ai_assistant": None,
            "chat_history": [],
            "ai_context": "",
            "structured_json": "{}",
            "selected_transaction": None,
            "file_loaded": False,
            "geo_resolved": False,
        }
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """
        Description: Main entry point for the dashboard. Initialises session state,
                     applies the CSS theme, renders the sidebar, and then shows either
                     the 4-tab analysis view (if a file is loaded) or the welcome screen.
        Input: None
        Output: None — renders the entire Streamlit UI
        """
        self._init_state()
        UiThemeManager.apply_theme()
        st.markdown(
            """
            <style>
            [data-testid="stHeader"],
            .stDeployButton,
            [data-testid="stDeployButton"],
            #MainMenu {
                display: none !important;
                visibility: hidden !important;
            }
            [data-testid="stMarkdownContainer"] ul,
            [data-testid="stMarkdownContainer"] li {
                direction: rtl;
                text-align: right;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        self._build_sidebar()

        if st.session_state.file_loaded:
            self._render_main_tabs()
        else:
            self._render_welcome_screen()

    # ------------------------------------------------------------------ #
    #  Sidebar                                                             #
    # ------------------------------------------------------------------ #

    def _build_sidebar(self) -> None:
        """
        Description: Renders the left sidebar containing the app logo, the PCAP file uploader,
                     a quick stats panel (packets / duration / errors), and a chat-clear button.
                     When a new file is uploaded, it triggers the full analysis pipeline.
        Input: None
        Output: None — renders sidebar widgets into st.sidebar
        """
        with st.sidebar:
            # --- Logo / title ---
            st.markdown(
                """
                <div style="text-align:center; padding: 1rem 0 0.5rem;">
                    <span style="font-size:2.4rem;">🔬</span>
                    <h2 style="margin:0; font-size:1.4rem; font-weight:700;">NetAI Analyzer</h2>
                    <p style="margin:0; font-size:0.78rem; opacity:0.65;">
                        Network Traffic Intelligence Platform
                    </p>
                </div>
                <hr style="margin: 0.75rem 0;">
                """,
                unsafe_allow_html=True,
            )

            # --- File uploader ---
            st.subheader("📂 Load Capture File")
            uploaded_file = st.file_uploader(
                "Upload a PCAP file",
                type=["pcap", "pcapng"],
                label_visibility="collapsed",
            )

            if uploaded_file is not None:
                current_name = getattr(uploaded_file, "name", None)
                prev_name = st.session_state.get("_last_uploaded_name")

                if current_name != prev_name:
                    st.session_state["_last_uploaded_name"] = current_name
                    self._load_capture(uploaded_file)

            st.divider()

            # Clear chat button (shown only when chat history exists)
            if st.session_state.chat_history:
                st.divider()
                if st.button("🗑️ Clear Chat History", use_container_width=True):
                    st.session_state.chat_history = []
                    st.rerun()

            # --- Quick stats ---
            if st.session_state.file_loaded:
                st.divider()
                st.subheader("📊 Quick Stats")
                loader: PacketCaptureLoader = st.session_state.loader
                error_engine: ErrorHunterEngine = st.session_state.error_engine
                summary = loader.get_summary()

                st.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
                duration = summary.get("duration_seconds", 0)
                st.metric("Duration", f"{duration:.2f}s")
                error_count = len(error_engine.get_errors()) if error_engine else 0
                st.metric(
                    "HTTP Errors",
                    error_count,
                    delta=None if error_count == 0 else f"{error_count} issue(s)",
                    delta_color="inverse",
                )

    # ------------------------------------------------------------------ #
    #  File loading pipeline                                               #
    # ------------------------------------------------------------------ #

    def _load_capture(self, uploaded_file) -> None:
        """
        Description: Runs the full analysis pipeline when a new PCAP file is uploaded.
                     Creates all analysis objects in sequence: loader → analyzer → error engine →
                     geo mapper → AI context. Stores everything in Streamlit session state.
        Input: uploaded_file — file-like object from st.file_uploader
        Output: None — populates st.session_state and shows success/error toast
        """
        with st.spinner("🔄 Loading and analysing capture file…"):
            try:
                # 1. Load packets — PacketCaptureLoader.load() handles the
                #    temp-file creation internally; just pass the file object.
                loader = PacketCaptureLoader()
                success = loader.load(uploaded_file)
                if not success:
                    raise RuntimeError(loader.error_message or "Unknown error loading capture.")
                st.session_state.loader = loader

                packets = loader.get_packets()
                raw_packets_info = loader.get_raw_packets_info()

                # 2. Analyse HTTP streams
                analyzer = HttpStreamAnalyzer(packets)
                analyzer.analyze()
                st.session_state.analyzer = analyzer

                transactions = analyzer.get_transactions()

                # 3. Hunt for errors
                error_engine = ErrorHunterEngine(transactions)
                error_engine.scan()
                st.session_state.error_engine = error_engine

                # 4. Prepare GeoIP mapper (resolve lazily in GeoIP tab)
                geo_mapper = GeoIpMapper(raw_packets_info)
                st.session_state.geo_mapper = geo_mapper
                st.session_state.geo_resolved = False

                # 5. Build AI context string
                summary = loader.get_summary()
                st.session_state.ai_context = self._build_ai_context(summary, transactions)

                st.session_state.file_loaded = True
                st.toast(f"✅ Loaded **{uploaded_file.name}** successfully!", icon="🎉")

            except Exception as exc:  # noqa: BLE001
                st.error(f"❌ Failed to load capture: {exc}")
                st.session_state.file_loaded = False

    def _build_ai_context(self, summary: dict, transactions: list[dict]) -> str:
        """
        Description: Builds a detailed summary of the capture and HTTP transactions
                     (including frame numbers, timestamps, latency/time delta, status codes,
                     hosts, IPs/ports, and stream IDs) to inject into the AI prompt.
        Input: summary (dict) — capture summary from PacketCaptureLoader.get_summary();
               transactions (list[dict]) — HTTP transactions from HttpStreamAnalyzer
        Output: str — multi-line text string ready to be embedded in the AI prompt
        """
        from collections import Counter  # noqa: PLC0415

        host_counts = Counter(t.get("host") or t.get("dst_ip", "unknown") for t in transactions)

        slowest_txns = sorted(
            [t for t in transactions if t.get("response_time_ms") is not None],
            key=lambda x: x.get("response_time_ms", 0),
            reverse=True,
        )[:10]
        slowest_requests = [
            {
                "frame": t.get("request_frame"),
                "timestamp": str(t.get("request_timestamp", "")),
                "protocol": "HTTP",
                "host": t.get("host") or t.get("dst_ip", ""),
                "uri": t.get("uri", "/"),
                "time_delta_ms": t.get("response_time_ms"),
            }
            for t in slowest_txns
        ]
        status_codes = [
            {
                "frame": t.get("request_frame"),
                "response_frame": t.get("response_frame"),
                "timestamp": str(t.get("request_timestamp", "")),
                "code": t.get("status_code"),
                "host": t.get("host") or t.get("dst_ip", ""),
                "uri": t.get("uri", "/"),
            }
            for t in transactions
            if t.get("status_code") is not None
        ]

        import json as _json  # noqa: PLC0415

        structured_json = _json.dumps(
            {
                "capture_summary": {
                    "total_packets": summary.get("total_packets", "N/A"),
                    "start_time_utc": summary.get("start_time", "N/A"),
                    "end_time_utc": summary.get("end_time", "N/A"),
                    "duration_seconds": summary.get("duration_seconds", "N/A"),
                    "protocols": summary.get("protocols", {}),
                    "top_src_ips": summary.get("top_src_ips", []),
                    "top_dst_ips": summary.get("top_dst_ips", []),
                },
                "slowest_requests": slowest_requests,
                "status_codes": status_codes[:50],
                "host_counts": dict(host_counts),
                "http_transactions": [
                    {
                        "request_frame": t.get("request_frame"),
                        "response_frame": t.get("response_frame"),
                        "request_timestamp": t.get("request_timestamp"),
                        "response_timestamp": t.get("response_timestamp"),
                        "method": t.get("method"),
                        "host": t.get("host"),
                        "uri": t.get("uri"),
                        "status_code": t.get("status_code"),
                        "time_delta_ms": t.get("response_time_ms"),
                        "src_ip": t.get("src_ip"),
                        "src_port": t.get("src_port"),
                        "dst_ip": t.get("dst_ip"),
                        "dst_port": t.get("dst_port"),
                        "stream_key": t.get("stream_key"),
                    }
                    for t in transactions[:80]
                ],
            },
            indent=2,
            default=str,
        )
        st.session_state.structured_json = structured_json
        return structured_json

    # ------------------------------------------------------------------ #
    #  Main tabs                                                           #
    # ------------------------------------------------------------------ #

    def _render_main_tabs(self) -> None:
        """
        Description: Creates the 4 main tabs and routes rendering to each tab's method.
        Input: None
        Output: None — renders all 4 Streamlit tabs
        """
        tab_overview, tab_http, tab_geo, tab_ai = st.tabs(
            [
                "Overview & Error Hunter",
                "HTTP Transactions & Stream Inspector",
                "GeoIP Server Map",
                "AI Traffic Investigator",
            ]
        )
        with tab_overview:
            self._tab_overview()
        with tab_http:
            self._tab_http()
        with tab_geo:
            self._tab_geo()
        with tab_ai:
            self._tab_ai()

    # ------------------------------------------------------------------ #
    #  Tab 1 — Overview & Error Hunter                                     #
    # ------------------------------------------------------------------ #

    def _tab_overview(self) -> None:
        """
        Description: Renders Tab 1 — the Error Hunter alert banner, capture metric cards,
                     protocol distribution donut chart, traffic-over-time line chart, and
                     top source/destination IP tables.
        Input: None — reads from st.session_state (loader, error_engine)
        Output: None — renders all Tab 1 UI elements
        """
        loader: PacketCaptureLoader = st.session_state.loader
        error_engine: ErrorHunterEngine = st.session_state.error_engine
        summary = loader.get_summary()

        # ── Error Hunter ────────────────────────────────────────────────
        st.header("🚨 Error Hunter", divider="red")
        errors = error_engine.get_errors() if error_engine else []

        if errors:
            banner_html = UiThemeManager.error_banner_html(errors)
            st.markdown(banner_html, unsafe_allow_html=True)

            for error in errors:
                status_display = error.get("status_code") if error.get("status_code") is not None else "No Response"
                label = (
                    f"[{status_display}] "
                    f"{error.get('method', 'GET')} "
                    f"{error.get('host', '')}{error.get('uri', '/')}"
                )
                with st.expander(label, expanded=False):
                    # Map status codes to human-readable meanings
                    status_meanings = {
                        400: "Bad Request - The server could not understand the request",
                        401: "Unauthorized - Authentication is required",
                        403: "Forbidden - Access to this resource is denied",
                        404: "Not Found - The requested resource or path was not found on the server",
                        405: "Method Not Allowed",
                        408: "Request Timeout",
                        429: "Too Many Requests - Rate limit exceeded",
                        500: "Internal Server Error - The server encountered an unexpected error",
                        502: "Bad Gateway - Invalid response from upstream server",
                        503: "Service Unavailable - The server is temporarily unable to handle requests",
                        504: "Gateway Timeout",
                    }
                    sc = error.get("status_code")
                    meaning = status_meanings.get(sc, f"HTTP {sc} Error") if sc else "No Response / Timeout"

                    def _parse_frame(val) -> int | None:
                        if val is None or str(val).strip() in ("", "?", "None"):
                            return None
                        try:
                            return int(str(val).strip().lstrip("#"))
                        except (ValueError, TypeError):
                            return None

                    req_frame = _parse_frame(error.get("request_frame"))
                    resp_frame = _parse_frame(error.get("response_frame"))
                    host = error.get("host", "")
                    uri = error.get("uri", "/")
                    method = error.get("method", "GET")
                    src_ip = error.get("src_ip") or "N/A"
                    src_port = error.get("src_port")
                    src = f"{src_ip}:{src_port}" if src_port else str(src_ip)
                    dst_ip = error.get("dst_ip") or "N/A"
                    dst_port = error.get("dst_port")
                    dst = f"{dst_ip}:{dst_port}" if dst_port else str(dst_ip)
                    resp_time = error.get("response_time_ms")
                    ts = error.get("request_timestamp", "")

                    frame_line = ""
                    if req_frame is not None and resp_frame is not None:
                        frame_line = f"**Request Frame:** `#{req_frame}` → **Response Frame:** `#{resp_frame}`  \n"
                    elif req_frame is not None:
                        frame_line = f"**Request Frame:** `#{req_frame}`  \n"
                    elif resp_frame is not None:
                        frame_line = f"**Response Frame:** `#{resp_frame}`  \n"

                    st.markdown(
                        f"**Status:** `{sc if sc is not None else 'N/A'}` — {meaning}  \n"
                        f"{frame_line}"
                        f"**URL:** `{method} http://{host}{uri}`  \n"
                        f"**Client → Server:** `{src}` → `{dst}`  \n"
                        f"**Response Time:** {f'{resp_time:.1f} ms' if resp_time else 'N/A'}  \n"
                        f"**Timestamp:** `{ts}`"
                    )
        else:
            st.markdown(
                UiThemeManager.success_badge_html("✅ Zero HTTP Errors Detected"),
                unsafe_allow_html=True,
            )

        st.divider()

        # ── Capture Summary cards ────────────────────────────────────────
        st.header("📋 Capture Summary")
        total_packets = summary.get("total_packets", 0)
        duration = summary.get("duration_seconds", 0)
        protocols: dict = summary.get("protocols", {})
        top_src_ips: list = summary.get("top_src_ips", [])

        top_ip = top_src_ips[0][0] if top_src_ips else "N/A"
        proto_count = len(protocols)

        c1, c2, c3, c4 = st.columns(4)
        cards = [
            (c1, "Total Packets", f"{total_packets:,}", ""),
            (c2, "Start Time", summary.get("start_time", "N/A")[:19].replace("T", " "), ""),
            (c3, "End Time", summary.get("end_time", "N/A")[:19].replace("T", " "), ""),
            (c4, "Duration", f"{duration:.2f}s", ""),
        ]
        for col, label, value, icon in cards:
            with col:
                card_html = UiThemeManager.metric_card_html(icon, label, value)
                st.markdown(card_html, unsafe_allow_html=True)

        st.divider()

        # ── Protocol Distribution ────────────────────────────────────────
        st.subheader("📡 Protocol Distribution")
        if protocols:
            proto_df = pd.DataFrame(
                list(protocols.items()), columns=["Protocol", "Count"]
            )
            fig_proto = px.pie(
                proto_df,
                names="Protocol",
                values="Count",
                hole=0.4,
                title="Protocol Breakdown",
            )
            fig_proto.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_proto, use_container_width=True)
        else:
            st.info("No protocol data available.")

        st.divider()

        # ── Top IPs table ────────────────────────────────────────────────
        st.subheader("🌐 Top IP Addresses")
        top_dst_ips: list = summary.get("top_dst_ips", [])

        col_src, col_dst = st.columns(2)
        with col_src:
            st.caption("**Top Source IPs**")
            if top_src_ips:
                src_df = pd.DataFrame(top_src_ips, columns=["Source IP", "Packets"])
                st.dataframe(src_df, use_container_width=True, hide_index=True)
            else:
                st.info("No data.")

        with col_dst:
            st.caption("**Top Destination IPs**")
            if top_dst_ips:
                dst_df = pd.DataFrame(top_dst_ips, columns=["Destination IP", "Packets"])
                st.dataframe(dst_df, use_container_width=True, hide_index=True)
            else:
                st.info("No data.")

    # ------------------------------------------------------------------ #
    #  Tab 2 — HTTP Transactions & Stream Inspector                        #
    # ------------------------------------------------------------------ #

    def _tab_http(self) -> None:
        """
        Description: Renders Tab 2 — the HTTP transaction table with filters (method, status,
                     host/URI search), and the Stream Inspector that shows full request/response
                     headers, body, POST parameters, and the raw TCP stream view.
        Input: None — reads from st.session_state (analyzer, selected_transaction)
        Output: None — renders all Tab 2 UI elements
        """
        analyzer: HttpStreamAnalyzer = st.session_state.analyzer
        transactions: list[dict] = analyzer.get_transactions() if analyzer else []

        st.header("🌐 HTTP Transactions")

        if not transactions:
            st.info("No HTTP transactions found in this capture.")
            return

        # ── Filter bar ──────────────────────────────────────────────────
        all_methods = sorted({t.get("method", "GET") for t in transactions})
        all_statuses = sorted({str(t.get("status_code", "")) for t in transactions if t.get("status_code")})

        fc1, fc2, fc3 = st.columns([2, 2, 3])
        with fc1:
            method_filter = st.multiselect(
                "Method", options=all_methods, default=[], placeholder="All methods"
            )
        with fc2:
            status_filter = st.multiselect(
                "Status Code", options=all_statuses, default=[], placeholder="All statuses"
            )
        with fc3:
            host_search = st.text_input("Search Host / URI", placeholder="e.g. api.example.com")

        # Apply filters
        filtered = transactions
        if method_filter:
            filtered = [t for t in filtered if t.get("method") in method_filter]
        if status_filter:
            filtered = [t for t in filtered if str(t.get("status_code", "")) in status_filter]
        if host_search.strip():
            q = host_search.strip().lower()
            filtered = [
                t for t in filtered
                if q in t.get("host", "").lower() or q in t.get("uri", "").lower()
            ]

        st.caption(f"Showing {len(filtered)} of {len(transactions)} transactions")

        # ── Transactions table ───────────────────────────────────────────
        if filtered:
            table_rows = []
            for i, txn in enumerate(filtered):
                table_rows.append(
                    {
                        "Index": i,
                        "Frame Req": txn.get("request_frame", ""),
                        "Frame Resp": txn.get("response_frame", ""),
                        "Method": txn.get("method", ""),
                        "Host": txn.get("host", ""),
                        "URI": txn.get("uri", "/"),
                        "Status": txn.get("status_code", ""),
                        "Resp Time (ms)": txn.get("response_time_ms", ""),
                        "Src IP": txn.get("src_ip", ""),
                        "Dst IP": txn.get("dst_ip", ""),
                        "Src Port": txn.get("src_port", ""),
                        "Dst Port": txn.get("dst_port", ""),
                    }
                )
            txn_df = pd.DataFrame(table_rows).set_index("Index")

            st.dataframe(
                txn_df,
                use_container_width=True,
                column_config={
                    "Status": st.column_config.NumberColumn(
                        "Status",
                        help="HTTP status code",
                        format="%d",
                    ),
                    "Resp Time (ms)": st.column_config.NumberColumn(
                        "Resp Time (ms)",
                        format="%.1f ms",
                    ),
                },
            )

            # ── Transaction selector ─────────────────────────────────────
            st.subheader("🔎 Stream Inspector")
            selector_options = {
                f"[{i}] {t.get('method','?')} {t.get('host','')}{t.get('uri','/')} → {t.get('status_code','?')}": i
                for i, t in enumerate(filtered)
            }
            selected_label = st.selectbox(
                "Select a transaction to inspect",
                options=list(selector_options.keys()),
                index=0,
                key="txn_selector",
            )
            selected_idx = selector_options[selected_label]
            st.session_state.selected_transaction = filtered[selected_idx]

        else:
            st.info("No transactions match the current filters.")
            st.session_state.selected_transaction = None

        # ── Stream Inspector detail pane ─────────────────────────────────
        txn = st.session_state.selected_transaction
        if txn:
            st.divider()
            status_code = txn.get("status_code", 0)
            st.markdown(
                UiThemeManager.status_badge_html(status_code),
                unsafe_allow_html=True,
            )

            req_col, resp_col = st.columns(2)

            with req_col:
                with st.expander("📤 Request Details", expanded=True):
                    req_headers = txn.get("request_headers", {})
                    st.caption("**Request Headers**")
                    st.json(req_headers)

                    # Show POST body / client payload clearly
                    request_body = txn.get("request_body", "")
                    if request_body.strip():
                        st.caption("**Client Payload / POST Data**")
                        st.code(request_body, language="text")

                    # Also show parsed POST parameters if URL-encoded form data
                    analyzer_ref: HttpStreamAnalyzer = st.session_state.get("analyzer")
                    if analyzer_ref:
                        post_params = analyzer_ref.get_post_params(txn)
                        if post_params:
                            st.caption("**Parsed POST Parameters**")
                            st.json(post_params)

            with resp_col:
                with st.expander("📥 Response Details", expanded=True):
                    resp_headers = txn.get("response_headers", {})
                    st.caption("**Response Headers**")
                    st.json(resp_headers)

                    body_preview = txn.get("response_body_preview", "")
                    if body_preview:
                        st.caption("**Response Body**")
                        st.code(body_preview, language="text")

    # ------------------------------------------------------------------ #
    #  Tab 3 — GeoIP Server Map                                           #
    # ------------------------------------------------------------------ #

    def _tab_geo(self) -> None:
        """
        Description: Renders Tab 3 — the GeoIP world map. On first visit, calls resolve_all()
                     to look up public IPs via ip-api.com. Shows an explanation about private
                     vs public IPs, the interactive scatter-geo map, and a country summary table.
        Input: None — reads from st.session_state (geo_mapper, geo_resolved, loader)
        Output: None — renders all Tab 3 UI elements
        """
        geo_mapper: GeoIpMapper = st.session_state.geo_mapper

        if geo_mapper is None:
            st.info("Load a capture file to enable GeoIP mapping.")
            return

        st.header("🗺️ GeoIP Server Map")

        st.info(
            "**Why are some IPs missing from the map?** "
            "Private/LAN IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x) and multicast "
            "addresses (224.x.x.x) are internal network addresses with no geographic location. "
            "Only **public** IP addresses are shown on the world map.",
            icon="ℹ️"
        )

        # Show all IPs split into public vs private
        all_raw = st.session_state.get("loader")
        if all_raw:
            raw_info = st.session_state.loader.get_raw_packets_info() if st.session_state.loader else []
            # Gather unique IPs from raw packets
            all_ips = set()
            for pkt in raw_info:
                if pkt.get("src_ip"): all_ips.add(pkt["src_ip"])
                if pkt.get("dst_ip"): all_ips.add(pkt["dst_ip"])

            public_ips = [ip for ip in all_ips if not geo_mapper._is_private_ip(ip)]
            private_ips = [ip for ip in all_ips if geo_mapper._is_private_ip(ip)]

            with st.expander(f"All Extracted IPs ({len(all_ips)} unique)", expanded=False):
                c_pub, c_priv = st.columns(2)
                with c_pub:
                    st.caption(f"**Public IPs ({len(public_ips)}) — mapped on world map**")
                    if public_ips:
                        st.dataframe(pd.DataFrame({"IP": sorted(public_ips)}), hide_index=True, use_container_width=True)
                with c_priv:
                    st.caption(f"**Private/Local IPs ({len(private_ips)}) — internal network, not on map**")
                    if private_ips:
                        st.dataframe(pd.DataFrame({"IP": sorted(private_ips)}), hide_index=True, use_container_width=True)

        # Lazy resolution
        if not st.session_state.geo_resolved:
            with st.spinner("🌍 Resolving IP geolocation…"):
                try:
                    geo_mapper.resolve_all()
                    st.session_state.geo_resolved = True
                except Exception as exc:  # noqa: BLE001
                    st.error(f"GeoIP resolution failed: {exc}")
                    return

        geo_data: list[dict] = geo_mapper.get_map_data()

        if not geo_data:
            st.warning("No geolocation data available.")
            return

        # Stats
        resolved_count = sum(1 for g in geo_data if g.get("lat") is not None)
        st.caption(f"✅ Resolved **{resolved_count}** of **{len(geo_data)}** unique IPs")

        error_msg = getattr(geo_mapper, "error_message", None)
        if error_msg:
            st.warning(f"⚠️ {error_msg}")

        # World map
        geo_df = pd.DataFrame(geo_data)
        required_cols = {"lat", "lon", "ip", "country"}
        if required_cols.issubset(set(geo_df.columns)):
            # Ensure packet_count column exists
            if "packet_count" not in geo_df.columns:
                geo_df["packet_count"] = 1

            hover_cols = [c for c in ["ip", "city", "isp", "org"] if c in geo_df.columns]

            fig_map = px.scatter_geo(
                geo_df,
                lat="lat",
                lon="lon",
                size="packet_count",
                color="country",
                hover_data=hover_cols,
                projection="natural earth",
                title="IP Geolocation Map",
            )
            fig_map.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            missing = required_cols - set(geo_df.columns)
            st.warning(f"Map unavailable — missing columns: {missing}")

        # Country summary table
        st.subheader("🏳️ Country Summary")
        country_summary = geo_mapper.get_country_summary()
        if country_summary:
            cs_df = pd.DataFrame(country_summary)
            st.dataframe(cs_df, use_container_width=True, hide_index=True)
        else:
            st.info("No country summary available.")

    # ------------------------------------------------------------------ #
    #  Tab 4 — AI Traffic Investigator                                     #
    # ------------------------------------------------------------------ #

    def _tab_ai(self) -> None:
        """
        Description: Renders Tab 4 — the AI Traffic Investigator. Lets the user select an
                     AI provider (OpenAI or Gemini), auto-configures using the .env key, shows
                     suggested questions, renders the full chat history with evidence boxes,
                     and handles new questions via the chat input widget.
        Input: None — reads from st.session_state (ai_assistant, chat_history, ai_context, loader)
        Output: None — renders all Tab 4 UI elements
        """
        ai_assistant: AiEvidenceAssistant | None = st.session_state.ai_assistant

        st.header("AI Traffic Investigator")

        # ── Gemini model selector & .env API key configuration ───────────
        from ai_evidence_assistant import DEFAULT_GEMINI_MODEL, GEMINI_MODELS  # noqa: PLC0415

        load_dotenv(override=True)

        default_idx = (
            GEMINI_MODELS.index(DEFAULT_GEMINI_MODEL)
            if DEFAULT_GEMINI_MODEL in GEMINI_MODELS
            else 0
        )
        selected_model = st.selectbox(
            "Gemini Model",
            options=GEMINI_MODELS,
            index=default_idx,
            key="gemini_model_select",
        )

        # Load GEMINI_API_KEY strictly from the local .env file (using dotenv and os.environ)
        env_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if env_key == "your_gemini_api_key_here":
            env_key = ""
        active_key = env_key

        # ── Auto-configure whenever model or key changes ─────────────────
        last_cfg = st.session_state.get("_last_gemini_cfg", "")
        cfg_sig = f"{selected_model}:{active_key}"
        if cfg_sig != last_cfg:
            st.session_state["gemini_invalid_key_error"] = False
            if active_key:
                try:
                    assistant = AiEvidenceAssistant()
                    assistant.configure(model=selected_model)
                    st.session_state.ai_assistant = assistant
                    st.session_state._last_gemini_cfg = cfg_sig
                except ValueError as e:
                    st.session_state.ai_assistant = None
                    st.warning(str(e))
            else:
                st.session_state.ai_assistant = None
                st.session_state._last_gemini_cfg = cfg_sig

        ai_assistant = st.session_state.ai_assistant

        # Guard — missing key or invalid key warning
        if not active_key or ai_assistant is None or not ai_assistant.is_configured():
            st.warning(
                "🔑 No Gemini API key found. API keys must not be entered via the UI — "
                "please configure GEMINI_API_KEY locally in the `.env` file in the root directory."
            )
            return

        if st.session_state.get("gemini_invalid_key_error", False):
            st.warning(
                "⚠️ Your Gemini API key in `.env` appears to be invalid or expired. "
                "Please update GEMINI_API_KEY locally in the `.env` file in the root directory."
            )

        loader: PacketCaptureLoader = st.session_state.loader
        summary = loader.get_summary() if loader else {}

        structured_json = st.session_state.get("structured_json") or st.session_state.get("ai_context") or "{}"

        system_prompt = f"""
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

        # ── Raw Data Expander ────────────────────────────────────────────
        with st.expander("🔍 View Raw Injected Data (JSON)"):
            st.json(structured_json)

        def _query_gemini_with_retry(question_text: str) -> None:
            st.session_state.chat_history.append({"role": "user", "content": question_text})
            response = None
            last_error = None
            with st.status("🤖 Analyzing network traffic...", expanded=True) as status:
                for attempt in range(1, 4):
                    try:
                        status.update(
                            label=f"🤖 Analyzing network traffic... (Attempt {attempt}/3)",
                            state="running",
                        )
                        st.write(f"Attempt {attempt}/3: Sending request to Gemini ({selected_model})...")
                        response = ai_assistant.ask(
                            question_text,
                            structured_json,
                            st.session_state.chat_history[:-1],
                            system_prompt=system_prompt,
                            raise_on_error=True,
                        )
                        status.update(
                            label=f"✅ Analysis complete (Attempt {attempt}/3)",
                            state="complete",
                            expanded=False,
                        )
                        break
                    except Exception as exc:  # noqa: BLE001
                        last_error = exc
                        if isinstance(exc, PermissionError):
                            st.session_state["gemini_invalid_key_error"] = True
                        st.write(f"⚠️ Attempt {attempt}/3 failed: {exc}")
                        if attempt < 3:
                            status.update(
                                label=f"🤖 Analyzing network traffic... (Attempt {attempt}/3 failed, retrying in 2s)",
                                state="running",
                            )
                            time.sleep(2)
                        else:
                            status.update(
                                label="❌ Analysis failed after 3 attempts.",
                                state="error",
                                expanded=True,
                            )

            if response is not None:
                if isinstance(response, dict):
                    answer_text = response.get("answer", str(response))
                else:
                    answer_text = str(response)
                st.session_state.chat_history.append(
                    {"role": "assistant", "content": answer_text}
                )
                st.rerun()
            else:
                st.error(
                    f"❌ Gemini API request failed after 3 attempts. Last error: {last_error}"
                )

        # ── Suggested questions ──────────────────────────────────────────
        suggested = ai_assistant.get_suggested_questions(summary) if hasattr(ai_assistant, "get_suggested_questions") else []

        if suggested:
            st.subheader("💡 Suggested Questions")
            pill_cols = st.columns(min(len(suggested), 3))
            for i, question in enumerate(suggested):
                with pill_cols[i % len(pill_cols)]:
                    if st.button(question, key=f"suggested_q_{i}", use_container_width=True):
                        _query_gemini_with_retry(question)

        st.divider()

        # ── Chat history ─────────────────────────────────────────────────
        st.subheader("💬 Conversation")
        chat_container = st.container()

        with chat_container:
            for message in st.session_state.chat_history:
                role = message.get("role", "user")
                content = message.get("content", "")
                if isinstance(content, dict):
                    content = content.get("answer", str(content))

                with st.chat_message(role):
                    if role == "assistant":
                        with st.container(border=True):
                            st.markdown(content)
                    else:
                        st.markdown(content)

        # ── Chat input ───────────────────────────────────────────────────
        user_input = st.chat_input("Ask anything about this capture…")
        if user_input:
            _query_gemini_with_retry(user_input)

    # ------------------------------------------------------------------ #
    #  Welcome screen                                                      #
    # ------------------------------------------------------------------ #

    def _render_welcome_screen(self) -> None:
        """
        Description: Renders the welcome/landing page shown before any PCAP file is uploaded.
                     Displays the app title, a short description, and three feature cards
                     (Error Hunter, GeoIP Map, AI Assistant) with upload instructions.
        Input: None
        Output: None — renders the welcome screen UI
        """
        st.markdown(
            """
            <div style="
                text-align: center;
                padding: 4rem 2rem 2rem;
            ">
                <div style="font-size: 5rem; margin-bottom: 1rem;">🔬</div>
                <h1 style="font-size: 2.8rem; font-weight: 800; margin-bottom: 0.5rem;">
                    Network Traffic AI Dashboard
                </h1>
                <p style="font-size: 1.15rem; opacity: 0.7; max-width: 640px; margin: 0 auto 2.5rem;">
                    Upload a <code>.pcap</code> or <code>.pcapng</code> capture file to automatically
                    detect HTTP errors, visualise traffic patterns on a world map, and interrogate
                    your data with AI-powered natural language analysis.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Feature cards
        fc1, fc2, fc3 = st.columns(3)
        feature_cards = [
            (
                fc1,
                "🚨",
                "Error Hunter",
                "Automatically surfaces all HTTP 4xx/5xx errors with request & response details, "
                "frame numbers, and one-click stream inspection.",
            ),
            (
                fc2,
                "🗺️",
                "GeoIP Map",
                "Resolves every unique server IP to its geographic location and plots an interactive "
                "world map showing traffic origin & destination.",
            ),
            (
                fc3,
                "🤖",
                "AI Assistant",
                "Ask plain-English questions about the capture. The AI reads packet summaries, "
                "HTTP transactions and error context to give evidence-backed answers.",
            ),
        ]

        for col, icon, title, desc in feature_cards:
            with col:
                st.markdown(
                    f"""
                    <div style="
                        border: 1px solid rgba(128,128,128,0.25);
                        border-radius: 12px;
                        padding: 1.5rem;
                        text-align: center;
                        height: 100%;
                    ">
                        <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">{icon}</div>
                        <h3 style="margin: 0 0 0.5rem;">{title}</h3>
                        <p style="opacity: 0.7; font-size: 0.9rem; margin: 0;">{desc}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<br>", unsafe_allow_html=True)

        # Upload instructions
        st.info(
            "👈 **Get started**: Upload a `.pcap` or `.pcapng` file using the sidebar on the left.",
            icon="📂",
        )


def main() -> None:
    DashboardController().run()


if __name__ == "__main__":
    main()
