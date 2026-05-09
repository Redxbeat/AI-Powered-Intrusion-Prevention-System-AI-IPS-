"""
=============================================================
AI-IPS Real-Time Dashboard
=============================================================
JARVIS-themed cybersecurity monitoring dashboard.
Displays live traffic, threats, blocked IPs, and more.
=============================================================
"""

import sys
import os
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from modules.logger_db import ThreatLogger
from modules.firewall import FirewallManager
from config.settings import DATABASE_PATH, ASSETS_DIR

# ── Page Configuration ──────────────────────────────────────
st.set_page_config(
    page_title="AI-IPS | Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── JARVIS CSS Theme ────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap');

    /* Main background with grid pattern */
    .stApp {
        background: #0a0e17;
        background-image:
            linear-gradient(rgba(0, 212, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 212, 255, 0.03) 1px, transparent 1px);
        background-size: 50px 50px;
    }

    /* Header styling */
    .main-title {
        font-family: 'Orbitron', monospace;
        font-size: 2.5rem;
        font-weight: 900;
        text-align: center;
        background: linear-gradient(135deg, #00d4ff 0%, #00ff88 50%, #00d4ff 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 30px rgba(0, 212, 255, 0.5);
        padding: 10px 0;
        letter-spacing: 3px;
        animation: glow 2s ease-in-out infinite alternate;
    }

    @keyframes glow {
        from { filter: drop-shadow(0 0 5px rgba(0, 212, 255, 0.3)); }
        to { filter: drop-shadow(0 0 20px rgba(0, 212, 255, 0.6)); }
    }

    .sub-title {
        font-family: 'Share Tech Mono', monospace;
        text-align: center;
        color: #4a9eff;
        font-size: 0.85rem;
        letter-spacing: 5px;
        text-transform: uppercase;
        margin-bottom: 20px;
    }

    /* KPI Card styling */
    .kpi-card {
        background: linear-gradient(145deg, #111827 0%, #0d1321 100%);
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: linear-gradient(90deg, transparent, #00d4ff, transparent);
    }
    .kpi-card:hover {
        border-color: rgba(0, 212, 255, 0.5);
        box-shadow: 0 0 25px rgba(0, 212, 255, 0.15);
        transform: translateY(-2px);
    }
    .kpi-value {
        font-family: 'Orbitron', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #00d4ff;
    }
    .kpi-value.danger { color: #ff4757; }
    .kpi-value.success { color: #00ff88; }
    .kpi-value.warning { color: #ffa502; }
    .kpi-label {
        font-family: 'Share Tech Mono', monospace;
        color: #8892a4;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-top: 8px;
    }

    /* Section headers */
    .section-header {
        font-family: 'Orbitron', monospace;
        color: #00d4ff;
        font-size: 1.1rem;
        border-bottom: 1px solid rgba(0, 212, 255, 0.2);
        padding-bottom: 8px;
        margin: 25px 0 15px 0;
        letter-spacing: 2px;
    }

    /* Table styling */
    .threat-table {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
    }

    /* Status indicator */
    .status-online {
        display: inline-block;
        width: 10px; height: 10px;
        background: #00ff88;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 5px #00ff88; }
        50% { opacity: 0.5; box-shadow: 0 0 15px #00ff88; }
    }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    .stDeployButton { display: none; }

    /* Blocked IP card */
    .blocked-ip-card {
        background: rgba(255, 71, 87, 0.1);
        border: 1px solid rgba(255, 71, 87, 0.3);
        border-radius: 8px;
        padding: 10px 15px;
        margin: 5px 0;
        font-family: 'Share Tech Mono', monospace;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Plotly chart background override */
    .js-plotly-plot .plotly .bg { fill: transparent !important; }
</style>
""", unsafe_allow_html=True)


# ── Initialize Services ─────────────────────────────────────
@st.cache_resource
def get_logger():
    return ThreatLogger()

@st.cache_resource
def get_firewall():
    return FirewallManager()

logger = get_logger()
firewall = get_firewall()


# ── Plotly Theme ────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono, monospace", color="#8892a4"),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor="rgba(0,212,255,0.08)", zerolinecolor="rgba(0,212,255,0.08)"),
    yaxis=dict(gridcolor="rgba(0,212,255,0.08)", zerolinecolor="rgba(0,212,255,0.08)"),
)

COLORS = {
    "cyan": "#00d4ff",
    "green": "#00ff88",
    "red": "#ff4757",
    "orange": "#ffa502",
    "purple": "#a855f7",
    "blue": "#3b82f6",
}


# ══════════════════════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════════════════════
st.markdown('<div class="main-title">🛡️ AI-IPS THREAT MONITOR</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title"><span class="status-online"></span>System Online &nbsp;|&nbsp; Intrusion Prevention Active</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  KPI CARDS (auto-refresh)
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=3)
def render_kpi_cards():
    stats = logger.get_stats_count()

    c1, c2, c3, c4, c5, c6 = st.columns(6)

    with c1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value">{stats['total_packets']:,}</div>
            <div class="kpi-label">Total Packets</div>
        </div>""", unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value success">{stats['normal_packets']:,}</div>
            <div class="kpi-label">Normal Traffic</div>
        </div>""", unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value danger">{stats['malicious_packets']:,}</div>
            <div class="kpi-label">Malicious</div>
        </div>""", unsafe_allow_html=True)

    with c4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value warning">{stats['total_threats']:,}</div>
            <div class="kpi-label">Threats Detected</div>
        </div>""", unsafe_allow_html=True)

    with c5:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value danger">{stats['blocked_ips']:,}</div>
            <div class="kpi-label">IPs Blocked</div>
        </div>""", unsafe_allow_html=True)

    with c6:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value" style="color: #a855f7;">{stats.get('connected_clients', 0):,}</div>
            <div class="kpi-label">Connected Clients</div>
        </div>""", unsafe_allow_html=True)

render_kpi_cards()


# ══════════════════════════════════════════════════════════════
#  LIVE TRAFFIC CHART
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=5)
def render_traffic_chart():
    st.markdown('<div class="section-header">📊 LIVE TRAFFIC ANALYSIS</div>',
                unsafe_allow_html=True)

    traffic_data = logger.get_traffic_stats(limit=60)

    if traffic_data:
        df = pd.DataFrame(traffic_data)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["timestamp"], y=df["normal_count"],
            name="Normal", mode="lines+markers",
            line=dict(color=COLORS["green"], width=2),
            marker=dict(size=4),
            fill="tozeroy",
            fillcolor="rgba(0, 255, 136, 0.05)",
        ))
        fig.add_trace(go.Scatter(
            x=df["timestamp"], y=df["malicious_count"],
            name="Malicious", mode="lines+markers",
            line=dict(color=COLORS["red"], width=2),
            marker=dict(size=4),
            fill="tozeroy",
            fillcolor="rgba(255, 71, 87, 0.05)",
        ))
        fig.update_layout(
            **PLOTLY_LAYOUT,
            height=350,
            legend=dict(
                orientation="h", yanchor="top", y=1.12,
                font=dict(color="#e0e6ed")
            ),
            hovermode="x unified",
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("⏳ Waiting for traffic data... Start the IDS engine first.")

render_traffic_chart()


# ══════════════════════════════════════════════════════════════
#  ATTACK DISTRIBUTION + TOP ATTACKERS
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=5)
def render_analysis_charts():
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="section-header">🎯 ATTACK CLASSIFICATION</div>',
                    unsafe_allow_html=True)
        attack_data = logger.get_attack_summary()
        if attack_data:
            df = pd.DataFrame(attack_data)
            color_map = {
                "Port Scan": COLORS["cyan"],
                "Brute Force": COLORS["orange"],
                "SYN Flood": COLORS["red"],
                "High Rate Anomaly": COLORS["purple"],
                "ML Detected": COLORS["blue"],
            }
            colors = [color_map.get(t, COLORS["cyan"]) for t in df["attack_type"]]

            fig = go.Figure(data=[go.Pie(
                labels=df["attack_type"],
                values=df["count"],
                hole=0.55,
                marker=dict(colors=colors, line=dict(color="#0a0e17", width=2)),
                textfont=dict(family="Share Tech Mono", color="#e0e6ed"),
            )])
            fig.update_layout(
                **PLOTLY_LAYOUT,
                height=350,
                showlegend=True,
                legend=dict(font=dict(color="#e0e6ed")),
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No attacks detected yet.")

    with col2:
        st.markdown('<div class="section-header">🏴‍☠️ TOP ATTACKER IPs</div>',
                    unsafe_allow_html=True)
        attacker_data = logger.get_top_attackers(limit=10)
        if attacker_data:
            df = pd.DataFrame(attacker_data)
            fig = go.Figure(data=[go.Bar(
                y=df["src_ip"],
                x=df["count"],
                orientation="h",
                marker=dict(
                    color=df["count"],
                    colorscale=[[0, COLORS["cyan"]], [1, COLORS["red"]]],
                ),
                text=df["count"],
                textposition="outside",
                textfont=dict(family="Orbitron", color="#e0e6ed"),
            )])
            fig.update_layout(**PLOTLY_LAYOUT, height=350)
            fig.update_layout(yaxis=dict(autorange="reversed", gridcolor="rgba(0,212,255,0.08)"))
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No attackers recorded yet.")

render_analysis_charts()


# ══════════════════════════════════════════════════════════════
#  THREAT LOG TABLE
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=3)
def render_threat_logs():
    st.markdown('<div class="section-header">📋 THREAT LOG</div>',
                unsafe_allow_html=True)

    threats = logger.get_recent_threats(limit=50)
    if threats:
        df = pd.DataFrame(threats)
        display_cols = ["timestamp", "src_ip", "dst_ip", "attack_type",
                        "confidence", "action_taken"]
        display_df = df[[c for c in display_cols if c in df.columns]].copy()

        if "confidence" in display_df.columns:
            display_df["confidence"] = display_df["confidence"].apply(
                lambda x: f"{x:.1%}" if pd.notna(x) else "N/A"
            )
        if "timestamp" in display_df.columns:
            display_df["timestamp"] = pd.to_datetime(
                display_df["timestamp"]
            ).dt.strftime("%H:%M:%S")

        # Color-code by attack type
        st.dataframe(
            display_df,
            width="stretch",
            height=400,
            column_config={
                "timestamp": st.column_config.TextColumn("Time", width=80),
                "src_ip": st.column_config.TextColumn("Source IP", width=130),
                "dst_ip": st.column_config.TextColumn("Dest IP", width=130),
                "attack_type": st.column_config.TextColumn("Attack Type", width=140),
                "confidence": st.column_config.TextColumn("Confidence", width=90),
                "action_taken": st.column_config.TextColumn("Action", width=80),
            },
        )
    else:
        st.info("No threats logged yet. System is monitoring...")

render_threat_logs()


# ══════════════════════════════════════════════════════════════
#  BLOCKED IPs + UNBLOCK BUTTONS
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=5)
def render_blocked_ips():
    st.markdown('<div class="section-header">🚫 BLOCKED IPs</div>',
                unsafe_allow_html=True)

    blocked = logger.get_blocked_ips(active_only=True)

    if blocked:
        for idx, entry in enumerate(blocked):
            ip = entry["ip"]
            reason = entry.get("reason", "N/A")
            blocked_at = entry.get("blocked_at", "N/A")

            col1, col2, col3, col4 = st.columns([3, 3, 3, 2])
            with col1:
                st.markdown(f"🔴 **{ip}**")
            with col2:
                st.caption(f"Reason: {reason}")
            with col3:
                st.caption(f"Blocked: {blocked_at[:19]}")
            with col4:
                if st.button("🔓 Unblock", key=f"unblock_{ip}_{idx}"):
                    fw_ok = firewall.unblock_ip(ip)
                    # Always mark as unblocked in DB regardless of firewall result
                    logger.log_unblock(ip)
                    if fw_ok:
                        st.success(f"✅ Unblocked {ip}")
                    else:
                        st.info(
                            f"✅ {ip} removed from block list.  \n"
                            "ℹ️ OS firewall rule needs **Administrator** privileges to remove."
                        )
                    st.rerun()
    else:
        st.success("✅ No IPs currently blocked.")

render_blocked_ips()


# ══════════════════════════════════════════════════════════════
#  WHITELIST MANAGEMENT
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=10)
def render_whitelist():
    import re
    import config.settings as _cfg
    from config.settings import WHITELISTED_IPS

    st.markdown('<div class="section-header">🛡️ WHITELISTED IPs</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; color:#8892a4;
                font-size:0.8rem; margin-bottom:12px;">
        Whitelisted IPs are <b style="color:#00ff88">monitored but NEVER blocked</b>
        by the firewall, even if they trigger attack detection.
    </div>
    """, unsafe_allow_html=True)

    # Categorise IPs for display
    categories = {
        "Loopback / Any":  ["127.0.0.1", "0.0.0.0", "255.255.255.255", "::1"],
        "This Server":     ["10.114.159.152"],
        "DNS Servers":     ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"],
        "Gateways":        ["192.168.0.1", "192.168.1.1", "10.0.0.1", "10.114.159.1"],
        "Custom":          [],
    }
    known = {ip for ips in categories.values() for ip in ips}
    categories["Custom"] = [ip for ip in sorted(WHITELISTED_IPS) if ip not in known]

    for cat, ips in categories.items():
        ips_in = [ip for ip in ips if ip in WHITELISTED_IPS]
        if not ips_in:
            continue
        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace; color:#4a9eff;
                    font-size:0.75rem; letter-spacing:1px; margin:10px 0 4px 0;">
            {cat.upper()}
        </div>""", unsafe_allow_html=True)

        for ip in ips_in:
            c1, c2 = st.columns([8, 1])
            with c1:
                st.markdown(f"""
                <div style="background:rgba(0,255,136,0.05);
                            border:1px solid rgba(0,255,136,0.2);
                            border-radius:6px; padding:6px 14px; margin:2px 0;
                            font-family:'Share Tech Mono',monospace;
                            color:#00ff88; font-size:0.85rem;">
                    🛡️ {ip}
                </div>""", unsafe_allow_html=True)
            with c2:
                essential = ip in ("127.0.0.1", "0.0.0.0", "::1", "255.255.255.255")
                if not essential:
                    if st.button("✖", key=f"wl_rm_{ip}",
                                 help=f"Remove {ip} from whitelist"):
                        _cfg.WHITELISTED_IPS.discard(ip)
                        st.toast(f"🗑️ {ip} removed from whitelist")
                        st.rerun()

    # Add new IP
    st.markdown("---")
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; color:#4a9eff;
                font-size:0.75rem; letter-spacing:1px; margin-bottom:6px;">
        ADD IP TO WHITELIST
    </div>""", unsafe_allow_html=True)

    wa, wb = st.columns([5, 1])
    with wa:
        new_ip = st.text_input(
            "IP", placeholder="e.g. 192.168.1.100",
            label_visibility="collapsed", key="wl_new_ip"
        )
    with wb:
        if st.button("➕ Add", key="wl_add", type="primary"):
            ip_ok = re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$",
                             (new_ip or "").strip())
            if ip_ok:
                _cfg.WHITELISTED_IPS.add(new_ip.strip())
                st.toast(f"✅ {new_ip.strip()} added to whitelist", icon="🛡️")
                st.rerun()
            else:
                st.error("Enter a valid IP address.")

    st.caption(
        "⚠️ Runtime changes apply to this session only. "
        "To make permanent, edit WHITELISTED_IPS in config/settings.py"
    )

render_whitelist()



@st.fragment(run_every=5)
def render_usb_monitor():
    st.markdown('<div class="section-header">🔌 USB DEVICE MONITOR</div>',
                unsafe_allow_html=True)

    # Get current USB devices via WMI (live scan)
    usb_devices = []
    try:
        import wmi
        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            if "USB" in (disk.InterfaceType or ""):
                usb_devices.append({
                    "device_id": disk.PNPDeviceID or "Unknown",
                    "description": disk.Caption or "USB Device",
                    "size": f"{int(disk.Size or 0) / (1024**3):.1f} GB" if disk.Size else "N/A",
                    "status": disk.Status or "Unknown",
                })
        for usb in c.Win32_USBHub():
            usb_devices.append({
                "device_id": usb.DeviceID or "Unknown",
                "description": usb.Description or "USB Hub/Device",
                "size": "—",
                "status": usb.Status or "Unknown",
            })
    except ImportError:
        pass
    except Exception:
        pass

    # Also show logged USB events from DB
    usb_events = logger.get_usb_events(limit=10)

    if usb_devices:
        st.markdown(f"""
        <div style="
            font-family: 'Share Tech Mono', monospace;
            color: #00ff88; font-size: 0.85rem;
            margin-bottom: 10px;
        ">🟢 {len(usb_devices)} USB device(s) currently connected</div>
        """, unsafe_allow_html=True)

        for idx, dev in enumerate(usb_devices):
            is_storage = "GB" in dev["size"]
            icon = "💾" if is_storage else "🔌"
            border_color = "rgba(0, 255, 136, 0.3)" if dev["status"] == "OK" else "rgba(255, 71, 87, 0.3)"

            st.markdown(f"""
            <div style="
                background: linear-gradient(145deg, #111827 0%, #0d1321 100%);
                border: 1px solid {border_color};
                border-radius: 10px;
                padding: 12px 16px;
                margin: 6px 0;
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-family: 'Share Tech Mono', monospace;
            ">
                <div>
                    <span style="font-size: 1.1rem;">{icon}</span>
                    <span style="color: #e0e6ed; font-weight: bold; margin-left: 8px;">{dev['description']}</span>
                </div>
                <div style="display: flex; gap: 20px; align-items: center;">
                    <span style="color: #4a9eff; font-size: 0.75rem;">{dev['size']}</span>
                    <span style="
                        color: {'#00ff88' if dev['status'] == 'OK' else '#ff4757'};
                        font-size: 0.75rem;
                        padding: 2px 10px;
                        border-radius: 12px;
                        background: {'rgba(0,255,136,0.1)' if dev['status'] == 'OK' else 'rgba(255,71,87,0.1)'};
                    ">{dev['status']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander(f"Device ID: {dev['device_id'][:50]}...", expanded=False):
                st.code(dev["device_id"], language=None)
    else:
        st.markdown("""
        <div style="
            background: rgba(74, 158, 255, 0.05);
            border: 1px solid rgba(74, 158, 255, 0.2);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            font-family: 'Share Tech Mono', monospace;
            color: #4a9eff; font-size: 0.85rem;
        ">ℹ️ No USB storage devices detected (WMI module may not be installed)</div>
        """, unsafe_allow_html=True)

    # Show recent USB event history
    if usb_events:
        st.markdown("""
        <div style="color: #8892a4; font-family: 'Share Tech Mono'; font-size: 0.8rem;
                    margin-top: 15px; letter-spacing: 1px;">RECENT USB EVENTS</div>
        """, unsafe_allow_html=True)
        for ev in usb_events[:5]:
            auth_icon = "🟢" if ev.get("is_authorized") else "🔴"
            ts = ev.get("timestamp", "")[:19]
            st.markdown(f"""
            <div style="
                font-family: 'Share Tech Mono', monospace;
                font-size: 0.75rem; color: #8892a4;
                padding: 4px 0;
                border-bottom: 1px solid rgba(0,212,255,0.05);
            ">{auth_icon} {ts} — {ev.get('description', 'Unknown')} [{ev.get('event_type', 'unknown')}]</div>
            """, unsafe_allow_html=True)

render_usb_monitor()


# ══════════════════════════════════════════════════════════════
#  CONNECTED SYSTEMS MONITOR
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=5)
def render_connected_systems():
    st.markdown('<div class="section-header">🖥️ CONNECTED SYSTEMS</div>',
                unsafe_allow_html=True)

    clients = logger.get_connected_clients()

    if clients:
        st.markdown(f"""
        <p style="
            font-family: 'Share Tech Mono', monospace;
            color: #a855f7; font-size: 0.85rem;
            margin-bottom: 12px;
        ">🌐 {len(clients)} system(s) connected to this server</p>
        """, unsafe_allow_html=True)

        # Create a row of client cards (2 per row)
        for i in range(0, len(clients), 2):
            cols = st.columns(2)
            for j, col in enumerate(cols):
                if i + j < len(clients):
                    client = clients[i + j]
                    ip = client["ip"]
                    mac = client.get("mac", "Unknown")
                    hostname = client.get("hostname", "") or "—"
                    pkts_sent = client.get("packets_sent", 0)
                    pkts_recv = client.get("packets_received", 0)
                    bytes_sent = client.get("bytes_sent", 0)
                    bytes_recv = client.get("bytes_received", 0)
                    last_seen = client.get("last_seen", "")[:19]

                    def fmt_bytes(b):
                        if b > 1024 * 1024:
                            return f"{b / (1024*1024):.1f} MB"
                        elif b > 1024:
                            return f"{b / 1024:.1f} KB"
                        return f"{b} B"

                    total_traffic = fmt_bytes(bytes_sent + bytes_recv)
                    dns_queries = logger.get_client_dns_queries(client_ip=ip, limit=8)
                    device_vendor = client.get("device_vendor", "Unknown")
                    os_guess = client.get("os_guess", "Unknown")
                    protocol_stats = client.get("protocol_stats", {})
                    top_ports = client.get("top_ports", [])

                    with col:
                        with st.container(border=True):
                            # ── Header: IP + Traffic + Remove button ──────────
                            h1, h2, h3 = st.columns([3, 2, 1])
                            with h1:
                                st.markdown(f"**🖥️ {ip}**")
                                st.caption(f"{hostname}")
                            with h2:
                                st.markdown(f"""
                                <p style="text-align: right; font-family: 'Share Tech Mono', monospace;
                                          color: #a855f7; font-size: 0.8rem; margin: 0;">
                                    {total_traffic}<br>
                                    <span style="color: #4a5568; font-size: 0.7rem;">{last_seen}</span>
                                </p>""", unsafe_allow_html=True)
                            with h3:
                                # ── BLOCK & REMOVE BUTTON ─────────────────────
                                btn_key = f"remove_client_{ip}_{i}_{j}"
                                if st.button("🚫 Block", key=btn_key,
                                             help=f"Block {ip} via firewall and remove from dashboard",
                                             type="primary"):
                                    fw_ok = firewall.block_ip(ip, reason=f"Manual block from dashboard")
                                    logger.log_block(ip, reason="Manually blocked from dashboard")
                                    logger.remove_client(ip)   # Wipe from DB immediately
                                    if fw_ok:
                                        st.toast(f"🚫 {ip} blocked and removed!", icon="🔒")
                                    else:
                                        st.toast(f"⚠️ {ip} removed from dashboard (firewall needs Admin)", icon="⚠️")
                                    st.rerun()

                            # Badges: Vendor & OS
                            st.markdown(f"""
                            <div style="margin-bottom: 8px;">
                                <span style="background: rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; margin-right: 5px;">🏭 {device_vendor}</span>
                                <span style="background: rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">🖥️ {os_guess}</span>
                            </div>
                            """, unsafe_allow_html=True)

                            # Stats row
                            s1, s2, s3 = st.columns(3)
                            with s1:
                                st.caption(f"MAC: `{mac}`")
                            with s2:
                                st.markdown(f"<span style='color:#00ff88; font-family: monospace; font-size:0.8rem;'>↑ {pkts_sent:,} pkts</span>", unsafe_allow_html=True)
                            with s3:
                                st.markdown(f"<span style='color:#00d4ff; font-family: monospace; font-size:0.8rem;'>↓ {pkts_recv:,} pkts</span>", unsafe_allow_html=True)

                            # Protocol breakdown
                            if protocol_stats:
                                p_str = " | ".join([f"{k}:{v}%" for k, v in protocol_stats.items() if v > 0])
                                st.markdown(f"<div style='font-size: 0.75rem; color: #8892a4; margin-bottom: 8px;'>Protocols: {p_str}</div>", unsafe_allow_html=True)

                            # Top Ports
                            if top_ports:
                                ports_tags = ""
                                for p in top_ports:
                                    ports_tags += f"<span style='background: rgba(255, 71, 87, 0.15); border: 1px solid rgba(255, 71, 87, 0.3); border-radius: 4px; padding: 2px 6px; margin: 2px; font-size: 0.7rem; color: #ff4757;'>{p['label']} ({p['port']})</span>"
                                st.markdown(f"<div style='margin-bottom: 8px;'>{ports_tags}</div>", unsafe_allow_html=True)

                            # Visited sites
                            st.markdown("---")
                            st.caption("VISITED SITES")
                            if dns_queries:
                                domain_tags = ""
                                for d in dns_queries[:8]:
                                    domain_tags += f"""<span style="
                                        display: inline-block;
                                        background: rgba(74, 158, 255, 0.15);
                                        border: 1px solid rgba(74, 158, 255, 0.3);
                                        border-radius: 6px;
                                        padding: 2px 8px;
                                        margin: 2px;
                                        font-size: 0.75rem;
                                        color: #4a9eff;
                                        font-family: 'Share Tech Mono', monospace;
                                    ">{d['domain']}</span>"""
                                st.markdown(domain_tags, unsafe_allow_html=True)
                            else:
                                st.caption("No DNS activity recorded")
    else:
        st.info("⏳ No active clients. Connect a device and start the IDS engine.")

render_connected_systems()


# ══════════════════════════════════════════════════════════════
#  SOUND ALERT (HTML Audio for new threats)
# ══════════════════════════════════════════════════════════════
@st.fragment(run_every=5)
def check_new_threats():
    """Check for very recent threats and play alert sound."""
    threats = logger.get_recent_threats(limit=1)
    if threats:
        last_threat = threats[0]
        ts = datetime.fromisoformat(last_threat["timestamp"])
        age = (datetime.now() - ts).total_seconds()
        if age < 6:  # Threat within last 6 seconds
            st.toast(
                f"⚠️ THREAT: {last_threat['attack_type']} from "
                f"{last_threat['src_ip']}",
                icon="🚨"
            )

check_new_threats()


# ══════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("""
<div style="text-align: center; font-family: 'Share Tech Mono', monospace;
            color: #4a5568; font-size: 0.75rem;">
    AI-IPS v2.0 &nbsp;|&nbsp; Powered by Random Forest ML &nbsp;|&nbsp;
    Real-Time Threat Detection &amp; Prevention<br>
    System Time: <span id="clock"></span>
</div>
<script>
    function updateClock() {
        document.getElementById('clock').textContent =
            new Date().toLocaleTimeString();
    }
    setInterval(updateClock, 1000);
    updateClock();
</script>
""", unsafe_allow_html=True)
