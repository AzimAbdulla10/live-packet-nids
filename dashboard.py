import time
from datetime import datetime
import pandas as pd
import streamlit as st
from database import db
from config import DB_PATH

st.set_page_config(
    page_title="NIDS Live Telemetry",
    page_icon="🛡️",
    layout="wide"
)

# Custom minimal styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1e2130;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #4CAF50;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Intrusion Detection System — Telemetry Console")
st.caption(f"Real-time packet capture, hybrid rule + ML detections. Database: `{DB_PATH}`")

# Sidebar settings
with st.sidebar:
    st.header("⚙️ Controls")
    auto_refresh = st.checkbox("Auto-refresh (every 3s)", value=True)
    if st.button("🔄 Refresh Now"):
        st.rerun()

    st.markdown("---")
    st.subheader("Data Management")
    if st.button("🗑️ Clear Database Logs"):
        db.clear_database()
        st.success("Database cleared!")
        st.rerun()

    st.markdown("---")
    st.subheader("Quick Export")
    alerts_data = db.get_recent_alerts(limit=5000)
    if alerts_data:
        df_export = pd.DataFrame(alerts_data)
        csv_data = df_export.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV Report",
            data=csv_data,
            file_name=f"nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# Fetch stats from SQLite
stats = db.get_stats()

# KPI Metrics Row
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Packets Analyzed", f"{stats['total_packets']:,}")
col2.metric("Total Security Alerts", f"{stats['total_alerts']:,}")
col3.metric("Rule Engine Alerts", f"{stats['rule_alerts']:,}")
col4.metric("ML Engine Detections", f"{stats['ml_alerts']:,}")

st.markdown("---")

# Visualizations Row
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("🚨 Threat Type Breakdown")
    if stats["alert_breakdown"]:
        df_types = pd.DataFrame(stats["alert_breakdown"])
        st.bar_chart(df_types.set_index("alert_type")["count"])
    else:
        st.info("No security alerts logged yet.")

with col_right:
    st.subheader("🎯 Top Attacking Source IPs")
    if stats["top_attackers"]:
        df_attackers = pd.DataFrame(stats["top_attackers"])
        st.dataframe(df_attackers, use_container_width=True)
    else:
        st.info("No malicious IPs identified yet.")

st.markdown("---")

# Live Alerts Stream Table
st.subheader("🔴 Live Security Incidents Feed")
recent_alerts = db.get_recent_alerts(limit=100)

if recent_alerts:
    df_alerts = pd.DataFrame(recent_alerts)
    df_alerts["Time"] = df_alerts["timestamp"].apply(lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S"))
    
    # Filter by engine
    filter_engine = st.selectbox("Filter by Engine", ["All", "RULE", "ML"])
    if filter_engine != "All":
        df_alerts = df_alerts[df_alerts["engine"] == filter_engine]

    display_cols = ["Time", "engine", "severity", "alert_type", "src_ip", "details"]
    st.dataframe(
        df_alerts[display_cols].rename(columns={
            "engine": "Engine",
            "severity": "Severity",
            "alert_type": "Alert Type",
            "src_ip": "Source IP",
            "details": "Details"
        }),
        use_container_width=True,
        height=320
    )
else:
    st.write("No incidents currently active. Monitoring live traffic...")

# Auto refresh trigger
if auto_refresh:
    time.sleep(3)
    st.rerun()
