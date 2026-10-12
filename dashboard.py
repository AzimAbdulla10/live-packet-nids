import time
from datetime import datetime
import pandas as pd
import streamlit as st
from database import db
from config import DB_PATH

st.set_page_config(
    page_title="NIDS Security Telemetry",
    layout="wide"
)

# Custom enterprise styling
st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
    }
</style>
""", unsafe_allow_html=True)

st.title("Network Intrusion Detection System — Security Operations Console")
st.caption(f"Real-time packet inspection, signature rules, and machine learning inference. Database: {DB_PATH}")

# Sidebar controls
with st.sidebar:
    st.header("Console Controls")
    auto_refresh = st.checkbox("Auto-refresh (every 3s)", value=True)
    if st.button("Refresh Now"):
        st.rerun()

    st.markdown("---")
    st.subheader("Data Management")
    if st.button("Clear Incident Logs"):
        db.clear_database()
        st.success("Incident logs cleared from database.")
        st.rerun()

    st.markdown("---")
    st.subheader("Data Export")
    alerts_data = db.get_recent_alerts(limit=5000)
    if alerts_data:
        df_export = pd.DataFrame(alerts_data)
        csv_data = df_export.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download CSV Audit Report",
            data=csv_data,
            file_name=f"nids_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    flows_data = db.get_recent_flows(limit=5000)
    if flows_data:
        df_flows_export = pd.DataFrame(flows_data)
        csv_flows = df_flows_export.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Flow Summaries CSV",
            data=csv_flows,
            file_name=f"nids_flows_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# Fetch stats from SQLite
stats = db.get_stats()

# KPI Metrics Row
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Packets Analyzed", f"{stats['total_packets']:,}")
col2.metric("Total Alerts", f"{stats['total_alerts']:,}")
col3.metric("Rule Alerts", f"{stats['rule_alerts']:,}")
col4.metric("ML Threat Detections", f"{stats['ml_alerts']:,}")
col5.metric("Flows Tracked", f"{stats.get('total_flows', 0):,}")

st.markdown("---")

# Visualizations Row
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("Threat Breakdown by Classification")
    if stats["alert_breakdown"]:
        df_types = pd.DataFrame(stats["alert_breakdown"])
        st.bar_chart(df_types.set_index("alert_type")["count"])
    else:
        st.info("No security alerts logged yet.")

with col_right:
    st.subheader("Top Flagged Source Addresses")
    if stats["top_attackers"]:
        df_attackers = pd.DataFrame(stats["top_attackers"])
        st.dataframe(
            df_attackers.rename(columns={"src_ip": "Source IP", "alert_count": "Alert Count"}),
            use_container_width=True
        )
    else:
        st.info("No malicious addresses identified yet.")

st.markdown("---")

# Live Alerts Stream Table
st.subheader("Security Incidents Feed")
recent_alerts = db.get_recent_alerts(limit=100)

if recent_alerts:
    df_alerts = pd.DataFrame(recent_alerts)
    df_alerts["Time"] = df_alerts["timestamp"].apply(lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S"))
    
    filter_engine = st.selectbox("Filter by Engine", ["All", "RULE", "ML", "ANOMALY", "HYBRID"])
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
        height=300
    )
else:
    st.write("No incidents currently logged. Monitoring network interface...")

st.markdown("---")

# Network Flow Summaries Table
st.subheader("Network Flow Summaries")
recent_flows = db.get_recent_flows(limit=50)

if recent_flows:
    df_flows = pd.DataFrame(recent_flows)
    df_flows["Start Time"] = df_flows["start_time"].apply(lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S") if t else "-")
    df_flows["Duration (s)"] = df_flows["duration"].apply(lambda d: f"{d:.2f}" if d is not None else "0.00")
    
    flow_cols = ["Start Time", "protocol", "initiator_ip", "responder_ip", "initiator_port", "responder_port", "total_packets", "total_bytes", "Duration (s)", "finalization_reason"]
    display_flow_cols = [c for c in flow_cols if c in df_flows.columns]
    st.dataframe(
        df_flows[display_flow_cols].rename(columns={
            "protocol": "Protocol",
            "initiator_ip": "Initiator IP",
            "responder_ip": "Responder IP",
            "initiator_port": "Src Port",
            "responder_port": "Dst Port",
            "total_packets": "Packets",
            "total_bytes": "Bytes",
            "finalization_reason": "Reason"
        }),
        use_container_width=True,
        height=280
    )
else:
    st.write("No flow summaries recorded yet. Flows will appear upon finalization or timeout.")

# Auto refresh loop
if auto_refresh:
    time.sleep(3)
    st.rerun()
