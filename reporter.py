import sys
import argparse
import csv
from datetime import datetime
from database import db
from config import DB_PATH

def generate_text_summary() -> str:
    stats = db.get_stats()
    alerts = db.get_recent_alerts(limit=50)

    lines = []
    lines.append("=" * 65)
    lines.append("      NETWORK INTRUSION DETECTION SYSTEM - AUDIT REPORT      ")
    lines.append("=" * 65)
    lines.append(f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Database:     {DB_PATH}")
    lines.append("-" * 65)
    lines.append(f"Total Packets Analyzed:   {stats['total_packets']:,}")
    lines.append(f"Total Flows Tracked:      {stats.get('total_flows', 0):,}")
    lines.append(f"Total Security Alerts:    {stats['total_alerts']:,}")
    lines.append(f"  - Signature Rule Alerts: {stats['rule_alerts']:,}")
    lines.append(f"  - Machine Learning Alerts: {stats['ml_alerts']:,}")
    lines.append("-" * 65)

    lines.append("\n[TOP ATTACKING SOURCE IPs]")
    if stats["top_attackers"]:
        for i, att in enumerate(stats["top_attackers"], 1):
            lines.append(f"  {i}. {att['src_ip']:<18} | {att['alert_count']} alert(s)")
    else:
        lines.append("  No threats recorded yet.")

    lines.append("\n[THREAT TYPE BREAKDOWN]")
    if stats["alert_breakdown"]:
        for b in stats["alert_breakdown"]:
            lines.append(f"  - {b['alert_type']:<22}: {b['count']} incident(s)")
    else:
        lines.append("  No threats recorded yet.")

    lines.append("\n[RECENT INCIDENTS LOG]")
    if alerts:
        lines.append(f"{'TIME':<10} {'ENGINE':<6} {'SEVERITY':<10} {'TYPE':<18} {'SOURCE':<16} {'DETAILS'}")
        lines.append("-" * 95)
        for a in alerts[:25]:
            t_str = datetime.fromtimestamp(a["timestamp"]).strftime("%H:%M:%S")
            lines.append(
                f"{t_str:<10} {a['engine']:<6} {a['severity']:<10} {a['alert_type']:<18} {a['src_ip']:<16} {a['details'][:35]}"
            )
    else:
        lines.append("  No recent incidents logged.")

    lines.append("=" * 65)
    return "\n".join(lines)

def export_alerts_csv(output_path: str = "incident_report.csv"):
    alerts = db.get_recent_alerts(limit=5000)
    if not alerts:
        print("[WARN] No alerts found to export.")
        return

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Timestamp", "DateTime", "Engine", "Severity", "Alert Type", "Source IP", "Details"])
        for a in alerts:
            dt_str = datetime.fromtimestamp(a["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                a["id"],
                a["timestamp"],
                dt_str,
                a["engine"],
                a["severity"],
                a["alert_type"],
                a["src_ip"],
                a["details"]
            ])
    print(f"[SUCCESS] Exported {len(alerts)} alerts to: {output_path}")

def export_flows_csv(output_path: str = "flows_report.csv"):
    flows = db.get_recent_flows(limit=5000)
    if not flows:
        print("[WARN] No flow summaries found to export.")
        return

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Flow ID", "Protocol", "Initiator IP", "Responder IP",
            "Src Port", "Dst Port", "Start Time", "Last Seen", "Duration",
            "Total Packets", "Fwd Packets", "Bwd Packets", "Total Bytes",
            "Flow Bytes/s", "Flow Pkts/s", "SYN Count", "Reason"
        ])
        for fl in flows:
            writer.writerow([
                fl.get("id"),
                fl.get("flow_id"),
                fl.get("protocol"),
                fl.get("initiator_ip"),
                fl.get("responder_ip"),
                fl.get("initiator_port"),
                fl.get("responder_port"),
                fl.get("start_time"),
                fl.get("last_seen"),
                fl.get("duration"),
                fl.get("total_packets"),
                fl.get("fwd_packets"),
                fl.get("bwd_packets"),
                fl.get("total_bytes"),
                fl.get("flow_bytes_s"),
                fl.get("flow_pkts_s"),
                fl.get("syn_count"),
                fl.get("finalization_reason")
            ])
    print(f"[SUCCESS] Exported {len(flows)} flow summaries to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="NIDS Security Incident Reporting Tool")
    parser.add_argument("--summary", action="store_true", help="Print audit report summary to console")
    parser.add_argument("--export-csv", type=str, nargs="?", const="incident_report.csv", help="Export alerts to CSV")
    parser.add_argument("--export-flows", type=str, nargs="?", const="flows_report.csv", help="Export flow summaries to CSV")
    parser.add_argument("--export-text", type=str, nargs="?", const="audit_summary.txt", help="Export summary to text file")

    args = parser.parse_args()

    if len(sys.argv) == 1 or args.summary:
        print(generate_text_summary())

    if args.export_csv:
        export_alerts_csv(args.export_csv)

    if args.export_flows:
        export_flows_csv(args.export_flows)

    if args.export_text:
        content = generate_text_summary()
        with open(args.export_text, "w") as f:
            f.write(content)
        print(f"[SUCCESS] Saved summary to: {args.export_text}")

if __name__ == "__main__":
    main()
