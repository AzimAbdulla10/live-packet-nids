import sqlite3
import time
from typing import List, Dict, Any, Optional
from config import DB_PATH

class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._memory_conn = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", timeout=30.0, check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    flags TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    alert_type TEXT,
                    severity TEXT,
                    engine TEXT,
                    src_ip TEXT,
                    details TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    packets_per_sec REAL,
                    total_alerts INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT,
                    protocol TEXT,
                    initiator_ip TEXT,
                    responder_ip TEXT,
                    initiator_port INTEGER,
                    responder_port INTEGER,
                    start_time REAL,
                    last_seen REAL,
                    duration REAL,
                    total_packets INTEGER,
                    fwd_packets INTEGER,
                    bwd_packets INTEGER,
                    total_bytes INTEGER,
                    fwd_bytes INTEGER,
                    bwd_bytes INTEGER,
                    flow_bytes_s REAL,
                    flow_pkts_s REAL,
                    syn_count INTEGER,
                    finalization_reason TEXT,
                    UNIQUE(flow_id, start_time, last_seen)
                )
            """)
            # Create indexes for fast lookup during dashboard queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_time ON flow_summaries(start_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_id ON flow_summaries(flow_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src ON flow_summaries(initiator_ip)")
            conn.commit()

    def insert_packet(self, pkt: Dict[str, Any]):
        if not pkt:
            return
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pkt.get("timestamp", time.time()),
                pkt.get("src_ip"),
                pkt.get("dst_ip"),
                pkt.get("src_port"),
                pkt.get("dst_port"),
                pkt.get("protocol"),
                pkt.get("length", 0),
                pkt.get("flags", "")
            ))
            conn.commit()

    def insert_packets_batch(self, packets: List[Dict[str, Any]]):
        if not packets:
            return
        rows = [
            (
                p.get("timestamp", time.time()),
                p.get("src_ip"),
                p.get("dst_ip"),
                p.get("src_port"),
                p.get("dst_port"),
                p.get("protocol"),
                p.get("length", 0),
                p.get("flags", "")
            )
            for p in packets if p
        ]
        with self._get_connection() as conn:
            conn.executemany("""
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()

    def insert_alert(self, alert_type: str, severity: str, engine: str, src_ip: str, details: str):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (timestamp, alert_type, severity, engine, src_ip, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                time.time(),
                alert_type,
                severity,
                engine,
                src_ip,
                details
            ))
            conn.commit()

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, engine, src_ip, details
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags
                FROM packets
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def insert_flow_summary(self, flow: Dict[str, Any], finalization_reason: str = "unknown") -> bool:
        if not flow:
            return False
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO flow_summaries (
                        flow_id, protocol, initiator_ip, responder_ip,
                        initiator_port, responder_port, start_time, last_seen,
                        duration, total_packets, fwd_packets, bwd_packets,
                        total_bytes, fwd_bytes, bwd_bytes, flow_bytes_s,
                        flow_pkts_s, syn_count, finalization_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get("flow_id"),
                    flow.get("protocol"),
                    flow.get("initiator_ip"),
                    flow.get("responder_ip"),
                    flow.get("initiator_port"),
                    flow.get("responder_port"),
                    flow.get("start_time"),
                    flow.get("last_seen"),
                    flow.get("duration", 0.0),
                    flow.get("total_packets", 0),
                    flow.get("fwd_packets", 0),
                    flow.get("bwd_packets", 0),
                    flow.get("total_bytes", 0),
                    flow.get("fwd_bytes", 0),
                    flow.get("bwd_bytes", 0),
                    flow.get("flow_bytes_s", 0.0),
                    flow.get("flow_pkts_s", 0.0),
                    flow.get("syn_count", 0),
                    finalization_reason
                ))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"[WARN] Failed to insert flow summary to database: {e}")
            return False

    def insert_flow_summaries_batch(self, flows: List[Dict[str, Any]], finalization_reason: str = "unknown") -> int:
        if not flows:
            return 0
        rows = [
            (
                f.get("flow_id"),
                f.get("protocol"),
                f.get("initiator_ip"),
                f.get("responder_ip"),
                f.get("initiator_port"),
                f.get("responder_port"),
                f.get("start_time"),
                f.get("last_seen"),
                f.get("duration", 0.0),
                f.get("total_packets", 0),
                f.get("fwd_packets", 0),
                f.get("bwd_packets", 0),
                f.get("total_bytes", 0),
                f.get("fwd_bytes", 0),
                f.get("bwd_bytes", 0),
                f.get("flow_bytes_s", 0.0),
                f.get("flow_pkts_s", 0.0),
                f.get("syn_count", 0),
                finalization_reason
            )
            for f in flows if f
        ]
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT OR IGNORE INTO flow_summaries (
                        flow_id, protocol, initiator_ip, responder_ip,
                        initiator_port, responder_port, start_time, last_seen,
                        duration, total_packets, fwd_packets, bwd_packets,
                        total_bytes, fwd_bytes, bwd_bytes, flow_bytes_s,
                        flow_pkts_s, syn_count, finalization_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, rows)
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            print(f"[WARN] Failed to insert flow summaries batch to database: {e}")
            return 0

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, flow_id, protocol, initiator_ip, responder_ip,
                       initiator_port, responder_port, start_time, last_seen,
                       duration, total_packets, fwd_packets, bwd_packets,
                       total_bytes, fwd_bytes, bwd_bytes, flow_bytes_s,
                       flow_pkts_s, syn_count, finalization_reason
                FROM flow_summaries
                ORDER BY last_seen DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM packets")
            total_packets = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE engine LIKE '%RULE%'")
            rule_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE engine LIKE '%ML%'")
            ml_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM flow_summaries")
            total_flows = cursor.fetchone()[0]

            # Top 5 attacker IPs
            cursor.execute("""
                SELECT src_ip, COUNT(*) as alert_count
                FROM alerts
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT 5
            """)
            top_attackers = [dict(row) for row in cursor.fetchall()]

            # Breakdown by alert type
            cursor.execute("""
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
            """)
            alert_breakdown = [dict(row) for row in cursor.fetchall()]

            return {
                "total_packets": total_packets,
                "total_alerts": total_alerts,
                "rule_alerts": rule_alerts,
                "ml_alerts": ml_alerts,
                "total_flows": total_flows,
                "top_attackers": top_attackers,
                "alert_breakdown": alert_breakdown
            }

    def clear_database(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM packets")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM system_metrics")
            conn.execute("DELETE FROM flow_summaries")
            conn.commit()

# Global default instance
db = DatabaseManager()
