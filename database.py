import sqlite3
import time
from typing import List, Dict, Any, Optional
from config import DB_PATH

class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
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
            # Create indexes for fast lookup during dashboard queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip)")
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

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM packets")
            total_packets = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE engine = 'RULE'")
            rule_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE engine = 'ML'")
            ml_alerts = cursor.fetchone()[0]

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
                "top_attackers": top_attackers,
                "alert_breakdown": alert_breakdown
            }

    def clear_database(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM packets")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM system_metrics")
            conn.commit()

# Global default instance
db = DatabaseManager()
