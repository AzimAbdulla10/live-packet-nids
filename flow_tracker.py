import math
import time
from collections import OrderedDict
from typing import Dict, Any, Optional, Tuple, List, Set

try:
    from config import FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT, FLOW_MAX_TABLE_SIZE
except ImportError:
    FLOW_IDLE_TIMEOUT = 15.0
    FLOW_ACTIVE_TIMEOUT = 120.0
    FLOW_MAX_TABLE_SIZE = 10000

class RunningStats:
    """
    Computes running count, sum, min, max, mean, and sample variance/std
    using Welford's algorithm in O(1) space and O(1) time without retaining packets.
    """
    def __init__(self):
        self.count: int = 0
        self.sum: float = 0.0
        self.min: float = float("inf")
        self.max: float = 0.0
        self._mean: float = 0.0
        self._m2: float = 0.0

    def update(self, val: float):
        self.count += 1
        self.sum += val
        if val < self.min:
            self.min = val
        if val > self.max:
            self.max = val
        delta = val - self._mean
        self._mean += delta / self.count
        delta2 = val - self._mean
        self._m2 += delta * delta2

    @property
    def mean(self) -> float:
        return self._mean if self.count > 0 else 0.0

    @property
    def variance(self) -> float:
        return (self._m2 / (self.count - 1)) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def min_val(self) -> float:
        return self.min if self.count > 0 else 0.0

    @property
    def max_val(self) -> float:
        return self.max if self.count > 0 else 0.0


def _parse_flags(flags_val: Any) -> Set[str]:
    """
    Parses flags from string (e.g. 'SYN-ACK', 'SYN', 'S', 'SA') or set into canonical flag tokens.
    """
    if not flags_val:
        return set()
    if isinstance(flags_val, (set, list, tuple)):
        return {str(f).upper() for f in flags_val}
    
    tokens = set()
    s = str(flags_val).upper().replace(",", "-").replace(" ", "-")
    parts = s.split("-")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"):
            tokens.add(p)
        elif len(p) <= 8 and all(c in "SAFRPUCE" for c in p):
            # Handle compact representation like 'SA', 'S', 'F'
            char_map = {
                'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST',
                'P': 'PSH', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
            }
            for c in p:
                if c in char_map:
                    tokens.add(char_map[c])
        else:
            tokens.add(p)
    return tokens


def make_canonical_flow_key(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: Optional[str]
) -> Optional[Tuple[Tuple[str, int], Tuple[str, int], str]]:
    """
    Generates a canonical bidirectional 5-tuple flow key.
    Order-independent for endpoints so both forward and reverse packets
    yield the exact same hashable key.
    For ICMP, port is canonically represented as -1.
    """
    if not src_ip or not dst_ip:
        return None
    proto = str(protocol).upper() if protocol else "OTHER"
    
    p1 = int(src_port) if src_port is not None else -1
    p2 = int(dst_port) if dst_port is not None else -1

    ep1 = (str(src_ip), p1)
    ep2 = (str(dst_ip), p2)

    # Sort endpoints to achieve bidirectionality
    if ep1 < ep2:
        return (ep1, ep2, proto)
    else:
        return (ep2, ep1, proto)


class Flow:
    """
    Maintains incremental bidirectional flow statistics for a single network conversation.
    """
    def __init__(self, first_packet: Dict[str, Any]):
        self.initiator_ip: str = str(first_packet.get("src_ip", ""))
        self.responder_ip: str = str(first_packet.get("dst_ip", ""))
        
        raw_sp = first_packet.get("src_port")
        raw_dp = first_packet.get("dst_port")
        self.initiator_port: Optional[int] = int(raw_sp) if raw_sp is not None else None
        self.responder_port: Optional[int] = int(raw_dp) if raw_dp is not None else None
        
        self.protocol: str = str(first_packet.get("protocol", "OTHER")).upper()
        
        first_time = float(first_packet.get("timestamp", time.time()))
        self.start_time: float = first_time
        self.last_seen: float = first_time
        self.fwd_last_time: float = first_time
        self.bwd_last_time: Optional[float] = None

        # Packet and byte counters
        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0

        # Incremental packet length statistics
        self.len_stats = RunningStats()
        self.fwd_len_stats = RunningStats()
        self.bwd_len_stats = RunningStats()

        # Inter-arrival time (IAT) statistics (in seconds)
        self.flow_iat_stats = RunningStats()
        self.fwd_iat_stats = RunningStats()
        self.bwd_iat_stats = RunningStats()

        # TCP Flag Counters
        self.syn_count: int = 0
        self.ack_count: int = 0
        self.fin_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.urg_count: int = 0
        self.ece_count: int = 0
        self.cwr_count: int = 0

        self.fwd_syn_count: int = 0
        self.bwd_syn_count: int = 0
        self.pure_syn_count: int = 0  # SYN flag set without ACK
        self.finalization_reason: str = "active"

        # Ingestion of the first packet
        self.update(first_packet)

    @property
    def flow_id(self) -> str:
        p1 = self.initiator_port if self.initiator_port is not None else ""
        p2 = self.responder_port if self.responder_port is not None else ""
        return f"{self.protocol}:{self.initiator_ip}:{p1}<->{self.responder_ip}:{p2}"

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(0.0, self.last_seen - self.start_time)

    @property
    def duration_us(self) -> float:
        """Flow duration in microseconds (as used by CIC-IDS2017)."""
        return self.duration * 1e6

    @property
    def flow_bytes_per_sec(self) -> float:
        """Flow throughput in Bytes per second."""
        if self.duration <= 0.0:
            return 0.0
        return self.total_bytes / self.duration

    @property
    def flow_packets_per_sec(self) -> float:
        """Flow throughput in Packets per second."""
        if self.duration <= 0.0:
            return 0.0
        return self.total_packets / self.duration

    @property
    def fwd_packets_per_sec(self) -> float:
        if self.duration <= 0.0:
            return 0.0
        return self.fwd_packets / self.duration

    @property
    def bwd_packets_per_sec(self) -> float:
        dur = max(self.duration, 1e-6)
        return self.bwd_packets / dur

    def is_forward(self, pkt: Dict[str, Any]) -> bool:
        """
        Determines if packet is in forward direction (initiator -> responder)
        or backward direction (responder -> initiator).
        """
        src_ip = str(pkt.get("src_ip", ""))
        dst_ip = str(pkt.get("dst_ip", ""))
        
        raw_sp = pkt.get("src_port")
        src_port = int(raw_sp) if raw_sp is not None else None

        if self.initiator_port is not None and self.responder_port is not None:
            if src_ip == self.initiator_ip and src_port == self.initiator_port:
                return True
            if src_ip == self.responder_ip and src_port == self.responder_port:
                return False

        # Fallback for ICMP or missing port representations
        if src_ip == self.initiator_ip and dst_ip == self.responder_ip:
            return True
        return False

    def update(self, pkt: Dict[str, Any]):
        """
        Incrementally updates flow state and statistics with a new packet.
        """
        curr_time = float(pkt.get("timestamp", time.time()))
        pkt_len = int(pkt.get("length", 0))
        is_fwd = self.is_forward(pkt)

        # 1. Inter-arrival time calculations
        if self.total_packets >= 1:
            flow_iat = max(0.0, curr_time - self.last_seen)
            self.flow_iat_stats.update(flow_iat)

        if is_fwd:
            if self.fwd_packets >= 1:
                fwd_iat = max(0.0, curr_time - self.fwd_last_time)
                self.fwd_iat_stats.update(fwd_iat)
            self.fwd_last_time = max(self.fwd_last_time, curr_time)
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_len_stats.update(pkt_len)
        else:
            if self.bwd_packets >= 1 and self.bwd_last_time is not None:
                bwd_iat = max(0.0, curr_time - self.bwd_last_time)
                self.bwd_iat_stats.update(bwd_iat)
            self.bwd_last_time = curr_time if self.bwd_last_time is None else max(self.bwd_last_time, curr_time)
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_len_stats.update(pkt_len)

        # Global timestamps & overall length
        self.last_seen = max(self.last_seen, curr_time)
        self.len_stats.update(pkt_len)

        # 2. Flag counting
        flags = _parse_flags(pkt.get("flags", ""))
        has_syn = "SYN" in flags
        has_ack = "ACK" in flags

        if has_syn:
            self.syn_count += 1
            if is_fwd:
                self.fwd_syn_count += 1
            else:
                self.bwd_syn_count += 1
            if not has_ack:
                self.pure_syn_count += 1

        if has_ack:
            self.ack_count += 1
        if "FIN" in flags:
            self.fin_count += 1
        if "RST" in flags:
            self.rst_count += 1
        if "PSH" in flags:
            self.psh_count += 1
        if "URG" in flags:
            self.urg_count += 1
        if "ECE" in flags:
            self.ece_count += 1
        if "CWR" in flags:
            self.cwr_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """
        Returns full structured dictionary of flow statistics.
        """
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "initiator_ip": self.initiator_ip,
            "responder_ip": self.responder_ip,
            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "duration_us": self.duration_us,
            "total_packets": self.total_packets,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "total_bytes": self.total_bytes,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            # Length stats
            "pkt_len_min": self.len_stats.min_val,
            "pkt_len_max": self.len_stats.max_val,
            "pkt_len_mean": self.len_stats.mean,
            "pkt_len_std": self.len_stats.std,
            "fwd_pkt_len_min": self.fwd_len_stats.min_val,
            "fwd_pkt_len_max": self.fwd_len_stats.max_val,
            "fwd_pkt_len_mean": self.fwd_len_stats.mean,
            "fwd_pkt_len_std": self.fwd_len_stats.std,
            "bwd_pkt_len_min": self.bwd_len_stats.min_val,
            "bwd_pkt_len_max": self.bwd_len_stats.max_val,
            "bwd_pkt_len_mean": self.bwd_len_stats.mean,
            "bwd_pkt_len_std": self.bwd_len_stats.std,
            # Rate stats
            "flow_bytes_s": self.flow_bytes_per_sec,
            "flow_pkts_s": self.flow_packets_per_sec,
            "fwd_pkts_s": self.fwd_packets_per_sec,
            "bwd_pkts_s": self.bwd_packets_per_sec,
            # Inter-arrival time stats
            "flow_iat_mean": self.flow_iat_stats.mean,
            "flow_iat_std": self.flow_iat_stats.std,
            "flow_iat_min": self.flow_iat_stats.min_val,
            "flow_iat_max": self.flow_iat_stats.max_val,
            "fwd_iat_mean": self.fwd_iat_stats.mean,
            "fwd_iat_std": self.fwd_iat_stats.std,
            "bwd_iat_mean": self.bwd_iat_stats.mean,
            "bwd_iat_std": self.bwd_iat_stats.std,
            # Flags
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "urg_count": self.urg_count,
            "ece_count": self.ece_count,
            "cwr_count": self.cwr_count,
            "fwd_syn_count": self.fwd_syn_count,
            "bwd_syn_count": self.bwd_syn_count,
            "pure_syn_count": self.pure_syn_count,
            "finalization_reason": self.finalization_reason
        }

    def to_model_features(self) -> Dict[str, Any]:
        """
        Maps bidirectional flow statistics directly to the feature schema
        expected by the trained ML model (CIC-IDS2017 canonical columns).
        """
        dest_port = self.responder_port if self.responder_port is not None else 0
        avg_pkt_size = self.len_stats.mean
        return {
            "Destination Port": dest_port,
            "Flow Duration": self.duration_us,
            "Total Fwd Packets": self.fwd_packets,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Fwd Packet Length Mean": self.fwd_len_stats.mean,
            "Flow Bytes/s": self.flow_bytes_per_sec,
            "Flow Packets/s": self.flow_packets_per_sec,
            "SYN Flag Count": 1 if self.syn_count > 0 else 0,
            "Average Packet Size": avg_pkt_size
        }


class FlowTracker:
    """
    Tracks and manages live bidirectional network flows with bounded memory
    and configurable timeout expiration.
    """
    def __init__(
        self,
        idle_timeout: float = FLOW_IDLE_TIMEOUT,
        active_timeout: float = FLOW_ACTIVE_TIMEOUT,
        max_flows: int = FLOW_MAX_TABLE_SIZE
    ):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows
        
        # OrderedDict acts as an O(1) LRU table: key -> Flow
        self.active_flows: OrderedDict[Tuple, Flow] = OrderedDict()
        self.total_flows_created: int = 0
        self.total_flows_expired: int = 0

    def process_packet(self, pkt: Dict[str, Any]) -> Tuple[Optional[Flow], List[Flow]]:
        """
        Processes an incoming packet dictionary.
        Returns:
            (current_flow, list_of_expired_flows)
        """
        if not pkt or not isinstance(pkt, dict):
            return None, []

        key = make_canonical_flow_key(
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
            pkt.get("protocol")
        )

        if not key:
            return None, []

        curr_time = float(pkt.get("timestamp", time.time()))

        # Check and expire stale flows periodically
        expired = self.expire_stale_flows(curr_time)

        if key in self.active_flows:
            flow = self.active_flows[key]
            # Check if this flow itself has exceeded idle or active timeout before updating
            if curr_time - flow.last_seen > self.idle_timeout:
                flow.finalization_reason = "idle_timeout"
                expired.append(flow)
                self.total_flows_expired += 1
                flow = Flow(pkt)
                self.active_flows[key] = flow
                self.total_flows_created += 1
            elif curr_time - flow.start_time > self.active_timeout:
                flow.finalization_reason = "active_timeout"
                expired.append(flow)
                self.total_flows_expired += 1
                flow = Flow(pkt)
                self.active_flows[key] = flow
                self.total_flows_created += 1
            else:
                flow.update(pkt)
            self.active_flows.move_to_end(key)
        else:
            # Memory bounding: Evict least recently updated flow if table is full
            if len(self.active_flows) >= self.max_flows:
                oldest_key, oldest_flow = self.active_flows.popitem(last=False)
                oldest_flow.finalization_reason = "table_eviction"
                expired.append(oldest_flow)
                self.total_flows_expired += 1

            flow = Flow(pkt)
            self.active_flows[key] = flow
            self.total_flows_created += 1

        return flow, expired

    def get_flow(self, pkt: Dict[str, Any]) -> Optional[Flow]:
        """
        Looks up the active flow for a packet without modifying state.
        """
        if not pkt or not isinstance(pkt, dict):
            return None
        key = make_canonical_flow_key(
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
            pkt.get("protocol")
        )
        return self.active_flows.get(key) if key else None

    def expire_stale_flows(self, current_time: float) -> List[Flow]:
        """
        Scans and purges flows that have exceeded idle or active lifetime timeouts.
        """
        expired = []
        # Since OrderedDict is ordered by access time, we check oldest entries first
        keys_to_remove = []
        for key, flow in self.active_flows.items():
            if current_time - flow.last_seen >= self.idle_timeout:
                flow.finalization_reason = "idle_timeout"
                keys_to_remove.append(key)
                expired.append(flow)
            elif current_time - flow.start_time >= self.active_timeout:
                flow.finalization_reason = "active_timeout"
                keys_to_remove.append(key)
                expired.append(flow)

        for k in keys_to_remove:
            self.active_flows.pop(k, None)
            self.total_flows_expired += 1

        return expired

    def clear(self):
        """Resets all tracked flows."""
        self.active_flows.clear()
        self.total_flows_created = 0
        self.total_flows_expired = 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns tracker status and summary metrics."""
        return {
            "active_flows_count": len(self.active_flows),
            "total_flows_created": self.total_flows_created,
            "total_flows_expired": self.total_flows_expired,
            "max_capacity": self.max_flows,
            "idle_timeout": self.idle_timeout,
            "active_timeout": self.active_timeout
        }
