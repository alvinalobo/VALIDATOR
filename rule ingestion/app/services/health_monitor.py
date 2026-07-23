import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class ConnectorHealthStatus(BaseModel):
    connector_id: str
    vendor: str
    product: str
    availability: float    # 0.0 to 100.0 %
    error_rate: float      # 0.0 to 100.0 %
    avg_latency: float     # in seconds
    health_score: float    # 0.0 to 100.0
    status: str            # 'Green', 'Amber', 'Red'
    total_queries: int
    failed_queries: int
    last_checked: float

class HealthMonitor:
    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}

    def register_connector(self, connector_id: str, vendor: str, product: str):
        if connector_id not in self.metrics:
            self.metrics[connector_id] = {
                "vendor": vendor,
                "product": product,
                "latencies": [],
                "success_count": 0,
                "failure_count": 0,
                "total_queries": 0,
                "last_checked": time.time(),
                "connection_available": True
            }

    def record_query(self, connector_id: str, latency: float, success: bool):
        if connector_id not in self.metrics:
            return
        
        m = self.metrics[connector_id]
        m["total_queries"] += 1
        m["last_checked"] = time.time()
        
        if success:
            m["success_count"] += 1
            m["latencies"].append(latency)
            if len(m["latencies"]) > 100:
                m["latencies"].pop(0)
        else:
            m["failure_count"] += 1

    def record_connection_status(self, connector_id: str, available: bool):
        if connector_id not in self.metrics:
            return
        self.metrics[connector_id]["connection_available"] = available
        self.metrics[connector_id]["last_checked"] = time.time()

    def get_health(self, connector_id: str) -> Optional[ConnectorHealthStatus]:
        if connector_id not in self.metrics:
            return None
            
        m = self.metrics[connector_id]
        total = m["total_queries"]
        failures = m["failure_count"]
        
        conn_ok = m["connection_available"]
        if total > 0:
            query_success_rate = (m["success_count"] / total) * 100.0
            availability = query_success_rate if conn_ok else (query_success_rate * 0.5)
        else:
            availability = 100.0 if conn_ok else 0.0

        error_rate = (failures / total * 100.0) if total > 0 else 0.0
        latencies = m["latencies"]
        avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0

        # Health score calculation
        score = 100.0
        score -= (100.0 - availability) * 0.5
        score -= error_rate * 0.4
        
        if avg_latency > 2.0:
            latency_penalty = min(30.0, (avg_latency - 2.0) * 5.0)
            score -= latency_penalty
            
        score = max(0.0, min(100.0, score))
        if not conn_ok:
            score = min(20.0, score)

        if score >= 80.0:
            status = "Green"
        elif score >= 50.0:
            status = "Amber"
        else:
            status = "Red"

        return ConnectorHealthStatus(
            connector_id=connector_id,
            vendor=m["vendor"],
            product=m["product"],
            availability=round(availability, 2),
            error_rate=round(error_rate, 2),
            avg_latency=round(avg_latency, 3),
            health_score=round(score, 2),
            status=status,
            total_queries=total,
            failed_queries=failures,
            last_checked=m["last_checked"]
        )

    def get_all_health(self) -> List[ConnectorHealthStatus]:
        statuses = []
        for cid in self.metrics.keys():
            h = self.get_health(cid)
            if h:
                statuses.append(h)
        return statuses

monitor = HealthMonitor()
